import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { audit } from "./audit.js";

export function createOrg({ name, retentionDays = 365, userId }) {
  const id = uuid();
  const ts = now();
  db.prepare(`INSERT INTO orgs (id, name, retention_days, created_at, created_by) VALUES (?, ?, ?, ?, ?)`).run(
    id,
    name.trim(),
    retentionDays,
    ts,
    userId
  );
  db.prepare(`INSERT INTO org_members (org_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)`).run(id, userId, ts);
  audit({ orgId: id, actorId: userId, action: "org.created", targetType: "org", targetId: id, meta: { name } });
  return getOrg(id);
}

export function getOrg(id) {
  return db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(id);
}

export function listOrgsForUser(userId, { platformAdmin = false } = {}) {
  // Org sidebar is always membership-scoped (created or invited).
  // Platform admins audit globally via Admin console — they do not browse foreign orgs here.
  void platformAdmin;
  return db
    .prepare(
      `SELECT o.*, om.role AS my_role, 0 AS oversight FROM orgs o
       JOIN org_members om ON om.org_id = o.id
       WHERE om.user_id = ?
       ORDER BY o.created_at DESC`
    )
    .all(userId);
}

export function getOrgMembership(orgId, userId) {
  return db.prepare(`SELECT * FROM org_members WHERE org_id = ? AND user_id = ?`).get(orgId, userId);
}

export function requireOrgRole(orgId, userId, roles = ["owner", "admin", "member"]) {
  const m = getOrgMembership(orgId, userId);
  if (!m || !roles.includes(m.role)) {
    const err = new Error("Forbidden");
    err.code = "FORBIDDEN";
    throw err;
  }
  return m;
}

export function addOrgMember({ orgId, userId, role, actorId }) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  const allowed = ["owner", "admin", "member"];
  if (!allowed.includes(role)) {
    const err = new Error("Invalid role");
    err.code = "VALIDATION";
    throw err;
  }
  db.prepare(
    `INSERT INTO org_members (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(org_id, user_id) DO UPDATE SET role = excluded.role`
  ).run(orgId, userId, role, now());
  audit({
    orgId,
    actorId,
    action: "org.member_added",
    targetType: "user",
    targetId: userId,
    meta: { role },
  });
}

/**
 * Bulk add by userIds (shared role) and/or CSV-style entries [{ email, role }].
 * Skips unknown emails / inactive users. Does not add role "owner" via bulk.
 */
export function addOrgMembersBulk({ orgId, actorId, userIds = [], role = "member", entries = [] }) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  const allowed = ["admin", "member"];
  const result = { added: [], skipped: [], updated: [] };

  const upsert = (user, memberRole) => {
    if (!allowed.includes(memberRole)) {
      result.skipped.push({ email: user.email, reason: "invalid_role" });
      return;
    }
    if (user.status !== "active") {
      result.skipped.push({ email: user.email, reason: "inactive" });
      return;
    }
    const existing = getOrgMembership(orgId, user.id);
    addOrgMember({ orgId, userId: user.id, role: memberRole, actorId });
    if (existing) result.updated.push({ userId: user.id, email: user.email, role: memberRole });
    else result.added.push({ userId: user.id, email: user.email, role: memberRole });
  };

  const sharedRole = allowed.includes(role) ? role : "member";
  for (const id of userIds || []) {
    const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(id);
    if (!user) {
      result.skipped.push({ userId: id, reason: "not_found" });
      continue;
    }
    upsert(user, sharedRole);
  }

  for (const entry of entries || []) {
    const email = String(entry.email || "").trim().toLowerCase();
    if (!email) continue;
    const memberRole = allowed.includes(entry.role) ? entry.role : sharedRole;
    const user = db.prepare(`SELECT * FROM users WHERE email = ? COLLATE NOCASE`).get(email);
    if (!user) {
      result.skipped.push({ email, reason: "not_registered" });
      continue;
    }
    upsert(user, memberRole);
  }

  audit({
    orgId,
    actorId,
    action: "org.members_bulk_added",
    targetType: "org",
    targetId: orgId,
    meta: {
      added: result.added.length,
      updated: result.updated.length,
      skipped: result.skipped.length,
    },
  });

  return { ...result, members: listOrgMembers(orgId) };
}

export function listOrgMembers(orgId) {
  return db
    .prepare(
      `SELECT u.id, u.email, u.name, u.status, om.role, om.created_at
       FROM org_members om JOIN users u ON u.id = om.user_id
       WHERE om.org_id = ? ORDER BY om.role, u.name`
    )
    .all(orgId);
}

export function countOrgOwners(orgId) {
  return db.prepare(`SELECT COUNT(*) AS n FROM org_members WHERE org_id = ? AND role = 'owner'`).get(orgId).n;
}

export function removeOrgMember({ orgId, userId, actorId }) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  const target = getOrgMembership(orgId, userId);
  if (!target) {
    const err = new Error("Not an org member");
    err.code = "NOT_FOUND";
    throw err;
  }
  const actor = getOrgMembership(orgId, actorId);
  if (target.role === "owner" && actor.role !== "owner") {
    const err = new Error("Only an owner can remove another owner");
    err.code = "FORBIDDEN";
    throw err;
  }
  if (target.role === "owner" && countOrgOwners(orgId) <= 1) {
    const err = new Error("Cannot remove the last org owner");
    err.code = "VALIDATION";
    throw err;
  }
  if (userId === actorId && target.role === "owner" && countOrgOwners(orgId) <= 1) {
    const err = new Error("Cannot remove yourself as the last owner");
    err.code = "VALIDATION";
    throw err;
  }
  // Drop project memberships in this org for the user
  db.prepare(
    `DELETE FROM project_members WHERE user_id = ? AND project_id IN (SELECT id FROM projects WHERE org_id = ?)`
  ).run(userId, orgId);
  // Drop folder ACL + file ACL in this org's projects
  db.prepare(
    `DELETE FROM folder_acl WHERE user_id = ? AND folder_id IN (
      SELECT f.id FROM folders f JOIN projects p ON p.id = f.project_id WHERE p.org_id = ?
    )`
  ).run(userId, orgId);
  db.prepare(
    `DELETE FROM file_acl WHERE user_id = ? AND file_id IN (
      SELECT fi.id FROM files fi JOIN projects p ON p.id = fi.project_id WHERE p.org_id = ?
    )`
  ).run(userId, orgId);
  db.prepare(`DELETE FROM org_members WHERE org_id = ? AND user_id = ?`).run(orgId, userId);
  audit({
    orgId,
    actorId,
    action: "org.member_removed",
    targetType: "user",
    targetId: userId,
    meta: { previousRole: target.role },
  });
}

/** Bulk set org role (member|admin only) for many users. */
export function updateOrgMembersRolesBulk({ orgId, actorId, userIds = [], role }) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  if (!["member", "admin"].includes(role)) {
    const err = new Error("Role must be member or admin");
    err.code = "VALIDATION";
    throw err;
  }
  const actor = getOrgMembership(orgId, actorId);
  const result = { updated: [], skipped: [] };
  for (const userId of userIds) {
    const target = getOrgMembership(orgId, userId);
    if (!target) {
      result.skipped.push({ userId, reason: "not_member" });
      continue;
    }
    if (target.role === "owner") {
      result.skipped.push({ userId, reason: "cannot_change_owner" });
      continue;
    }
    if (userId === actorId && actor.role === "admin" && role === "member") {
      // admins can demote themselves; fine
    }
    addOrgMember({ orgId, userId, role, actorId });
    result.updated.push({ userId, role });
  }
  audit({
    orgId,
    actorId,
    action: "org.members_roles_bulk",
    targetType: "org",
    targetId: orgId,
    meta: { role, updated: result.updated.length, skipped: result.skipped.length },
  });
  return { ...result, members: listOrgMembers(orgId) };
}

/** Bulk remove org members. */
export function removeOrgMembersBulk({ orgId, actorId, userIds = [] }) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  const result = { removed: [], skipped: [] };
  for (const userId of userIds) {
    try {
      removeOrgMember({ orgId, userId, actorId });
      result.removed.push(userId);
    } catch (e) {
      result.skipped.push({ userId, reason: e.message });
    }
  }
  return { ...result, members: listOrgMembers(orgId) };
}

export function updateOrgRetention(orgId, retentionDays, actorId) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  db.prepare(`UPDATE orgs SET retention_days = ? WHERE id = ?`).run(retentionDays, orgId);
  audit({
    orgId,
    actorId,
    action: "org.retention_updated",
    targetType: "org",
    targetId: orgId,
    meta: { retentionDays },
  });
}
