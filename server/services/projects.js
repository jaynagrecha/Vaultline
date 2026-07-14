import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { audit } from "./audit.js";
import { requireOrgRole, getOrg, getOrgMembership, addOrgMember } from "./orgs.js";
import { generateProjectDek, wrapDek, unwrapDek, makeInviteCode, hashInviteCode } from "../crypto/vault.js";

export function createProject({ orgId, name, userId, retentionDays = null }) {
  requireOrgRole(orgId, userId, ["owner", "admin", "member"]);
  const id = uuid();
  const dek = generateProjectDek();
  const wrapped = wrapDek(dek);
  const invite = makeInviteCode();
  const ts = now();
  db.prepare(
    `INSERT INTO projects (id, org_id, name, invite_hash, wrapped_dek, retention_days, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, orgId, name.trim(), hashInviteCode(invite), wrapped, retentionDays, userId, ts);
  db.prepare(`INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'admin', ?)`).run(
    id,
    userId,
    ts
  );
  audit({
    orgId,
    projectId: id,
    actorId: userId,
    action: "project.created",
    targetType: "project",
    targetId: id,
    meta: { name },
  });
  return { project: getProject(id), inviteCode: invite };
}

export function getProject(id) {
  return db.prepare(`SELECT * FROM projects WHERE id = ?`).get(id);
}

export function getProjectDek(project) {
  return unwrapDek(project.wrapped_dek);
}

export function listProjectsForUser(userId, orgId = null, { platformAdmin = false } = {}) {
  // Same rule: only projects you're a member of. Platform audit is via Admin console.
  void platformAdmin;
  let sql = `SELECT p.*, pm.role AS my_role, o.name AS org_name, 0 AS oversight
    FROM projects p
    JOIN project_members pm ON pm.project_id = p.id
    JOIN orgs o ON o.id = p.org_id
    WHERE pm.user_id = ?`;
  const params = [userId];
  if (orgId) {
    sql += ` AND p.org_id = ?`;
    params.push(orgId);
  }
  sql += ` ORDER BY p.created_at DESC`;
  return db.prepare(sql).all(...params);
}

export function getProjectMembership(projectId, userId) {
  return db.prepare(`SELECT * FROM project_members WHERE project_id = ? AND user_id = ?`).get(projectId, userId);
}

export function requireProjectRole(projectId, userId, roles = ["admin", "member"]) {
  const m = getProjectMembership(projectId, userId);
  if (!m || !roles.includes(m.role)) {
    const err = new Error("Forbidden");
    err.code = "FORBIDDEN";
    throw err;
  }
  return m;
}

/**
 * Membership only. Platform admins do not get cross-org project browse;
 * they use the Admin console audit trail for global visibility.
 */
export function resolveProjectAccess(projectId, user) {
  const m = getProjectMembership(projectId, user.id);
  if (m) return { mode: "member", role: m.role, membership: m };
  const err = new Error("Forbidden");
  err.code = "FORBIDDEN";
  throw err;
}

export function joinProjectByInvite({ inviteCode, userId }) {
  const raw = String(inviteCode || "").trim();
  const inviteTried = raw ? raw.toUpperCase() : null;
  const hash = hashInviteCode(raw);
  const project = db.prepare(`SELECT * FROM projects WHERE invite_hash = ?`).get(hash);
  if (!project) {
    audit({
      actorId: userId,
      action: "project.join_failed",
      targetType: "invite",
      outcome: "failure",
      meta: { reason: "invalid_invite", inviteTried, message: "Invalid invite" },
    });
    const err = new Error("Invalid invite");
    err.code = "NOT_FOUND";
    throw err;
  }
  const existing = getProjectMembership(project.id, userId);
  if (existing) {
    audit({
      orgId: project.org_id,
      projectId: project.id,
      actorId: userId,
      action: "project.joined",
      targetType: "project",
      targetId: project.id,
      outcome: "success",
      meta: { name: project.name, alreadyMember: true },
    });
    return { project, role: existing.role, alreadyMember: true };
  }
  const orgMem = db
    .prepare(`SELECT * FROM org_members WHERE org_id = ? AND user_id = ?`)
    .get(project.org_id, userId);
  if (!orgMem) {
    audit({
      orgId: project.org_id,
      projectId: project.id,
      actorId: userId,
      action: "project.join_failed",
      targetType: "project",
      targetId: project.id,
      outcome: "failure",
      meta: {
        reason: "not_in_org",
        inviteTried,
        name: project.name,
        message: "You must be added to the organization before joining this project",
      },
    });
    const err = new Error("You must be added to the organization before joining this project");
    err.code = "FORBIDDEN";
    throw err;
  }
  db.prepare(`INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'member', ?)`).run(
    project.id,
    userId,
    now()
  );
  audit({
    orgId: project.org_id,
    projectId: project.id,
    actorId: userId,
    action: "project.joined",
    targetType: "project",
    targetId: project.id,
    outcome: "success",
    meta: { name: project.name, alreadyMember: false },
  });
  return { project, role: "member", alreadyMember: false };
}

export function canManageProjectMembers(projectId, actorId) {
  const project = getProject(projectId);
  if (!project) return false;
  const proj = getProjectMembership(projectId, actorId);
  if (proj?.role === "admin") return { project, via: "project_admin" };
  const org = getOrgMembership(project.org_id, actorId);
  if (org && (org.role === "owner" || org.role === "admin")) return { project, via: "org_" + org.role };
  return false;
}

export function addProjectMember({ projectId, userId, role, actorId }) {
  const gate = canManageProjectMembers(projectId, actorId);
  if (!gate) {
    const err = new Error("Forbidden");
    err.code = "FORBIDDEN";
    throw err;
  }
  const { project } = gate;
  const allowed = ["admin", "member"];
  if (!allowed.includes(role)) {
    const err = new Error("Invalid role");
    err.code = "VALIDATION";
    throw err;
  }

  const targetOrg = getOrgMembership(project.org_id, userId);
  if (!targetOrg) {
    const actorOrg = getOrgMembership(project.org_id, actorId);
    if (actorOrg && (actorOrg.role === "owner" || actorOrg.role === "admin")) {
      addOrgMember({ orgId: project.org_id, userId, role: "member", actorId });
    } else {
      const err = new Error("User must be added to the organization first");
      err.code = "FORBIDDEN";
      throw err;
    }
  }

  db.prepare(
    `INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role`
  ).run(projectId, userId, role, now());
  audit({
    orgId: project.org_id,
    projectId,
    actorId,
    action: "project.member_added",
    targetType: "user",
    targetId: userId,
    meta: { role },
  });
}

export function listProjectMembers(projectId) {
  return db
    .prepare(
      `SELECT u.id, u.email, u.name, u.status, pm.role, pm.created_at
       FROM project_members pm JOIN users u ON u.id = pm.user_id
       WHERE pm.project_id = ? ORDER BY pm.role, u.name`
    )
    .all(projectId);
}

export function removeProjectMember({ projectId, userId, actorId }) {
  const gate = canManageProjectMembers(projectId, actorId);
  if (!gate) {
    const err = new Error("Forbidden");
    err.code = "FORBIDDEN";
    throw err;
  }
  const { project } = gate;
  const target = getProjectMembership(projectId, userId);
  if (!target) {
    const err = new Error("Not a project member");
    err.code = "NOT_FOUND";
    throw err;
  }
  if (userId === actorId) {
    const err = new Error("Leave the project instead of removing yourself");
    err.code = "VALIDATION";
    throw err;
  }
  const adminCount = db
    .prepare(`SELECT COUNT(*) AS n FROM project_members WHERE project_id = ? AND role = 'admin'`)
    .get(projectId).n;
  if (target.role === "admin" && adminCount <= 1) {
    const err = new Error("Cannot remove the last project admin");
    err.code = "VALIDATION";
    throw err;
  }
  db.prepare(`DELETE FROM project_members WHERE project_id = ? AND user_id = ?`).run(projectId, userId);
  audit({
    orgId: project.org_id,
    projectId,
    actorId,
    action: "project.member_removed",
    targetType: "user",
    targetId: userId,
    meta: { previousRole: target.role },
  });
}

export function addProjectMembersBulk({ projectId, actorId, userIds = [], role = "member" }) {
  const gate = canManageProjectMembers(projectId, actorId);
  if (!gate) {
    const err = new Error("Forbidden");
    err.code = "FORBIDDEN";
    throw err;
  }
  const allowed = ["admin", "member"];
  const memberRole = allowed.includes(role) ? role : "member";
  const result = { added: [], skipped: [], updated: [] };
  for (const userId of userIds) {
    try {
      const existing = getProjectMembership(projectId, userId);
      addProjectMember({ projectId, userId, role: memberRole, actorId });
      if (existing) result.updated.push({ userId, role: memberRole });
      else result.added.push({ userId, role: memberRole });
    } catch (e) {
      result.skipped.push({ userId, reason: e.message });
    }
  }
  return { ...result, members: listProjectMembers(projectId) };
}

export function removeProjectMembersBulk({ projectId, actorId, userIds = [] }) {
  const result = { removed: [], skipped: [] };
  for (const userId of userIds) {
    try {
      removeProjectMember({ projectId, userId, actorId });
      result.removed.push(userId);
    } catch (e) {
      result.skipped.push({ userId, reason: e.message });
    }
  }
  return { ...result, members: listProjectMembers(projectId) };
}

export function updateProjectMembersRolesBulk({ projectId, actorId, userIds = [], role }) {
  if (!["admin", "member"].includes(role)) {
    const err = new Error("Role must be member or admin");
    err.code = "VALIDATION";
    throw err;
  }
  const result = { updated: [], skipped: [] };
  for (const userId of userIds) {
    try {
      addProjectMember({ projectId, userId, role, actorId });
      result.updated.push({ userId, role });
    } catch (e) {
      result.skipped.push({ userId, reason: e.message });
    }
  }
  return { ...result, members: listProjectMembers(projectId) };
}

export function rotateInviteCode(projectId, actorId) {
  const gate = canManageProjectMembers(projectId, actorId);
  if (!gate) {
    const err = new Error("Forbidden");
    err.code = "FORBIDDEN";
    throw err;
  }
  const invite = makeInviteCode();
  db.prepare(`UPDATE projects SET invite_hash = ? WHERE id = ?`).run(hashInviteCode(invite), projectId);
  const project = getProject(projectId);
  audit({
    orgId: project.org_id,
    projectId,
    actorId,
    action: "project.invite_rotated",
    targetType: "project",
    targetId: projectId,
  });
  return invite;
}

export function effectiveRetentionDays(project) {
  if (project.retention_days != null) return project.retention_days;
  const org = getOrg(project.org_id);
  return org?.retention_days ?? 365;
}
