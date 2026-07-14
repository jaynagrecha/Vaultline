import bcrypt from "bcryptjs";
import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { config } from "../config.js";
import { randomToken, sha256 } from "../crypto/vault.js";
import { audit } from "./audit.js";

const SESSION_MS = () => config.sessionDays * 24 * 60 * 60 * 1000;

export function findUserByEmail(email) {
  return db.prepare(`SELECT * FROM users WHERE email = ? COLLATE NOCASE`).get(String(email).trim());
}

export function findUserById(id) {
  return db.prepare(`SELECT * FROM users WHERE id = ?`).get(id);
}

/**
 * Typeahead for inviting users. Never returns the full directory.
 * @param {{ q: string, excludeOrgId?: string, excludeProjectId?: string, limit?: number }} opts
 */
export function searchUsersForInvite({ q, excludeOrgId = null, excludeProjectId = null, limit = 20 }) {
  const needle = String(q || "").trim().toLowerCase();
  if (needle.length < 2) return [];
  const lim = Math.min(Math.max(Number(limit) || 20, 1), 40);
  const like = `%${needle.replace(/[%_]/g, "")}%`;

  let sql = `
    SELECT u.id, u.email, u.name
    FROM users u
    WHERE u.status = 'active'
      AND (lower(u.email) LIKE ? OR lower(u.name) LIKE ?)`;
  const params = [like, like];

  if (excludeOrgId) {
    sql += ` AND NOT EXISTS (
      SELECT 1 FROM org_members om WHERE om.org_id = ? AND om.user_id = u.id
    )`;
    params.push(excludeOrgId);
  }
  if (excludeProjectId) {
    sql += ` AND NOT EXISTS (
      SELECT 1 FROM project_members pm WHERE pm.project_id = ? AND pm.user_id = u.id
    )`;
    params.push(excludeProjectId);
  }

  sql += ` ORDER BY
    CASE WHEN lower(u.email) = ? THEN 0
         WHEN lower(u.email) LIKE ? THEN 1
         WHEN lower(u.name) LIKE ? THEN 2
         ELSE 3 END,
    u.name
    LIMIT ?`;
  params.push(needle, `${needle}%`, `${needle}%`, lim);

  return db.prepare(sql).all(...params);
}

export function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    status: u.status,
    isPlatformAdmin: !!u.is_platform_admin,
    canCreateOrg: !!u.can_create_org || !!u.is_platform_admin,
    createdAt: u.created_at,
  };
}

export async function registerUser({ email, name, password, isPlatformAdmin = false, canCreateOrg = false }) {
  const existing = findUserByEmail(email);
  if (existing) {
    const err = new Error("Email already registered");
    err.code = "CONFLICT";
    throw err;
  }
  if (!password || password.length < 10) {
    const err = new Error("Password must be at least 10 characters");
    err.code = "VALIDATION";
    throw err;
  }
  const id = uuid();
  const password_hash = await bcrypt.hash(password, 12);
  const ts = now();
  const createOrg = canCreateOrg || isPlatformAdmin ? 1 : 0;
  db.prepare(
    `INSERT INTO users (id, email, name, password_hash, status, is_platform_admin, can_create_org, created_at)
     VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`
  ).run(id, email.trim().toLowerCase(), name.trim(), password_hash, isPlatformAdmin ? 1 : 0, createOrg, ts);
  audit({ actorId: id, action: "user.registered", targetType: "user", targetId: id, meta: { email } });
  return findUserById(id);
}

export async function verifyPassword(user, password) {
  if (!user?.password_hash) return false;
  return bcrypt.compare(password, user.password_hash);
}

export function createSession(userId, { ip, userAgent } = {}) {
  const id = uuid();
  const token = randomToken(32);
  const token_hash = sha256(token);
  const created = now();
  const expires = created + SESSION_MS();
  db.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, userId, token_hash, expires, created, ip || null, userAgent || null);
  return { token, expiresAt: expires };
}

export function getSessionUser(token) {
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT s.*, u.* FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ?`
    )
    .get(sha256(token), now());
  if (!row) return null;
  if (row.status !== "active") return null;
  return {
    sessionId: row.id,
    expiresAt: row.expires_at,
    user: {
      id: row.user_id,
      email: row.email,
      name: row.name,
      status: row.status,
      is_platform_admin: row.is_platform_admin,
      can_create_org: row.can_create_org,
      password_hash: row.password_hash,
      created_at: row.created_at,
    },
  };
}

export function destroySession(token) {
  if (!token) return;
  db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).run(sha256(token));
}

export function destroyAllUserSessions(userId) {
  db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(userId);
}

export function listUsers() {
  return db
    .prepare(
      `SELECT id, email, name, status, is_platform_admin, can_create_org, created_at, disabled_at FROM users ORDER BY created_at`
    )
    .all()
    .map((u) => ({
      id: u.id,
      email: u.email,
      name: u.name,
      status: u.status,
      isPlatformAdmin: !!u.is_platform_admin,
      canCreateOrg: !!u.can_create_org || !!u.is_platform_admin,
      createdAt: u.created_at,
      disabledAt: u.disabled_at,
    }));
}

export function setUserStatus(userId, status, actorId) {
  const disabled_at = status === "disabled" ? now() : null;
  db.prepare(`UPDATE users SET status = ?, disabled_at = ? WHERE id = ?`).run(status, disabled_at, userId);
  if (status === "disabled") destroyAllUserSessions(userId);
  audit({
    actorId,
    action: status === "disabled" ? "user.disabled" : "user.enabled",
    targetType: "user",
    targetId: userId,
  });
}

export function countPlatformAdmins() {
  return db.prepare(`SELECT COUNT(*) AS n FROM users WHERE is_platform_admin = 1 AND status = 'active'`).get().n;
}

export function isBootstrapEmail(email) {
  const boot = config.bootstrapAdminEmail?.trim().toLowerCase();
  if (!boot) return false;
  return String(email || "")
    .trim()
    .toLowerCase() === boot;
}

/** Platform admin only via BOOTSTRAP_ADMIN_EMAIL or explicit promote — never “first registrant”. */
export function shouldGrantPlatformAdminOnSignup(email) {
  return isBootstrapEmail(email);
}

export function setPlatformAdmin(userId, isAdmin, actorId) {
  const target = findUserById(userId);
  if (!target) {
    const err = new Error("User not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  if (!isAdmin && target.is_platform_admin) {
    if (countPlatformAdmins() <= 1) {
      const err = new Error("Cannot demote the last platform admin");
      err.code = "VALIDATION";
      throw err;
    }
  }
  db.prepare(`UPDATE users SET is_platform_admin = ? WHERE id = ?`).run(isAdmin ? 1 : 0, userId);
  audit({
    actorId,
    action: isAdmin ? "user.platform_admin_granted" : "user.platform_admin_revoked",
    targetType: "user",
    targetId: userId,
  });
  return findUserById(userId);
}

export function setCanCreateOrg(userId, grant, actorId) {
  const target = findUserById(userId);
  if (!target) {
    const err = new Error("User not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  db.prepare(`UPDATE users SET can_create_org = ? WHERE id = ?`).run(grant ? 1 : 0, userId);
  audit({
    actorId,
    action: grant ? "user.can_create_org_granted" : "user.can_create_org_revoked",
    targetType: "user",
    targetId: userId,
  });
  return findUserById(userId);
}

export function userCanCreateOrg(user) {
  return !!(user?.canCreateOrg || user?.can_create_org || user?.isPlatformAdmin || user?.is_platform_admin);
}

export function ensureBootstrapAdmin() {
  const email = config.bootstrapAdminEmail?.trim();
  if (!email) {
    if (countPlatformAdmins() === 0) {
      console.warn(
        "WARNING: No platform admins and BOOTSTRAP_ADMIN_EMAIL unset — set it, then register/login that email to unlock the admin console."
      );
    }
    return;
  }
  const u = findUserByEmail(email);
  if (u && !u.is_platform_admin) {
    db.prepare(`UPDATE users SET is_platform_admin = 1, can_create_org = 1 WHERE id = ?`).run(u.id);
    audit({
      actorId: u.id,
      action: "user.platform_admin_bootstrap",
      targetType: "user",
      targetId: u.id,
      meta: { email },
    });
    console.log(`Bootstrap platform admin ensured for ${email}`);
  } else if (u && u.is_platform_admin && !u.can_create_org) {
    db.prepare(`UPDATE users SET can_create_org = 1 WHERE id = ?`).run(u.id);
  } else if (!u) {
    console.warn(`BOOTSTRAP_ADMIN_EMAIL=${email} — register or SSO that account to become platform admin.`);
  }
}
