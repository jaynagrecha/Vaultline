import { config } from "../config.js";
import { getSessionUser, publicUser } from "../services/auth.js";
import { auditFromReq } from "../services/audit.js";

export function attachUser(req, res, next) {
  const token = req.cookies?.[config.cookieName];
  const session = getSessionUser(token);
  req.sessionToken = token || null;
  req.user = session ? publicUser(session.user) : null;
  req.userRaw = session?.user || null;
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  next();
}

export function requirePlatformAdmin(req, res, next) {
  if (!req.user?.isPlatformAdmin) return res.status(403).json({ error: "Forbidden" });
  next();
}

/** Platform admins oversee + audit only — never mutate orgs/projects/files.
 * Not mounted globally: bootstrap admins are often also Project Owners.
 * Prefer a dedicated platform-admin account for console-only use in production.
 */
export function blockPlatformAdminOrgOps(req, res, next) {
  if (!req.user?.isPlatformAdmin) return next();
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
  auditFromReq(req, {
    actorId: req.user.id,
    action: "platform.ops_denied",
    meta: { method: req.method, path: req.originalUrl || req.path },
  });
  return res.status(403).json({
    error: "Platform admins can only oversee and audit. Use a normal account for org/project work.",
  });
}

export function setSessionCookie(res, token, expiresAt) {
  res.cookie(config.cookieName, token, {
    httpOnly: true,
    secure: config.isProd,
    sameSite: "lax",
    expires: new Date(expiresAt),
    path: "/",
  });
}

export function clearSessionCookie(res) {
  res.clearCookie(config.cookieName, {
    path: "/",
    httpOnly: true,
    secure: config.isProd,
    sameSite: "lax",
  });
}
