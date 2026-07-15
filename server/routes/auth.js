import { Router } from "express";
import {
  registerUser,
  findUserByEmail,
  verifyPassword,
  createSession,
  destroySession,
  publicUser,
  listUsers,
  setUserStatus,
  setPlatformAdmin,
  setCanCreateOrg,
  shouldGrantPlatformAdminOnSignup,
  findUserById,
} from "../services/auth.js";
import { setSessionCookie, clearSessionCookie, requireAuth, requirePlatformAdmin } from "../middleware/auth.js";
import { authLimiter } from "../middleware/rateLimit.js";
import { audit, auditFromReq, exportAuditJson, listAudit, listAuditFilterOptions } from "../services/audit.js";
import { beginOidcLogin, finishOidcLogin, oidcEnabled } from "../services/oidc.js";
import { config } from "../config.js";
import {
  listCatalogOrgs,
  listCatalogProjects,
  listCatalogFolders,
  listCatalogFiles,
  auditCatalogView,
} from "../services/catalog.js";

const router = Router();

router.get("/meta", (_req, res) => {
  res.json({
    oidcEnabled: oidcEnabled(),
    smtpConfigured: !!(config.smtp?.host && config.smtp?.user && config.smtp?.pass),
    product: "Vaultline",
    version: "2.0.0",
  });
});

router.post("/register", authLimiter, async (req, res) => {
  try {
    const { email, name, password } = req.body || {};
    if (!email || !name || !password) return res.status(400).json({ error: "Missing fields" });
    const user = await registerUser({
      email,
      name,
      password,
      isPlatformAdmin: shouldGrantPlatformAdminOnSignup(email),
    });
    const { sendActivationForUser } = await import("../services/emailAuth.js");
    await sendActivationForUser(user);
    res.status(201).json({
      needsActivation: true,
      email: user.email,
      message: "Check your email for a 6-digit code or activation link.",
    });
  } catch (e) {
    const status = e.code === "CONFLICT" ? 409 : e.code === "VALIDATION" ? 400 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.post("/activate", authLimiter, async (req, res) => {
  try {
    const { email, code, token } = req.body || {};
    if (!email || (!code && !token)) {
      return res.status(400).json({ error: "Email and code (or link token) required" });
    }
    const { activateAccount } = await import("../services/emailAuth.js");
    const result = activateAccount({ email, code, token });
    const session = createSession(result.user.id, { ip: req.ip, userAgent: req.get("user-agent") });
    setSessionCookie(res, session.token, session.expiresAt);
    res.json({ user: publicUser(result.user), alreadyActive: !!result.alreadyActive });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/resend-activation", authLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "Email required" });
    const { resendActivation } = await import("../services/emailAuth.js");
    await resendActivation(email);
    res.json({ ok: true, message: "If that email needs activation, a new code was sent." });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/forgot-password", authLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "Email required" });
    const { requestPasswordReset } = await import("../services/emailAuth.js");
    await requestPasswordReset(email);
    res.json({ ok: true, message: "If that account exists, reset instructions were sent." });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/reset-password", authLimiter, async (req, res) => {
  try {
    const { email, code, token, password } = req.body || {};
    if (!email || !password || (!code && !token)) {
      return res.status(400).json({ error: "Email, new password, and code (or link token) required" });
    }
    const { resetPassword } = await import("../services/emailAuth.js");
    await resetPassword({ email, code, token, password });
    res.json({ ok: true, message: "Password updated — you can sign in." });
  } catch (e) {
    res.status(e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const fail = (reason) => {
      audit({
        actorId: null,
        action: "user.login_failed",
        targetType: "user",
        outcome: "failure",
        meta: { email: email || null, reason },
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });
      return res.status(401).json({ error: "Invalid email or password" });
    };
    if (!email || !password) return fail("missing");
    const user = findUserByEmail(email);
    if (!user) return fail("unknown_or_disabled");
    if (user.status === "pending" || !user.email_verified_at) {
      audit({
        actorId: null,
        action: "user.login_failed",
        targetType: "user",
        outcome: "failure",
        meta: { email: email || null, reason: "not_activated" },
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });
      return res.status(403).json({
        error: "Activate your account first — check your email for a code or link.",
        needsActivation: true,
        email: user.email,
      });
    }
    if (user.status !== "active") return fail("unknown_or_disabled");
    const ok = await verifyPassword(user, password);
    if (!ok) return fail("bad_password");
    const session = createSession(user.id, { ip: req.ip, userAgent: req.get("user-agent") });
    setSessionCookie(res, session.token, session.expiresAt);
    audit({
      actorId: user.id,
      action: "user.login",
      targetType: "user",
      targetId: user.id,
      ip: req.ip,
      userAgent: req.get("user-agent"),
    });
    res.json({ user: publicUser(user) });
  } catch (e) {
    res.status(500).json({ error: "Login failed" });
  }
});

router.post("/logout", requireAuth, (req, res) => {
  destroySession(req.sessionToken);
  clearSessionCookie(res);
  audit({ actorId: req.user.id, action: "user.logout", targetType: "user", targetId: req.user.id });
  res.json({ ok: true });
});

router.get("/me", (req, res) => {
  res.json({ user: req.user });
});

router.get("/oidc/enabled", (_req, res) => {
  res.json({ enabled: oidcEnabled() });
});

router.get("/oidc/start", authLimiter, async (req, res) => {
  try {
    if (!oidcEnabled()) return res.status(404).json({ error: "OIDC not configured" });
    const url = await beginOidcLogin();
    res.json({ url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get("/oidc/callback", authLimiter, async (req, res) => {
  try {
    const user = await finishOidcLogin(req.query);
    const session = createSession(user.id, { ip: req.ip, userAgent: req.get("user-agent") });
    setSessionCookie(res, session.token, session.expiresAt);
    audit({ actorId: user.id, action: "user.login_oidc", targetType: "user", targetId: user.id });
    res.redirect("/");
  } catch (e) {
    res.redirect("/?oidc_error=1");
  }
});

router.get("/admin/users", requireAuth, requirePlatformAdmin, (_req, res) => {
  res.json({ users: listUsers() });
});

router.post("/admin/users/:id/status", requireAuth, requirePlatformAdmin, (req, res) => {
  const { status } = req.body || {};
  if (!["active", "disabled"].includes(status)) return res.status(400).json({ error: "Invalid status" });
  setUserStatus(req.params.id, status, req.user.id);
  res.json({ ok: true });
});

router.post("/admin/users/:id/platform-admin", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const grant = !!req.body?.grant;
    if (!grant && req.params.id === req.user.id) {
      return res.status(400).json({ error: "Ask another admin to demote you" });
    }
    const user = setPlatformAdmin(req.params.id, grant, req.user.id);
    res.json({ user: publicUser(user) });
  } catch (e) {
    const status = e.code === "NOT_FOUND" ? 404 : e.code === "VALIDATION" ? 400 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.post("/admin/users/:id/can-create-org", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const target = findUserById(req.params.id);
    if (!target) return res.status(404).json({ error: "User not found" });
    if (target.is_platform_admin) {
      return res.status(400).json({
        error: "Platform admins always may create organizations — demote them first to change this flag",
      });
    }
    const grant = !!req.body?.grant;
    const user = setCanCreateOrg(req.params.id, grant, req.user.id);
    res.json({ user: publicUser(user) });
  } catch (e) {
    const status = e.code === "NOT_FOUND" ? 404 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.get("/admin/audit", requireAuth, requirePlatformAdmin, (req, res) => {
  const limit = Number(req.query.limit) || 200;
  const events = listAudit({
    limit,
    orgId: req.query.orgId || null,
    projectId: req.query.projectId || null,
    actorId: req.query.actorId || null,
    action: req.query.action || null,
    targetType: req.query.targetType || null,
    category: req.query.category || null,
    outcome: req.query.outcome || null,
    q: req.query.q || null,
    since: req.query.since ? Number(req.query.since) : null,
    until: req.query.until ? Number(req.query.until) : null,
  });
  res.json({ events });
});

router.get("/admin/audit/filters", requireAuth, requirePlatformAdmin, (_req, res) => {
  res.json(listAuditFilterOptions());
});

router.get("/admin/audit/export", requireAuth, requirePlatformAdmin, (req, res) => {
  auditFromReq(req, {
    actorId: req.user.id,
    action: "admin.audit_exported",
    targetType: "audit",
    outcome: "success",
    meta: {
      q: req.query.q || null,
      action: req.query.action || null,
      category: req.query.category || null,
      outcome: req.query.outcome || null,
      targetType: req.query.targetType || null,
      orgId: req.query.orgId || null,
      projectId: req.query.projectId || null,
      actorId: req.query.actorId || null,
    },
  });
  const payload = exportAuditJson({
    limit: Number(req.query.limit) || 10000,
    orgId: req.query.orgId || null,
    projectId: req.query.projectId || null,
    actorId: req.query.actorId || null,
    action: req.query.action || null,
    targetType: req.query.targetType || null,
    category: req.query.category || null,
    outcome: req.query.outcome || null,
    q: req.query.q || null,
    since: req.query.since ? Number(req.query.since) : null,
    until: req.query.until ? Number(req.query.until) : null,
  });
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="audit-export-${Date.now()}.json"`);
  res.send(JSON.stringify(payload, null, 2));
});

router.get("/admin/catalog/orgs", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    if (req.query.sync !== "1") {
      auditCatalogView(req.user.id, "admin.catalog_opened", { targetType: "catalog" });
    }
    res.json({
      mode: "catalog",
      notice: "Metadata only — file contents are never available here.",
      orgs: listCatalogOrgs(),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get("/admin/catalog/orgs/:orgId/projects", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const data = listCatalogProjects(req.params.orgId);
    if (req.query.sync !== "1") {
      auditCatalogView(req.user.id, "admin.catalog_org_viewed", {
        orgId: data.org.id,
        targetType: "org",
        targetId: data.org.id,
        meta: { name: data.org.name },
      });
    }
    res.json({ mode: "catalog", notice: "Metadata only — file contents are never available here.", ...data });
  } catch (e) {
    res.status(e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

router.get("/admin/catalog/projects/:projectId/folders", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const data = listCatalogFolders(req.params.projectId);
    if (req.query.sync !== "1") {
      auditCatalogView(req.user.id, "admin.catalog_project_viewed", {
        orgId: data.project.org_id,
        projectId: data.project.id,
        targetType: "project",
        targetId: data.project.id,
        meta: { name: data.project.name },
      });
    }
    res.json({ mode: "catalog", notice: "Metadata only — file contents are never available here.", ...data });
  } catch (e) {
    res.status(e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

router.get("/admin/catalog/folders/:folderId/files", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const data = listCatalogFiles(req.params.folderId);
    if (req.query.sync !== "1") {
      auditCatalogView(req.user.id, "admin.catalog_folder_viewed", {
        orgId: data.folder.org_id,
        projectId: data.folder.project_id,
        targetType: "folder",
        targetId: data.folder.id,
        meta: { name: data.folder.name },
      });
    }
    res.json({ mode: "catalog", notice: "Metadata only — file contents are never available here.", ...data });
  } catch (e) {
    res.status(e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

export default router;
