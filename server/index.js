import express from "express";
import path from "node:path";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import morgan from "morgan";
import { config, ensureDataDirs } from "./config.js";
import "./db.js";
import { ensureBootstrapAdmin } from "./services/auth.js";
import { storageHealth } from "./services/health.js";
import { attachUser } from "./middleware/auth.js";
import { apiLimiter } from "./middleware/rateLimit.js";
import authRoutes from "./routes/auth.js";
import apiRoutes from "./routes/api.js";
import { runBackup, listBackups, verifyBackup, stageRestore } from "./services/backup.js";
import { runRetentionPurge } from "./services/retention.js";
import { startBackgroundJobs } from "./jobs/scheduler.js";
import { requireAuth, requirePlatformAdmin } from "./middleware/auth.js";
import { auditFromReq } from "./services/audit.js";

ensureDataDirs();
ensureBootstrapAdmin();

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(morgan(config.isProd ? "combined" : "dev"));
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "'unsafe-eval'"],
        "style-src": [
          "'self'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com",
          "https://cdn.jsdelivr.net",
          "'unsafe-inline'",
        ],
        "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net", "data:"],
        "img-src": ["'self'", "data:", "blob:"],
        "connect-src": ["'self'", "https://cdn.jsdelivr.net"],
        "worker-src": ["'self'", "blob:", "https://cdn.jsdelivr.net"],
        "child-src": ["'self'", "blob:"],
        "upgrade-insecure-requests": null,
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: config.isProd,
  })
);
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(attachUser);
app.use("/api", apiLimiter);
app.get("/api/health", (_req, res) => {
  const storage = storageHealth();
  const body = {
    ok: storage.ok,
    product: "Vaultline",
    version: "2.0.0",
    oidc: config.oidc.enabled,
    storage: {
      dataDir: storage.dataDir,
      writable: storage.writable,
      dbOk: storage.dbOk,
      onRender: storage.onRender,
    },
  };
  res.status(storage.ok ? 200 : 503).json(body);
});
app.use("/api/auth", authRoutes);
app.use("/api", apiRoutes);

app.post("/api/admin/backup", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const dest = runBackup();
    auditFromReq(req, {
      actorId: req.user.id,
      action: "admin.backup_created",
      targetType: "backup",
      meta: { path: dest },
    });
    res.json({ ok: true, path: dest });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/backups", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    res.json({ backups: listBackups() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/backups/:backupId/verify", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    res.json(verifyBackup(req.params.backupId));
  } catch (e) {
    res.status(e.code === "NOT_FOUND" ? 404 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

app.post("/api/admin/backups/:backupId/restore", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const result = stageRestore(req.params.backupId);
    auditFromReq(req, {
      actorId: req.user.id,
      action: "admin.backup_restore_staged",
      targetType: "backup",
      meta: { backupId: result.backupId },
    });
    res.json({ ok: true, ...result, message: "Restore staged — process will restart to apply." });
    setTimeout(() => process.exit(0), 800);
  } catch (e) {
    res.status(e.code === "NOT_FOUND" ? 404 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

app.post("/api/admin/retention/run", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    const dryRun = !!req.body?.dryRun;
    const result = runRetentionPurge({ dryRun, actorId: req.user.id });
    auditFromReq(req, {
      actorId: req.user.id,
      action: "admin.retention_run",
      targetType: "retention",
      meta: result,
    });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/console-opened", requireAuth, requirePlatformAdmin, (req, res) => {
  try {
    auditFromReq(req, {
      actorId: req.user.id,
      action: "admin.console_opened",
      targetType: "admin",
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const webRoot = path.join(config.root, "apps", "web");
app.use(express.static(webRoot, { etag: true, maxAge: 0 }));
app.get(/^(?!\/api).*/, (_req, res) => {
  res.sendFile(path.join(webRoot, "index.html"));
});

app.listen(config.port, () => {
  const health = storageHealth();
  console.log(`Vaultline on :${config.port}`);
  console.log(`DATA_DIR=${config.dataDir} writable=${health.writable} dbOk=${health.dbOk}`);
  console.log(`OIDC=${config.oidc.enabled ? "enabled" : "disabled (set OIDC_* to enable)"}`);
  console.log(
    `BOOTSTRAP_ADMIN_EMAIL=${config.bootstrapAdminEmail || "(unset — set this for the first platform admin)"}`
  );
  if (config.isProd && !config.publicUrl) {
    console.warn("WARNING: PUBLIC_URL unset — set it to your Render HTTPS URL for OIDC/callbacks.");
  }
  startBackgroundJobs();
});
