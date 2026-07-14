import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const isProd = process.env.NODE_ENV === "production";
/** Render sets RENDER=true; Disk mount is typically /var/data */
const onRender = process.env.RENDER === "true" || process.env.IS_PULL_REQUEST === "true";

function resolveDataDir() {
  if (process.env.DATA_DIR) return path.resolve(process.env.DATA_DIR);
  if (onRender) return "/var/data";
  return path.join(ROOT, "data");
}

function requireMasterKey() {
  const raw = process.env.MASTER_KEY || "";
  if (!raw) {
    if (isProd) {
      throw new Error(
        "MASTER_KEY is required in production. Set a stable secret in Render → Environment (do not rotate casually — it wraps project DEKs)."
      );
    }
    console.warn("WARNING: MASTER_KEY not set — using ephemeral dev key (local only)");
    return crypto.createHash("sha256").update("config-rooms-dev-master-key").digest();
  }
  try {
    const buf = Buffer.from(raw, "base64");
    if (buf.length === 32) return buf;
  } catch {
    /* fall through — treat as passphrase */
  }
  return crypto.createHash("sha256").update(raw).digest();
}

const dataDir = resolveDataDir();

export const config = {
  root: ROOT,
  port: Number(process.env.PORT) || 3847,
  dataDir,
  dbPath: process.env.DB_PATH || path.join(dataDir, "enterprise.db"),
  filesDir: process.env.FILES_DIR || path.join(dataDir, "files"),
  backupDir: process.env.BACKUP_DIR || path.join(dataDir, "backups"),
  masterKey: requireMasterKey(),
  sessionDays: Number(process.env.SESSION_DAYS) || 7,
  cookieName: "cr_session",
  isProd,
  onRender,
  publicUrl: (process.env.PUBLIC_URL || "").replace(/\/$/, ""),
  oidc: {
    issuer: process.env.OIDC_ISSUER || "",
    clientId: process.env.OIDC_CLIENT_ID || "",
    clientSecret: process.env.OIDC_CLIENT_SECRET || "",
    enabled: Boolean(process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET),
  },
  bootstrapAdminEmail: process.env.BOOTSTRAP_ADMIN_EMAIL || "",
  maxUploadBytes: Number(process.env.MAX_UPLOAD_BYTES) || 50 * 1024 * 1024,
};

/** Ensure data / files / backups exist and are writable (Render Disk). */
export function ensureDataDirs() {
  for (const dir of [config.dataDir, config.filesDir, config.backupDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const probe = path.join(config.dataDir, ".write-probe");
  try {
    fs.writeFileSync(probe, String(Date.now()));
    fs.unlinkSync(probe);
  } catch (e) {
    throw new Error(
      `DATA_DIR is not writable (${config.dataDir}): ${e.message}. On Render, attach a Disk at /var/data.`
    );
  }
}
