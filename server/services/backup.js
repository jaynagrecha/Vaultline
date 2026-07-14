import fs from "node:fs";
import path from "node:path";
import { config } from "../config.js";

function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, ent.name);
    const d = path.join(dest, ent.name);
    if (ent.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

function rmrf(target) {
  if (!fs.existsSync(target)) return;
  fs.rmSync(target, { recursive: true, force: true });
}

function backupRootName(name) {
  const base = path.basename(String(name || ""));
  if (!/^backup-[\w.-]+$/.test(base)) {
    throw Object.assign(new Error("Invalid backup id"), { code: "VALIDATION" });
  }
  return base;
}

/** Copy SQLite DB + encrypted files into timestamped backup folder. */
export function runBackup() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const dest = path.join(config.backupDir, `backup-${stamp}`);
  fs.mkdirSync(dest, { recursive: true });
  if (fs.existsSync(config.dbPath)) {
    fs.copyFileSync(config.dbPath, path.join(dest, "enterprise.db"));
    // SQLite WAL companions if present
    for (const suf of ["-wal", "-shm"]) {
      const p = config.dbPath + suf;
      if (fs.existsSync(p)) fs.copyFileSync(p, path.join(dest, `enterprise.db${suf}`));
    }
  }
  copyDir(config.filesDir, path.join(dest, "files"));
  const manifest = {
    createdAt: new Date().toISOString(),
    dbPath: config.dbPath,
    filesDir: config.filesDir,
    product: "Vaultline",
    version: "2.0.0",
  };
  fs.writeFileSync(path.join(dest, "manifest.json"), JSON.stringify(manifest, null, 2));
  return dest;
}

export function listBackups() {
  if (!fs.existsSync(config.backupDir)) return [];
  return fs
    .readdirSync(config.backupDir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name.startsWith("backup-"))
    .map((e) => {
      const dir = path.join(config.backupDir, e.name);
      const manifestPath = path.join(dir, "manifest.json");
      let manifest = null;
      try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      } catch {
        /* ignore */
      }
      const dbFile = path.join(dir, "enterprise.db");
      const ok = fs.existsSync(dbFile) && fs.existsSync(manifestPath);
      let sizeBytes = 0;
      try {
        const walk = (p) => {
          for (const ent of fs.readdirSync(p, { withFileTypes: true })) {
            const fp = path.join(p, ent.name);
            if (ent.isDirectory()) walk(fp);
            else sizeBytes += fs.statSync(fp).size;
          }
        };
        walk(dir);
      } catch {
        /* ignore */
      }
      return {
        id: e.name,
        createdAt: manifest?.createdAt || null,
        ok,
        sizeBytes,
        path: dir,
      };
    })
    .sort((a, b) => String(b.id).localeCompare(String(a.id)));
}

export function verifyBackup(backupId) {
  const id = backupRootName(backupId);
  const dir = path.join(config.backupDir, id);
  if (!fs.existsSync(dir)) throw Object.assign(new Error("Backup not found"), { code: "NOT_FOUND" });
  const dbFile = path.join(dir, "enterprise.db");
  const manifestPath = path.join(dir, "manifest.json");
  const errors = [];
  if (!fs.existsSync(dbFile)) errors.push("missing enterprise.db");
  if (!fs.existsSync(manifestPath)) errors.push("missing manifest.json");
  let manifest = null;
  if (fs.existsSync(manifestPath)) {
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    } catch (e) {
      errors.push(`manifest parse: ${e.message}`);
    }
  }
  return { id, ok: errors.length === 0, errors, manifest };
}

/**
 * Stage a restore onto the Disk, then exit so the process restarts and applies it
 * before reopening SQLite (see applyPendingRestore in config boot).
 */
export function stageRestore(backupId) {
  const verified = verifyBackup(backupId);
  if (!verified.ok) {
    throw Object.assign(new Error(`Backup invalid: ${verified.errors.join("; ")}`), { code: "VALIDATION" });
  }
  const id = verified.id;
  const src = path.join(config.backupDir, id);
  const pendingDb = path.join(config.dataDir, "enterprise.db.pending");
  const pendingFiles = path.join(config.dataDir, "files.pending");
  const flag = path.join(config.dataDir, "RESTORE_PENDING.json");

  rmrf(pendingDb);
  rmrf(pendingFiles);
  fs.copyFileSync(path.join(src, "enterprise.db"), pendingDb);
  copyDir(path.join(src, "files"), pendingFiles);
  fs.writeFileSync(
    flag,
    JSON.stringify({ backupId: id, stagedAt: new Date().toISOString() }, null, 2)
  );
  return { backupId: id, restartRequired: true };
}

/**
 * Must run BEFORE opening SQLite. Swaps staged restore into place.
 */
export function applyPendingRestore() {
  const flag = path.join(config.dataDir, "RESTORE_PENDING.json");
  if (!fs.existsSync(flag)) return null;
  let meta;
  try {
    meta = JSON.parse(fs.readFileSync(flag, "utf8"));
  } catch {
    fs.unlinkSync(flag);
    return null;
  }
  const pendingDb = path.join(config.dataDir, "enterprise.db.pending");
  const pendingFiles = path.join(config.dataDir, "files.pending");
  const safety = path.join(config.backupDir, `pre-restore-${Date.now()}`);
  fs.mkdirSync(safety, { recursive: true });
  if (fs.existsSync(config.dbPath)) {
    fs.copyFileSync(config.dbPath, path.join(safety, "enterprise.db"));
  }
  if (fs.existsSync(config.filesDir)) {
    copyDir(config.filesDir, path.join(safety, "files"));
  }
  fs.writeFileSync(path.join(safety, "manifest.json"), JSON.stringify({ note: "auto pre-restore", meta }, null, 2));

  if (fs.existsSync(pendingDb)) {
    fs.copyFileSync(pendingDb, config.dbPath);
    fs.unlinkSync(pendingDb);
  }
  if (fs.existsSync(pendingFiles)) {
    rmrf(config.filesDir);
    fs.mkdirSync(config.filesDir, { recursive: true });
    copyDir(pendingFiles, config.filesDir);
    rmrf(pendingFiles);
  }
  fs.unlinkSync(flag);
  console.log(`Restore applied from ${meta.backupId || "pending"} (safety copy: ${safety})`);
  return meta;
}
