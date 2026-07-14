/**
 * Startup probe used by /api/health and boot logging.
 * Keeps Render health checks honest about Disk + SQLite.
 */
import fs from "node:fs";
import path from "node:path";
import { config } from "../config.js";
import { db } from "../db.js";

export function storageHealth() {
  const checks = {
    dataDir: config.dataDir,
    dbPath: config.dbPath,
    filesDir: config.filesDir,
    backupDir: config.backupDir,
    writable: false,
    dbOk: false,
    onRender: !!config.onRender,
  };
  try {
    const probePath = path.join(config.dataDir, ".health");
    fs.writeFileSync(probePath, "ok");
    fs.unlinkSync(probePath);
    checks.writable = true;
  } catch (e) {
    checks.writeError = e.message;
  }
  try {
    db.prepare("SELECT 1 AS ok").get();
    checks.dbOk = true;
  } catch (e) {
    checks.dbError = e.message;
  }
  checks.ok = checks.writable && checks.dbOk;
  return checks;
}
