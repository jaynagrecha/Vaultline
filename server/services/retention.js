import { db, now } from "../db.js";
import { audit } from "./audit.js";
import fs from "node:fs";
import path from "node:path";
import { config } from "../config.js";

/**
 * Delete files past retention_until (and their version blobs).
 * Returns counts for ops / cron logs.
 */
export function runRetentionPurge({ dryRun = false, actorId = null } = {}) {
  const ts = now();
  const expired = db
    .prepare(
      `SELECT f.id, f.name, f.project_id, f.folder_id, f.retention_until, p.org_id
       FROM files f
       JOIN projects p ON p.id = f.project_id
       WHERE f.retention_until IS NOT NULL AND f.retention_until < ?`
    )
    .all(ts);

  const deleted = [];
  const errors = [];

  for (const file of expired) {
    try {
      const versions = db.prepare(`SELECT storage_key FROM file_versions WHERE file_id = ?`).all(file.id);
      if (!dryRun) {
        for (const v of versions) {
          if (v.storage_key && fs.existsSync(v.storage_key)) {
            try {
              fs.unlinkSync(v.storage_key);
            } catch {
              /* continue */
            }
          }
        }
        db.prepare(`DELETE FROM file_acl WHERE file_id = ?`).run(file.id);
        db.prepare(`DELETE FROM file_versions WHERE file_id = ?`).run(file.id);
        db.prepare(`DELETE FROM files WHERE id = ?`).run(file.id);
        audit({
          orgId: file.org_id,
          projectId: file.project_id,
          actorId: actorId || null,
          action: "file.retention_purged",
          targetType: "file",
          targetId: file.id,
          meta: { name: file.name, retentionUntil: file.retention_until },
        });
      }
      deleted.push({ id: file.id, name: file.name });
    } catch (e) {
      errors.push({ id: file.id, error: e.message });
    }
  }

  // Opportunistic: remove empty project file dirs under files/
  if (!dryRun && fs.existsSync(config.filesDir)) {
    try {
      for (const proj of fs.readdirSync(config.filesDir, { withFileTypes: true })) {
        if (!proj.isDirectory()) continue;
        const pdir = path.join(config.filesDir, proj.name);
        const left = fs.readdirSync(pdir);
        if (!left.length) fs.rmdirSync(pdir);
      }
    } catch {
      /* ignore */
    }
  }

  return { scanned: expired.length, deleted: deleted.length, dryRun: !!dryRun, items: deleted, errors };
}
