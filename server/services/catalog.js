/**
 * Platform-admin estate catalog: structural metadata only.
 * Never decrypts or returns file bytes.
 */
import { db } from "../db.js";
import { audit } from "./audit.js";

export function listCatalogOrgs() {
  return db
    .prepare(
      `SELECT o.id, o.name, o.retention_days, o.created_at,
        (SELECT COUNT(*) FROM org_members om WHERE om.org_id = o.id) AS member_count,
        (SELECT COUNT(*) FROM projects p WHERE p.org_id = o.id) AS project_count
       FROM orgs o
       ORDER BY o.name COLLATE NOCASE`
    )
    .all();
}

export function listCatalogProjects(orgId) {
  const org = db.prepare(`SELECT id, name FROM orgs WHERE id = ?`).get(orgId);
  if (!org) {
    const err = new Error("Organization not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  const projects = db
    .prepare(
      `SELECT p.id, p.name, p.created_at, p.org_id,
        (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id = p.id) AS member_count,
        (SELECT COUNT(*) FROM folders f WHERE f.project_id = p.id) AS folder_count
       FROM projects p
       WHERE p.org_id = ?
       ORDER BY p.name COLLATE NOCASE`
    )
    .all(orgId);
  return { org, projects };
}

export function listCatalogFolders(projectId) {
  const project = db
    .prepare(
      `SELECT p.id, p.name, p.org_id, o.name AS org_name
       FROM projects p JOIN orgs o ON o.id = p.org_id
       WHERE p.id = ?`
    )
    .get(projectId);
  if (!project) {
    const err = new Error("Project not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  const folders = db
    .prepare(
      `SELECT f.id, f.name, f.visibility, f.created_at, f.created_by, u.name AS created_by_name,
        (SELECT COUNT(*) FROM files fi WHERE fi.folder_id = f.id) AS file_count
       FROM folders f
       LEFT JOIN users u ON u.id = f.created_by
       WHERE f.project_id = ?
       ORDER BY f.created_at`
    )
    .all(projectId)
    .map((f, i) => ({ ...f, number: i + 1 }));
  return { project, folders };
}

export function listCatalogFiles(folderId) {
  const folder = db
    .prepare(
      `SELECT f.id, f.name, f.visibility, f.project_id, f.created_by,
        p.name AS project_name, p.org_id, o.name AS org_name
       FROM folders f
       JOIN projects p ON p.id = f.project_id
       JOIN orgs o ON o.id = p.org_id
       WHERE f.id = ?`
    )
    .get(folderId);
  if (!folder) {
    const err = new Error("Folder not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  const files = db
    .prepare(
      `SELECT fi.id, fi.name, fi.current_version, fi.created_at, fi.updated_at, fi.created_by,
        fi.language, fi.is_code, u.name AS created_by_name,
        (SELECT fv.size FROM file_versions fv
          WHERE fv.file_id = fi.id AND fv.version = fi.current_version) AS size
       FROM files fi
       LEFT JOIN users u ON u.id = fi.created_by
       WHERE fi.folder_id = ?
       ORDER BY fi.created_at`
    )
    .all(folderId);
  return { folder, files };
}

export function auditCatalogView(actorId, action, { orgId = null, projectId = null, targetType = null, targetId = null, meta = null } = {}) {
  audit({
    orgId,
    projectId,
    actorId,
    action,
    targetType,
    targetId,
    outcome: "success",
    meta,
  });
}
