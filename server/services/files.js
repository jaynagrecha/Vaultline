import fs from "node:fs";
import path from "node:path";
import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { config } from "../config.js";
import { audit, resolveFolderPath } from "./audit.js";
import {
  getProject,
  getProjectDek,
  requireProjectRole,
  resolveProjectAccess,
  effectiveRetentionDays,
} from "./projects.js";
import { encryptBuffer, decryptBuffer, sha256 } from "../crypto/vault.js";
import { processCodeContent, lintText } from "./codePipeline.js";
import { toMonacoLanguage } from "./codeDetect.js";

function folderAuditMeta(folder, extra = {}) {
  const folderPath = resolveFolderPath(folder.id) || folder.name;
  return {
    name: folder.name,
    folderId: folder.id,
    folderName: folder.name,
    folderPath,
    ...extra,
  };
}

function fileAuditMeta(file, folder, extra = {}) {
  const folderId = folder?.id || file.folder_id;
  const folderPath = resolveFolderPath(folderId) || folder?.name || null;
  return {
    name: file.name,
    folderId,
    folderName: folder?.name || (folderPath ? folderPath.split(" / ").pop() : null),
    folderPath,
    ...extra,
  };
}

function storagePath(projectId, fileId, version) {
  const dir = path.join(config.filesDir, projectId, fileId);
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, `v${version}.enc`);
}

function persistCodeMeta(fileId, meta) {
  db.prepare(
    `UPDATE files SET language = ?, is_code = ?, format_status = ?, diagnostics_json = ?, updated_at = ? WHERE id = ?`
  ).run(
    meta.language,
    meta.isCode ? 1 : 0,
    meta.formatStatus,
    JSON.stringify({
      diagnostics: meta.diagnostics || [],
      formatError: meta.formatError || null,
      checkedAt: Date.now(),
    }),
    now(),
    fileId
  );
}

function parseDiagnosticsJson(raw) {
  if (!raw) return { diagnostics: [], formatError: null };
  try {
    const parsed = JSON.parse(raw);
    return {
      diagnostics: Array.isArray(parsed.diagnostics) ? parsed.diagnostics : [],
      formatError: parsed.formatError || null,
      checkedAt: parsed.checkedAt || null,
    };
  } catch {
    return { diagnostics: [], formatError: null };
  }
}

export function folderAccess(folder, userId, projectRole) {
  if (projectRole === "admin") return "edit";
  if (folder.created_by === userId) return "edit";
  if (folder.visibility === "members") {
    const acl = db.prepare(`SELECT access FROM folder_acl WHERE folder_id = ? AND user_id = ?`).get(folder.id, userId);
    // Default for project members: read if visibility members and no ACL rows for anyone?
    // Enterprise: if visibility is members and no ACL entries, all project members get read; ACL grants edit
    const anyAcl = db.prepare(`SELECT 1 FROM folder_acl WHERE folder_id = ? LIMIT 1`).get(folder.id);
    if (!anyAcl) return "read";
    return acl?.access || null;
  }
  // restricted: must be on ACL
  const acl = db.prepare(`SELECT access FROM folder_acl WHERE folder_id = ? AND user_id = ?`).get(folder.id, userId);
  return acl?.access || null;
}

/** Upload / create files in a folder — folder ACL only. Never consults file_acl. */
export function canUploadToFolder(folder, userId, projectRole) {
  return folderAccess(folder, userId, projectRole) === "edit";
}

/**
 * Who may change Share folder / folder ACL.
 * Project admins + folder creator only — NOT people who merely have folder "Can edit" (RW).
 */
export function canManageFolderAcl(folder, userId, projectRole) {
  if (projectRole === "admin") return true;
  if (folder.created_by === userId) return true;
  return false;
}

/**
 * Who may change per-file ACL (gear).
 * Project Owner + folder creator: any file in the folder.
 * Uploader: only their own upload, and only while they still have edit on it
 * (Project Owner / folder creator can revoke them).
 */
export function canManageFileAcl(file, folder, userId, projectRole) {
  if (projectRole === "admin") return true;
  if (folder.created_by === userId) return true;
  if (file.created_by === userId) {
    return fileAccess(file, folder, userId, projectRole) === "edit";
  }
  return false;
}

/** Effective file ACL level for UI: read | edit | edit_delete | none | null (inherit). */
export function encodeFileAclLevel(access, canDelete) {
  if (access === "none") return "none";
  if (access === "read") return "read";
  if (access === "edit" && canDelete) return "edit_delete";
  if (access === "edit") return "edit";
  return null;
}

export function decodeFileAclLevel(level) {
  if (level === "edit_delete") return { access: "edit", canDelete: 1 };
  if (level === "edit") return { access: "edit", canDelete: 0 };
  if (level === "read") return { access: "read", canDelete: 0 };
  if (level === "none") return { access: "none", canDelete: 0 };
  return null;
}

/**
 * Delete a file:
 * - project admin / folder creator: always
 * - otherwise: only with explicit file ACL can_delete (Can edit + delete)
 * Folder "Can edit" or file "Can edit" alone is not enough.
 * File uploader may delete their own file only when there is no custom file ACL,
 * or when they have an explicit can_delete grant under custom ACL.
 */
export function canDeleteFile(file, folder, userId, projectRole) {
  if (projectRole === "admin") return true;
  if (folder.created_by === userId) return true;

  const facl = db
    .prepare(`SELECT access, can_delete FROM file_acl WHERE file_id = ? AND user_id = ?`)
    .get(file.id, userId);
  const hasCustomAcl = !!db.prepare(`SELECT 1 FROM file_acl WHERE file_id = ? LIMIT 1`).get(file.id);

  if (hasCustomAcl) {
    if (facl) return facl.access === "edit" && Number(facl.can_delete) === 1;
    // No per-user override under custom ACL → inherit folder access for view/edit, but not delete
    return false;
  }

  // Same as folder: uploader can remove their own upload
  return file.created_by === userId;
}

export function fileAccess(file, folder, userId, projectRole) {
  // Always-in: Project Owner + folder creator only — NOT the uploader.
  // Uploaders respect file ACL (including No access) when set by PO/creator.
  const alwaysIn = projectRole === "admin" || folder.created_by === userId;
  const facl = db.prepare(`SELECT access FROM file_acl WHERE file_id = ? AND user_id = ?`).get(file.id, userId);
  if (facl) {
    if (facl.access === "none") return alwaysIn ? "edit" : null;
    if (alwaysIn) return "edit";
    return facl.access;
  }
  // inherit folder — file-only overrides never change this path for other files
  const fa = folderAccess(folder, userId, projectRole);
  if (!fa) return null;
  if (alwaysIn) return "edit";
  return fa;
}

export function createFolder({ projectId, name, userId, visibility = "restricted", parentId = null }) {
  const membership = requireProjectRole(projectId, userId);
  const project = getProject(projectId);
  let parent_id = null;
  if (parentId) {
    const parent = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(parentId);
    if (!parent || parent.project_id !== projectId) {
      throw Object.assign(new Error("Parent folder not found in this project"), { code: "VALIDATION" });
    }
    let depth = 1;
    let walk = parent;
    while (walk?.parent_id) {
      depth += 1;
      if (depth >= 8) {
        throw Object.assign(new Error("Folder nesting limit is 8 levels"), { code: "VALIDATION" });
      }
      walk = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(walk.parent_id);
    }
    parent_id = parentId;
  }
  const id = uuid();
  db.prepare(
    `INSERT INTO folders (id, project_id, name, parent_id, created_by, created_at, visibility)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, projectId, name.trim(), parent_id, userId, now(), visibility);
  audit({
    orgId: project.org_id,
    projectId,
    actorId: userId,
    action: "folder.created",
    targetType: "folder",
    targetId: id,
    meta: folderAuditMeta({ id, name: name.trim(), parent_id }, { visibility }),
  });
  return db.prepare(`SELECT * FROM folders WHERE id = ?`).get(id);
}

/** Breadcrumb names from root → folder (inclusive). */
export function folderPathNames(folderId) {
  const names = [];
  let cur = db.prepare(`SELECT id, name, parent_id FROM folders WHERE id = ?`).get(folderId);
  const guard = new Set();
  while (cur && !guard.has(cur.id)) {
    guard.add(cur.id);
    names.unshift(cur.name);
    cur = cur.parent_id
      ? db.prepare(`SELECT id, name, parent_id FROM folders WHERE id = ?`).get(cur.parent_id)
      : null;
  }
  return names;
}

/** People who already have access to a folder (creator + explicit grants). */
export function listFolderAudience(folderId) {
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) return [];
  const people = new Map();
  const creator = db.prepare(`SELECT id, name, email FROM users WHERE id = ?`).get(folder.created_by);
  if (creator) {
    people.set(creator.id, {
      userId: creator.id,
      name: creator.name,
      email: creator.email,
      folderAccess: "edit",
      locked: true,
    });
  }
  const grants = db
    .prepare(
      `SELECT fa.user_id AS userId, fa.access, u.name, u.email
       FROM folder_acl fa JOIN users u ON u.id = fa.user_id
       WHERE fa.folder_id = ?
       ORDER BY u.name`
    )
    .all(folderId);
  for (const g of grants) {
    if (people.has(g.userId)) continue;
    people.set(g.userId, {
      userId: g.userId,
      name: g.name,
      email: g.email,
      folderAccess: g.access,
      locked: false,
    });
  }
  return [...people.values()];
}

export function listFolderAcl(folderId, actorId) {
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const membership = requireProjectRole(folder.project_id, actorId);
  if (!canManageFolderAcl(folder, actorId, membership.role)) {
    throw Object.assign(new Error("Only the folder creator or a project admin can manage folder sharing"), {
      code: "FORBIDDEN",
    });
  }
  const audience = listFolderAudience(folderId);
  const creator = audience.find((p) => p.locked) || null;
  const grants = audience
    .filter((p) => !p.locked)
    .map((p) => ({ userId: p.userId, name: p.name, email: p.email, access: p.folderAccess }));
  const project = getProject(folder.project_id);
  audit({
    orgId: project.org_id,
    projectId: folder.project_id,
    actorId,
    action: "folder.acl_viewed",
    targetType: "folder",
    targetId: folder.id,
    meta: folderAuditMeta(folder),
  });
  return {
    folder: {
      id: folder.id,
      name: folder.name,
      visibility: folder.visibility,
      created_by: folder.created_by,
    },
    creator: creator
      ? { userId: creator.userId, name: creator.name, email: creator.email, access: "edit", locked: true }
      : null,
    grants,
  };
}

export function listFileAcl(fileId, actorId) {
  const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
  if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
  const membership = requireProjectRole(file.project_id, actorId);
  if (!canManageFileAcl(file, folder, actorId, membership.role)) {
    throw Object.assign(new Error("Only the folder creator, project admin, or file uploader can change file permissions"), {
      code: "FORBIDDEN",
    });
  }

  const audience = listFolderAudience(folder.id);
  const fileGrants = db
    .prepare(`SELECT user_id AS userId, access, can_delete AS canDelete FROM file_acl WHERE file_id = ?`)
    .all(fileId);
  const grantMap = new Map(
    fileGrants.map((g) => [g.userId, encodeFileAclLevel(g.access, !!g.canDelete)])
  );
  const inherit = fileGrants.length === 0;

  const project = getProject(file.project_id);
  audit({
    orgId: project.org_id,
    projectId: file.project_id,
    actorId,
    action: "file.acl_viewed",
    targetType: "file",
    targetId: file.id,
    meta: fileAuditMeta(file, folder),
  });

  // Others only — never show the actor their own row (cannot set own file ACL).
  const people = audience
    .filter((p) => p.userId !== actorId)
    .map((p) => ({
      userId: p.userId,
      name: p.name,
      email: p.email,
      folderAccess: p.folderAccess,
      locked: p.locked,
      fileAccess: grantMap.has(p.userId) ? grantMap.get(p.userId) : null,
    }));

  return {
    file: { id: file.id, name: file.name, folder_id: file.folder_id },
    inherit,
    people,
  };
}

export function listFolders(projectId, user) {
  const userId = typeof user === "string" ? user : user.id;
  const accessCtx =
    typeof user === "object" && user
      ? resolveProjectAccess(projectId, user)
      : { mode: "member", role: requireProjectRole(projectId, userId).role };

  const folders = db.prepare(`SELECT * FROM folders WHERE project_id = ? ORDER BY created_at`).all(projectId);
  const childCount = new Map();
  for (const f of folders) {
    if (f.parent_id) childCount.set(f.parent_id, (childCount.get(f.parent_id) || 0) + 1);
  }
  const depthOf = (folder) => {
    let d = 0;
    let cur = folder;
    const seen = new Set();
    while (cur?.parent_id && !seen.has(cur.id)) {
      seen.add(cur.id);
      d += 1;
      cur = folders.find((x) => x.id === cur.parent_id);
      if (d > 20) break;
    }
    return d;
  };
  if (accessCtx.mode === "oversight") {
    return folders.map((f, i) => ({
      ...f,
      access: "oversight",
      canManageAcl: false,
      number: i + 1,
      depth: depthOf(f),
      path: folderPathNames(f.id),
      childCount: childCount.get(f.id) || 0,
    }));
  }
  return folders
    .map((f) => {
      const access = folderAccess(f, userId, accessCtx.role);
      if (!access) return null;
      return {
        ...f,
        access,
        canManageAcl: canManageFolderAcl(f, userId, accessCtx.role),
        depth: depthOf(f),
        path: folderPathNames(f.id),
        childCount: childCount.get(f.id) || 0,
      };
    })
    .filter(Boolean)
    .map((f, i) => ({ ...f, number: i + 1 }));
}

export function setFolderAcl({ folderId, grants, actorId }) {
  // grants: [{ userId, access: 'read'|'edit' }]
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) {
    const err = new Error("Folder not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  const membership = requireProjectRole(folder.project_id, actorId);
  if (!canManageFolderAcl(folder, actorId, membership.role)) {
    const err = new Error("Only the folder creator or a project admin can manage folder sharing");
    err.code = "FORBIDDEN";
    throw err;
  }
  const project = getProject(folder.project_id);
  db.prepare(`DELETE FROM folder_acl WHERE folder_id = ?`).run(folderId);
  const ins = db.prepare(`INSERT INTO folder_acl (folder_id, user_id, access) VALUES (?, ?, ?)`);
  for (const g of grants) {
    if (g.access === "read" || g.access === "edit") ins.run(folderId, g.userId, g.access);
  }
  db.prepare(`UPDATE folders SET visibility = 'restricted' WHERE id = ?`).run(folderId);
  audit({
    orgId: project.org_id,
    projectId: folder.project_id,
    actorId,
    action: "folder.acl_updated",
    targetType: "folder",
    targetId: folderId,
    meta: folderAuditMeta(folder, { grants }),
  });
}

/** Apply the same share list to many folders (creator/project-admin only per folder). */
export function setFolderAclBulk({ folderIds, grants, actorId }) {
  const ids = [...new Set((folderIds || []).filter(Boolean))];
  if (!ids.length) {
    const err = new Error("No folders selected");
    err.code = "VALIDATION";
    throw err;
  }
  const applied = [];
  const skipped = [];
  for (const folderId of ids) {
    try {
      setFolderAcl({ folderId, grants, actorId });
      applied.push(folderId);
    } catch (e) {
      skipped.push({ folderId, error: e.message });
    }
  }
  return { applied, skipped };
}

export function setFolderVisibilityEveryone({ folderId, everyoneAccess, actorId }) {
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  requireProjectRole(folder.project_id, actorId, ["admin"]);
  // everyone = members visibility, clear ACL; edit for all via granting all members edit or leave default read
  db.prepare(`DELETE FROM folder_acl WHERE folder_id = ?`).run(folderId);
  db.prepare(`UPDATE folders SET visibility = 'members' WHERE id = ?`).run(folderId);
  if (everyoneAccess === "edit") {
    const members = db.prepare(`SELECT user_id FROM project_members WHERE project_id = ?`).all(folder.project_id);
    const ins = db.prepare(`INSERT INTO folder_acl (folder_id, user_id, access) VALUES (?, ?, 'edit')`);
    for (const m of members) {
      if (m.user_id === folder.created_by) continue;
      ins.run(folderId, m.user_id);
    }
  }
  const project = getProject(folder.project_id);
  audit({
    orgId: project.org_id,
    projectId: folder.project_id,
    actorId,
    action: "folder.visibility_updated",
    targetType: "folder",
    targetId: folderId,
    meta: folderAuditMeta(folder, { everyoneAccess }),
  });
}

export function listFiles(folderId, user) {
  const userId = typeof user === "string" ? user : user.id;
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const accessCtx =
    typeof user === "object" && user
      ? resolveProjectAccess(folder.project_id, user)
      : { mode: "member", role: requireProjectRole(folder.project_id, userId).role };

  if (accessCtx.mode === "member" && !folderAccess(folder, userId, accessCtx.role)) {
    throw Object.assign(new Error("Forbidden"), { code: "FORBIDDEN" });
  }

  const files = db
    .prepare(
      `SELECT f.*, fv.size AS size FROM files f
       LEFT JOIN file_versions fv ON fv.file_id = f.id AND fv.version = f.current_version
       WHERE f.folder_id = ? ORDER BY f.created_at`
    )
    .all(folderId);
  const out = [];
  let n = 0;
  for (const f of files) {
    const access =
      accessCtx.mode === "oversight" ? "oversight" : fileAccess(f, folder, userId, accessCtx.role);
    if (!access) continue;
    n += 1;
    const creator = db.prepare(`SELECT name, email FROM users WHERE id = ?`).get(f.created_by);
    out.push({
      ...f,
      access,
      number: n,
      createdByName: creator?.name || "unknown",
      canDelete: accessCtx.mode === "member" && canDeleteFile(f, folder, userId, accessCtx.role),
      canManageAcl:
        accessCtx.mode === "member" && canManageFileAcl(f, folder, userId, accessCtx.role),
      language: f.language || null,
      isCode: !!f.is_code,
      formatStatus: f.format_status || null,
      diagnostics: parseDiagnosticsJson(f.diagnostics_json).diagnostics,
      monacoLanguage: toMonacoLanguage(f.language || "plaintext"),
    });
  }
  return out;
}

export async function uploadFile({ folderId, userId, filename, buffer }) {
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const membership = requireProjectRole(folder.project_id, userId);
  if (!canUploadToFolder(folder, userId, membership.role)) {
    throw Object.assign(new Error("Forbidden"), { code: "FORBIDDEN" });
  }

  const processed = await processCodeContent({ filename, buffer, format: true });
  buffer = processed.buffer;

  const project = getProject(folder.project_id);
  const dek = getProjectDek(project);
  const retentionDays = effectiveRetentionDays(project);
  const ts = now();
  const retention_until = ts + retentionDays * 24 * 60 * 60 * 1000;

  const fileId = uuid();
  const version = 1;
  const enc = encryptBuffer(dek, buffer);
  const key = storagePath(project.id, fileId, version);
  fs.writeFileSync(key, enc);
  const checksum = sha256(buffer);

  db.prepare(
    `INSERT INTO files (id, project_id, folder_id, name, created_by, current_version, retention_until, created_at, updated_at, language, is_code, format_status, diagnostics_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    fileId,
    project.id,
    folderId,
    filename,
    userId,
    version,
    retention_until,
    ts,
    ts,
    processed.language,
    processed.isCode ? 1 : 0,
    processed.formatStatus,
    JSON.stringify({
      diagnostics: processed.diagnostics,
      formatError: processed.formatError,
      checkedAt: ts,
    })
  );

  const versionId = uuid();
  db.prepare(
    `INSERT INTO file_versions (id, file_id, version, size, storage_key, checksum, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(versionId, fileId, version, buffer.length, key, checksum, userId, ts);

  audit({
    orgId: project.org_id,
    projectId: project.id,
    actorId: userId,
    action: "file.uploaded",
    targetType: "file",
    targetId: fileId,
    meta: fileAuditMeta(
      { name: filename, folder_id: folderId },
      folder,
      {
        size: buffer.length,
        version,
        language: processed.language,
        formatStatus: processed.formatStatus,
        diagnosticCount: processed.diagnostics.length,
        errorCount: processed.diagnostics.filter((d) => d.severity === "error").length,
      }
    ),
  });

  return db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
}

export async function saveFileVersion({ fileId, userId, buffer, format = true, baseVersion = undefined }) {
  const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
  if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
  const membership = requireProjectRole(file.project_id, userId);
  const access = fileAccess(file, folder, userId, membership.role);
  if (access !== "edit") throw Object.assign(new Error("Forbidden"), { code: "FORBIDDEN" });

  if (baseVersion !== undefined && baseVersion !== null) {
    const expected = Number(baseVersion);
    if (!Number.isFinite(expected) || expected !== file.current_version) {
      throw Object.assign(
        new Error(
          `Edit conflict: file is now v${file.current_version} (you edited from v${expected}). Reload and try again.`
        ),
        { code: "CONFLICT", currentVersion: file.current_version }
      );
    }
  }

  const processed = await processCodeContent({ filename: file.name, buffer, format });
  buffer = processed.buffer;

  const project = getProject(file.project_id);
  const dek = getProjectDek(project);
  const version = file.current_version + 1;
  const enc = encryptBuffer(dek, buffer);
  const key = storagePath(project.id, fileId, version);
  fs.writeFileSync(key, enc);
  const checksum = sha256(buffer);
  const ts = now();

  db.prepare(
    `INSERT INTO file_versions (id, file_id, version, size, storage_key, checksum, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(uuid(), fileId, version, buffer.length, key, checksum, userId, ts);
  db.prepare(`UPDATE files SET current_version = ?, updated_at = ? WHERE id = ?`).run(version, ts, fileId);
  persistCodeMeta(fileId, processed);

  audit({
    orgId: project.org_id,
    projectId: project.id,
    actorId: userId,
    action: "file.version_saved",
    targetType: "file",
    targetId: fileId,
    meta: fileAuditMeta(file, folder, {
      version,
      size: buffer.length,
      language: processed.language,
      formatStatus: processed.formatStatus,
      diagnosticCount: processed.diagnostics.length,
      errorCount: processed.diagnostics.filter((d) => d.severity === "error").length,
    }),
  });

  return {
    file: db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId),
    language: processed.language,
    formatStatus: processed.formatStatus,
    diagnostics: processed.diagnostics,
  };
}

/** Lint current buffer without saving (live editor / upload probe). */
export function diagnoseFileText({ fileId, userId, text, filename }) {
  if (fileId) {
    const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
    if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
    const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
    const membership = requireProjectRole(file.project_id, userId);
    if (!fileAccess(file, folder, userId, membership.role)) {
      throw Object.assign(new Error("Forbidden"), { code: "FORBIDDEN" });
    }
    filename = filename || file.name;
  }
  const result = lintText(filename || "file.txt", text ?? "");
  return {
    ...result,
    monacoLanguage: toMonacoLanguage(result.language),
  };
}

export function readFileContent(fileId, user, version = null) {
  const userId = typeof user === "string" ? user : user.id;
  const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
  if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
  const project = getProject(file.project_id);

  if (typeof user === "object" && user) {
    const accessCtx = resolveProjectAccess(file.project_id, user);
    if (accessCtx.mode === "oversight") {
      audit({
        orgId: project.org_id,
        projectId: project.id,
        actorId: userId,
        action: "platform.oversight.file_content_denied",
        targetType: "file",
        targetId: fileId,
        meta: fileAuditMeta(file, folder, { reason: "platform_admin_cannot_decrypt" }),
      });
      throw Object.assign(new Error("Platform admins cannot open file contents — audit metadata only"), {
        code: "FORBIDDEN",
      });
    }
  }

  const membership = requireProjectRole(file.project_id, userId);
  const access = fileAccess(file, folder, userId, membership.role);
  if (!access) {
    audit({
      orgId: project.org_id,
      projectId: project.id,
      actorId: userId,
      action: "file.access_denied",
      targetType: "file",
      targetId: fileId,
      outcome: "failure",
      meta: fileAuditMeta(file, folder, { reason: "no_permission", message: "Forbidden" }),
    });
    throw Object.assign(new Error("Forbidden"), { code: "FORBIDDEN" });
  }

  const ver = version || file.current_version;
  const row = db.prepare(`SELECT * FROM file_versions WHERE file_id = ? AND version = ?`).get(fileId, ver);
  if (!row) throw Object.assign(new Error("Version not found"), { code: "NOT_FOUND" });

  const dek = getProjectDek(project);
  const blob = fs.readFileSync(row.storage_key);
  const plain = decryptBuffer(dek, blob);

  audit({
    orgId: project.org_id,
    projectId: project.id,
    actorId: userId,
    action: "file.read",
    targetType: "file",
    targetId: fileId,
    meta: fileAuditMeta(file, folder, { version: ver }),
  });

  return {
    file,
    version: row,
    buffer: plain,
    access,
    canDelete: canDeleteFile(file, folder, userId, membership.role),
    language: file.language || null,
    isCode: !!file.is_code,
    formatStatus: file.format_status || null,
    diagnostics: parseDiagnosticsJson(file.diagnostics_json).diagnostics,
    monacoLanguage: toMonacoLanguage(file.language || "plaintext"),
  };
}

export function listVersions(fileId, userId) {
  const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
  if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
  const membership = requireProjectRole(file.project_id, userId);
  const access = fileAccess(file, folder, userId, membership.role);
  if (!access) {
    throw Object.assign(new Error("Forbidden"), { code: "FORBIDDEN" });
  }
  const versions = db
    .prepare(
      `SELECT fv.version, fv.size, fv.checksum, fv.created_at, fv.created_by, u.name AS created_by_name
       FROM file_versions fv LEFT JOIN users u ON u.id = fv.created_by
       WHERE fv.file_id = ? ORDER BY fv.version DESC`
    )
    .all(fileId)
    .map((v) => ({
      ...v,
      isCurrent: v.version === file.current_version,
    }));
  const project = getProject(file.project_id);
  audit({
    orgId: project.org_id,
    projectId: file.project_id,
    actorId: userId,
    action: "file.versions_listed",
    targetType: "file",
    targetId: file.id,
    meta: fileAuditMeta(file, folder),
  });
  return {
    name: file.name,
    currentVersion: file.current_version,
    access,
    canRestore: access === "edit",
    versions,
  };
}

/**
 * Restore an older version by copying its bytes forward as a new version (history preserved).
 * Requires file edit access. Does not re-format content.
 */
export async function restoreFileVersion({ fileId, version, userId, note }) {
  const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
  if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
  const membership = requireProjectRole(file.project_id, userId);
  const access = fileAccess(file, folder, userId, membership.role);
  if (access !== "edit") {
    throw Object.assign(new Error("Forbidden — edit access required to restore"), { code: "FORBIDDEN" });
  }

  const fromVersion = Number(version);
  if (!Number.isInteger(fromVersion) || fromVersion < 1) {
    throw Object.assign(new Error("Invalid version"), { code: "VALIDATION" });
  }
  if (fromVersion === file.current_version) {
    throw Object.assign(new Error("That version is already current"), { code: "VALIDATION" });
  }

  const previousCurrent = file.current_version;

  const row = db
    .prepare(`SELECT * FROM file_versions WHERE file_id = ? AND version = ?`)
    .get(fileId, fromVersion);
  if (!row) throw Object.assign(new Error("Version not found"), { code: "NOT_FOUND" });

  const project = getProject(file.project_id);
  const dek = getProjectDek(project);
  const plain = decryptBuffer(dek, fs.readFileSync(row.storage_key));

  const newVersion = previousCurrent + 1;
  const enc = encryptBuffer(dek, plain);
  const key = storagePath(project.id, fileId, newVersion);
  fs.writeFileSync(key, enc);
  const checksum = sha256(plain);
  const ts = now();

  db.prepare(
    `INSERT INTO file_versions (id, file_id, version, size, storage_key, checksum, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(uuid(), fileId, newVersion, plain.length, key, checksum, userId, ts);
  db.prepare(`UPDATE files SET current_version = ?, updated_at = ? WHERE id = ?`).run(newVersion, ts, fileId);

  // Refresh language/diagnostics from restored bytes without mutating them
  let language = file.language || "plaintext";
  let isCode = !!file.is_code;
  let diagnostics = [];
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(plain);
    const lint = lintText(file.name, text);
    language = lint.language;
    isCode = lint.isCode;
    diagnostics = lint.diagnostics;
    persistCodeMeta(fileId, {
      language,
      isCode,
      formatStatus: "restored",
      diagnostics,
      formatError: null,
    });
  } catch {
    persistCodeMeta(fileId, {
      language: "plaintext",
      isCode: false,
      formatStatus: "restored",
      diagnostics: [],
      formatError: null,
    });
  }

  const noteClean = note != null && String(note).trim() ? String(note).trim().slice(0, 500) : null;
  audit({
    orgId: project.org_id,
    projectId: project.id,
    actorId: userId,
    action: "file.version_restored",
    targetType: "file",
    targetId: fileId,
    meta: fileAuditMeta(file, folder, {
      restoredFrom: fromVersion,
      previousCurrent,
      newVersion,
      size: plain.length,
      note: noteClean,
    }),
  });

  return {
    file: db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId),
    restoredFrom: fromVersion,
    newVersion,
    language,
    diagnostics,
  };
}

export function setFileAcl({ fileId, grants, inherit, actorId }) {
  const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
  if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
  const membership = requireProjectRole(file.project_id, actorId);
  if (!canManageFileAcl(file, folder, actorId, membership.role)) {
    throw Object.assign(new Error("Only the folder creator, project admin, or file uploader can change file permissions"), {
      code: "FORBIDDEN",
    });
  }

  const audience = listFolderAudience(file.folder_id);
  const audienceMap = new Map(audience.map((p) => [p.userId, p]));
  const folderAclSnap = db
    .prepare(`SELECT user_id AS userId, access FROM folder_acl WHERE folder_id = ? ORDER BY user_id`)
    .all(file.folder_id);

  const applied = [];
  db.exec("BEGIN");
  try {
    db.prepare(`DELETE FROM file_acl WHERE file_id = ?`).run(fileId);
    if (!inherit) {
      const ins = db.prepare(
        `INSERT INTO file_acl (file_id, user_id, access, can_delete) VALUES (?, ?, ?, ?)`
      );
      for (const g of grants || []) {
        const person = audienceMap.get(g.userId);
        // Skip locked creator + actor (own row is not editable / not shown).
        if (!person || person.locked || g.userId === actorId) continue;
        const decoded = decodeFileAclLevel(g.access);
        if (!decoded) continue;
        const { access, canDelete } = decoded;
        // Always persist under custom ACL so "Can edit" clearly clears can_delete
        // (sparse skip used to drop the row and leave confusing inherit behavior).
        ins.run(fileId, g.userId, access, canDelete ? 1 : 0);
        applied.push({
          userId: g.userId,
          access: encodeFileAclLevel(access, !!canDelete),
        });
      }
    }
    const folderAclAfter = db
      .prepare(`SELECT user_id AS userId, access FROM folder_acl WHERE folder_id = ? ORDER BY user_id`)
      .all(file.folder_id);
    if (JSON.stringify(folderAclSnap) !== JSON.stringify(folderAclAfter)) {
      throw Object.assign(new Error("Internal error: file permissions must not change folder permissions"), {
        code: "INTERNAL",
      });
    }
    db.exec("COMMIT");
  } catch (e) {
    try {
      db.exec("ROLLBACK");
    } catch {
      /* ignore */
    }
    throw e;
  }

  const project = getProject(file.project_id);
  audit({
    orgId: project.org_id,
    projectId: file.project_id,
    actorId,
    action: "file.acl_updated",
    targetType: "file",
    targetId: fileId,
    meta: fileAuditMeta(file, folder, { inherit: !!inherit, grants: inherit ? null : applied }),
  });
}

/** Apply the same file ACL to many files in one folder. */
export function setFileAclBulk({ folderId, fileIds, grants, inherit, actorId }) {
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const ids = [...new Set((fileIds || []).filter(Boolean))];
  if (!ids.length) {
    const err = new Error("No files selected");
    err.code = "VALIDATION";
    throw err;
  }
  const applied = [];
  const skipped = [];
  for (const fileId of ids) {
    const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
    if (!file || file.folder_id !== folderId) {
      skipped.push({ fileId, error: "Not in this folder" });
      continue;
    }
    try {
      setFileAcl({ fileId, grants, inherit, actorId });
      applied.push(fileId);
    } catch (e) {
      skipped.push({ fileId, error: e.message });
    }
  }
  return { applied, skipped };
}

/** Remove a user from every folder_acl (+ their file_acl) in a project. */
export function offboardUserFromProjectFolders({ projectId, userId, actorId }) {
  const membership = requireProjectRole(projectId, actorId);
  const project = getProject(projectId);
  // Actor must be project admin or org owner/admin
  const orgMem = db
    .prepare(`SELECT role FROM org_members WHERE org_id = ? AND user_id = ?`)
    .get(project.org_id, actorId);
  const allowed =
    membership.role === "admin" ||
    (orgMem && (orgMem.role === "owner" || orgMem.role === "admin"));
  if (!allowed) throw Object.assign(new Error("Forbidden"), { code: "FORBIDDEN" });

  const folders = db.prepare(`SELECT id, created_by FROM folders WHERE project_id = ?`).all(projectId);
  let folderAclRemoved = 0;
  let fileAclRemoved = 0;
  let foldersSkippedCreator = 0;
  for (const folder of folders) {
    if (folder.created_by === userId) {
      foldersSkippedCreator += 1;
      continue; // cannot strip creator from their own folder ACL identity
    }
    const r = db.prepare(`DELETE FROM folder_acl WHERE folder_id = ? AND user_id = ?`).run(folder.id, userId);
    folderAclRemoved += r.changes || 0;
    const fr = db
      .prepare(
        `DELETE FROM file_acl WHERE user_id = ? AND file_id IN (SELECT id FROM files WHERE folder_id = ?)`
      )
      .run(userId, folder.id);
    fileAclRemoved += fr.changes || 0;
  }
  audit({
    orgId: project.org_id,
    projectId,
    actorId,
    action: "project.user_offboarded_folders",
    targetType: "user",
    targetId: userId,
    meta: { folderAclRemoved, fileAclRemoved, foldersSkippedCreator },
  });
  return { folderAclRemoved, fileAclRemoved, foldersSkippedCreator };
}

/** Copy share list from source folder onto many target folders. */
export function copyFolderAcl({ sourceFolderId, targetFolderIds, actorId }) {
  const source = listFolderAcl(sourceFolderId, actorId);
  const grants = (source.grants || []).map((g) => ({ userId: g.userId, access: g.access }));
  return setFolderAclBulk({ folderIds: targetFolderIds, grants, actorId });
}

/** Reset selected files to inherit folder ACL. */
export function resetFilesToFolderAcl({ folderId, fileIds, actorId }) {
  return setFileAclBulk({ folderId, fileIds, grants: [], inherit: true, actorId });
}

/** Delete many files; per-file delete permission still enforced. */
export function deleteFilesBulk({ fileIds, userId }) {
  const ids = [...new Set((fileIds || []).filter(Boolean))];
  const deleted = [];
  const skipped = [];
  for (const fileId of ids) {
    try {
      deleteFile(fileId, userId);
      deleted.push(fileId);
    } catch (e) {
      skipped.push({ fileId, error: e.message });
    }
  }
  return { deleted, skipped };
}

export function deleteFile(fileId, userId) {
  const file = db.prepare(`SELECT * FROM files WHERE id = ?`).get(fileId);
  if (!file) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(file.folder_id);
  const membership = requireProjectRole(file.project_id, userId);
  if (!canDeleteFile(file, folder, userId, membership.role)) {
    throw Object.assign(
      new Error("You do not have delete permission for this file — ask the folder admin to grant Can edit + delete"),
      { code: "FORBIDDEN" }
    );
  }
  const project = getProject(file.project_id);
  const versions = db.prepare(`SELECT storage_key FROM file_versions WHERE file_id = ?`).all(fileId);
  db.prepare(`DELETE FROM files WHERE id = ?`).run(fileId);
  for (const v of versions) {
    try {
      fs.unlinkSync(v.storage_key);
    } catch {
      /* ignore */
    }
  }
  audit({
    orgId: project.org_id,
    projectId: file.project_id,
    actorId: userId,
    action: "file.deleted",
    targetType: "file",
    targetId: fileId,
    meta: fileAuditMeta(file, folder),
  });
}

export function deleteFolder(folderId, userId) {
  const folder = db.prepare(`SELECT * FROM folders WHERE id = ?`).get(folderId);
  if (!folder) throw Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
  if (folder.created_by !== userId) {
    throw Object.assign(new Error("You can only delete folders you created"), { code: "FORBIDDEN" });
  }
  const childFolders = db.prepare(`SELECT COUNT(*) AS c FROM folders WHERE parent_id = ?`).get(folderId).c;
  if (childFolders > 0) {
    throw Object.assign(new Error("Delete or move nested folders first"), { code: "CONFLICT" });
  }
  const files = db.prepare(`SELECT id FROM files WHERE folder_id = ?`).all(folderId);
  for (const f of files) deleteFile(f.id, userId);
  // leftover files owned by others block? only delete own files - if others' files remain, refuse
  const remaining = db.prepare(`SELECT COUNT(*) AS c FROM files WHERE folder_id = ?`).get(folderId).c;
  if (remaining > 0) {
    throw Object.assign(new Error("Folder still has files owned by others"), { code: "CONFLICT" });
  }
  const project = getProject(folder.project_id);
  db.prepare(`DELETE FROM folders WHERE id = ?`).run(folderId);
  audit({
    orgId: project.org_id,
    projectId: folder.project_id,
    actorId: userId,
    action: "folder.deleted",
    targetType: "folder",
    targetId: folderId,
    meta: folderAuditMeta(folder),
  });
}
