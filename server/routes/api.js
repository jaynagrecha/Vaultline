import { Router } from "express";
import { requireAuth } from "../middleware/auth.js";
import {
  createOrg,
  listOrgsForUser,
  getOrg,
  listOrgMembers,
  addOrgMember,
  addOrgMembersBulk,
  removeOrgMember,
  removeOrgMembersBulk,
  updateOrgMembersRolesBulk,
  updateOrgRetention,
  requireOrgRole,
} from "../services/orgs.js";
import { findUserByEmail, findUserById, searchUsersForInvite, userCanCreateOrg } from "../services/auth.js";
import { listAudit, exportAuditJson, auditFromReq } from "../services/audit.js";
import {
  createProject,
  listProjectsForUser,
  joinProjectByInvite,
  listProjectMembers,
  addProjectMember,
  addProjectMembersBulk,
  removeProjectMember,
  removeProjectMembersBulk,
  updateProjectMembersRolesBulk,
  rotateInviteCode,
  getProject,
  resolveProjectAccess,
  canManageProjectMembers,
} from "../services/projects.js";
import * as files from "../services/files.js";
import multer from "multer";
import { config } from "../config.js";
import { uploadLimiter } from "../middleware/rateLimit.js";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes },
});

const router = Router();
router.use(requireAuth);

// —— User directory search (typeahead; never dumps full user list) ——
router.get("/users/search", (req, res) => {
  try {
    const q = String(req.query.q || "");
    const orgId = req.query.orgId || null;
    const projectId = req.query.projectId || null;
    if (!orgId && !projectId) {
      return res.status(400).json({ error: "orgId or projectId required" });
    }
    if (orgId) {
      requireOrgRole(orgId, req.user.id, ["owner", "admin"]);
    }
    if (projectId && !canManageProjectMembers(projectId, req.user.id)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    const users = searchUsersForInvite({
      q,
      excludeOrgId: orgId || null,
      excludeProjectId: projectId || null,
      limit: Number(req.query.limit) || 20,
    });
    res.json({ users, q });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

// —— Orgs ——
router.get("/orgs", (req, res) => {
  const orgs = listOrgsForUser(req.user.id, { platformAdmin: !!req.user.isPlatformAdmin });
  res.setHeader("Cache-Control", "no-store");
  res.json({ orgs });
});

router.post("/orgs", (req, res) => {
  try {
    if (!userCanCreateOrg(req.user)) {
      return res.status(403).json({ error: "You are not allowed to create organizations. Ask a platform admin." });
    }
    const { name, retentionDays } = req.body || {};
    if (!name) return res.status(400).json({ error: "Name required" });
    const org = createOrg({ name, retentionDays: retentionDays || 365, userId: req.user.id });
    res.status(201).json({ org });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get("/orgs/:orgId", (req, res) => {
  try {
    requireOrgRole(req.params.orgId, req.user.id);
    res.json({ org: getOrg(req.params.orgId), members: listOrgMembers(req.params.orgId), oversight: false });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.post("/orgs/:orgId/members", (req, res) => {
  try {
    const { email, userId, role } = req.body || {};
    const user = userId ? findUserById(userId) : findUserByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found — they must register first" });
    if (user.status !== "active") return res.status(400).json({ error: "User account is not active" });
    addOrgMember({ orgId: req.params.orgId, userId: user.id, role: role || "member", actorId: req.user.id });
    res.json({ ok: true, members: listOrgMembers(req.params.orgId) });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/orgs/:orgId/members/bulk", (req, res) => {
  try {
    const { userIds, role, entries } = req.body || {};
    const result = addOrgMembersBulk({
      orgId: req.params.orgId,
      actorId: req.user.id,
      userIds: userIds || [],
      role: role || "member",
      entries: entries || [],
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/orgs/:orgId/members/bulk-roles", (req, res) => {
  try {
    const result = updateOrgMembersRolesBulk({
      orgId: req.params.orgId,
      actorId: req.user.id,
      userIds: req.body?.userIds || [],
      role: req.body?.role,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/orgs/:orgId/members/bulk-remove", (req, res) => {
  try {
    const result = removeOrgMembersBulk({
      orgId: req.params.orgId,
      actorId: req.user.id,
      userIds: req.body?.userIds || [],
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.delete("/orgs/:orgId/members/:userId", (req, res) => {
  try {
    removeOrgMember({ orgId: req.params.orgId, userId: req.params.userId, actorId: req.user.id });
    res.json({ ok: true, members: listOrgMembers(req.params.orgId) });
  } catch (e) {
    const status =
      e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : e.code === "VALIDATION" ? 400 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.patch("/orgs/:orgId/retention", (req, res) => {
  try {
    const days = Number(req.body?.retentionDays);
    if (!days || days < 1) return res.status(400).json({ error: "Invalid retentionDays" });
    updateOrgRetention(req.params.orgId, days, req.user.id);
    res.json({ org: getOrg(req.params.orgId) });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.get("/orgs/:orgId/audit", (req, res) => {
  try {
    requireOrgRole(req.params.orgId, req.user.id, ["owner", "admin"]);
    const events = listAudit({ orgId: req.params.orgId, limit: Number(req.query.limit) || 200 });
    auditFromReq(req, {
      orgId: req.params.orgId,
      actorId: req.user.id,
      action: "org.audit_viewed",
      targetType: "org",
      targetId: req.params.orgId,
    });
    res.json({ events });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.get("/orgs/:orgId/audit/export", (req, res) => {
  try {
    requireOrgRole(req.params.orgId, req.user.id, ["owner", "admin"]);
    const payload = exportAuditJson({ orgId: req.params.orgId, limit: 10000 });
    auditFromReq(req, {
      orgId: req.params.orgId,
      actorId: req.user.id,
      action: "org.audit_exported",
      targetType: "org",
      targetId: req.params.orgId,
    });
    res.setHeader("Content-Disposition", `attachment; filename="org-audit-${req.params.orgId}.json"`);
    res.json(payload);
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

// —— Projects ——
router.get("/projects", (req, res) => {
  const projects = listProjectsForUser(req.user.id, req.query.orgId || null, {
    platformAdmin: !!req.user.isPlatformAdmin,
  });
  res.json({ projects });
});

router.post("/projects", (req, res) => {
  try {
    const { orgId, name, retentionDays } = req.body || {};
    if (!orgId || !name) return res.status(400).json({ error: "orgId and name required" });
    const result = createProject({ orgId, name, userId: req.user.id, retentionDays: retentionDays ?? null });
    res.status(201).json(result);
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.post("/projects/join", (req, res) => {
  try {
    const { inviteCode } = req.body || {};
    if (!inviteCode || !String(inviteCode).trim()) {
      auditFromReq(req, {
        actorId: req.user.id,
        action: "project.join_failed",
        targetType: "invite",
        outcome: "failure",
        meta: { reason: "missing_code", message: "Invite code required" },
      });
      return res.status(400).json({ error: "inviteCode required" });
    }
    const result = joinProjectByInvite({ inviteCode, userId: req.user.id });
    res.json(result);
  } catch (e) {
    const status = e.code === "NOT_FOUND" ? 404 : e.code === "FORBIDDEN" ? 403 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.get("/projects/:projectId", (req, res) => {
  try {
    const access = resolveProjectAccess(req.params.projectId, req.user);
    const project = getProject(req.params.projectId);
    if (access.mode === "oversight" && req.query.sync !== "1") {
      auditFromReq(req, {
        orgId: project.org_id,
        projectId: project.id,
        actorId: req.user.id,
        action: "platform.oversight.project_viewed",
        targetType: "project",
        targetId: project.id,
        meta: { name: project.name },
      });
    } else if (access.mode === "member" && req.query.sync !== "1") {
      auditFromReq(req, {
        orgId: project.org_id,
        projectId: project.id,
        actorId: req.user.id,
        action: "project.opened",
        targetType: "project",
        targetId: project.id,
        meta: { name: project.name },
      });
    }
    res.json({
      project,
      members: listProjectMembers(req.params.projectId),
      folders: files.listFolders(req.params.projectId, req.user),
      oversight: access.mode === "oversight",
      myRole: access.role,
    });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.post("/projects/:projectId/members", (req, res) => {
  try {
    const { email, userId, role } = req.body || {};
    const user = userId ? findUserById(userId) : findUserByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found — they must register first" });
    if (user.status !== "active") return res.status(400).json({ error: "User account is not active" });
    addProjectMember({
      projectId: req.params.projectId,
      userId: user.id,
      role: role || "member",
      actorId: req.user.id,
    });
    res.json({ members: listProjectMembers(req.params.projectId) });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/projects/:projectId/members/bulk", (req, res) => {
  try {
    const result = addProjectMembersBulk({
      projectId: req.params.projectId,
      actorId: req.user.id,
      userIds: req.body?.userIds || [],
      role: req.body?.role || "member",
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/projects/:projectId/members/bulk-remove", (req, res) => {
  try {
    const result = removeProjectMembersBulk({
      projectId: req.params.projectId,
      actorId: req.user.id,
      userIds: req.body?.userIds || [],
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/projects/:projectId/members/bulk-roles", (req, res) => {
  try {
    const result = updateProjectMembersRolesBulk({
      projectId: req.params.projectId,
      actorId: req.user.id,
      userIds: req.body?.userIds || [],
      role: req.body?.role,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/projects/:projectId/offboard-folders", (req, res) => {
  try {
    const userId = req.body?.userId;
    if (!userId) return res.status(400).json({ error: "userId required" });
    const result = files.offboardUserFromProjectFolders({
      projectId: req.params.projectId,
      userId,
      actorId: req.user.id,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.post("/projects/:projectId/folders/acl/copy", (req, res) => {
  try {
    const result = files.copyFolderAcl({
      sourceFolderId: req.body?.sourceFolderId,
      targetFolderIds: req.body?.targetFolderIds || [],
      actorId: req.user.id,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.delete("/projects/:projectId/members/:userId", (req, res) => {
  try {
    removeProjectMember({
      projectId: req.params.projectId,
      userId: req.params.userId,
      actorId: req.user.id,
    });
    res.json({ members: listProjectMembers(req.params.projectId) });
  } catch (e) {
    const status =
      e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : e.code === "VALIDATION" ? 400 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.post("/projects/:projectId/invite/rotate", (req, res) => {
  try {
    const inviteCode = rotateInviteCode(req.params.projectId, req.user.id);
    res.json({ inviteCode });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

// —— Folders / files ——
router.post("/projects/:projectId/folders", (req, res) => {
  try {
    const { name, visibility, parentId } = req.body || {};
    if (!name) return res.status(400).json({ error: "name required" });
    const folder = files.createFolder({
      projectId: req.params.projectId,
      name,
      userId: req.user.id,
      visibility: visibility || "members",
      parentId: parentId || null,
    });
    res.status(201).json({ folder });
  } catch (e) {
    res
      .status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500)
      .json({ error: e.message });
  }
});

router.get("/folders/:folderId/files", (req, res) => {
  try {
    const list = files.listFiles(req.params.folderId, req.user);
    res.setHeader("Cache-Control", "no-store");
    res.json({ files: list });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

router.get("/folders/:folderId/acl", (req, res) => {
  try {
    res.json(files.listFolderAcl(req.params.folderId, req.user.id));
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

router.post("/folders/:folderId/acl", (req, res) => {
  try {
    const { grants, everyoneAccess } = req.body || {};
    if (everyoneAccess) {
      files.setFolderVisibilityEveryone({
        folderId: req.params.folderId,
        everyoneAccess,
        actorId: req.user.id,
      });
    } else {
      files.setFolderAcl({ folderId: req.params.folderId, grants: grants || [], actorId: req.user.id });
    }
    res.json({ ok: true, ...(files.listFolderAcl(req.params.folderId, req.user.id)) });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.post("/projects/:projectId/folders/acl/bulk", (req, res) => {
  try {
    const { folderIds, grants } = req.body || {};
    const result = files.setFolderAclBulk({
      folderIds: folderIds || [],
      grants: grants || [],
      actorId: req.user.id,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/folders/:folderId/files/acl/bulk", (req, res) => {
  try {
    const result = files.setFileAclBulk({
      folderId: req.params.folderId,
      fileIds: req.body?.fileIds || [],
      grants: req.body?.grants || [],
      inherit: !!req.body?.inherit,
      actorId: req.user.id,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/folders/:folderId/files/acl/reset", (req, res) => {
  try {
    const result = files.resetFilesToFolderAcl({
      folderId: req.params.folderId,
      fileIds: req.body?.fileIds || [],
      actorId: req.user.id,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "VALIDATION" ? 400 : 500).json({ error: e.message });
  }
});

router.post("/folders/:folderId/files/bulk-delete", (req, res) => {
  try {
    const result = files.deleteFilesBulk({
      fileIds: req.body?.fileIds || [],
      userId: req.user.id,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.delete("/folders/:folderId", (req, res) => {
  try {
    files.deleteFolder(req.params.folderId, req.user.id);
    res.json({ ok: true });
  } catch (e) {
    const status = e.code === "FORBIDDEN" ? 403 : e.code === "CONFLICT" ? 409 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.post("/folders/:folderId/files", uploadLimiter, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "file required" });
    const file = await files.uploadFile({
      folderId: req.params.folderId,
      userId: req.user.id,
      filename: req.file.originalname,
      buffer: req.file.buffer,
    });
    res.status(201).json({
      file,
      language: file.language,
      isCode: !!file.is_code,
      formatStatus: file.format_status,
      diagnostics: (() => {
        try {
          return JSON.parse(file.diagnostics_json || "{}").diagnostics || [];
        } catch {
          return [];
        }
      })(),
    });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.get("/files/:fileId/content", (req, res) => {
  try {
    const result = files.readFileContent(
      req.params.fileId,
      req.user,
      req.query.version ? Number(req.query.version) : null
    );
    res.setHeader("Cache-Control", "no-store");
    res.json({
      name: result.file.name,
      size: result.version.size,
      version: result.version.version,
      currentVersion: result.file.current_version,
      access: result.access,
      canDelete: !!result.canDelete,
      language: result.language,
      isCode: result.isCode,
      formatStatus: result.formatStatus,
      diagnostics: result.diagnostics,
      monacoLanguage: result.monacoLanguage,
      contentBase64: result.buffer.toString("base64"),
      text: (() => {
        try {
          return new TextDecoder("utf-8", { fatal: true }).decode(result.buffer);
        } catch {
          return null;
        }
      })(),
    });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

router.put("/files/:fileId/content", async (req, res) => {
  try {
    const text = req.body?.text;
    if (typeof text !== "string") return res.status(400).json({ error: "text required" });
    const format = req.body?.format !== false;
    const baseVersion = req.body?.baseVersion;
    const result = await files.saveFileVersion({
      fileId: req.params.fileId,
      userId: req.user.id,
      buffer: Buffer.from(text, "utf8"),
      format,
      baseVersion,
    });
    res.json({
      file: result.file,
      language: result.language,
      formatStatus: result.formatStatus,
      diagnostics: result.diagnostics,
      currentVersion: result.file.current_version,
    });
  } catch (e) {
    const status = e.code === "FORBIDDEN" ? 403 : e.code === "CONFLICT" ? 409 : 500;
    res.status(status).json({
      error: e.message,
      code: e.code || undefined,
      currentVersion: e.currentVersion,
    });
  }
});

router.post("/files/:fileId/diagnostics", (req, res) => {
  try {
    const text = req.body?.text;
    if (typeof text !== "string") return res.status(400).json({ error: "text required" });
    const result = files.diagnoseFileText({
      fileId: req.params.fileId,
      userId: req.user.id,
      text,
      filename: req.body?.filename,
    });
    res.json(result);
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

router.post("/code/diagnostics", (req, res) => {
  try {
    const text = req.body?.text;
    const filename = req.body?.filename || "snippet.txt";
    if (typeof text !== "string") return res.status(400).json({ error: "text required" });
    const result = files.diagnoseFileText({
      userId: req.user.id,
      text,
      filename,
    });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get("/files/:fileId/versions", (req, res) => {
  try {
    res.json(files.listVersions(req.params.fileId, req.user.id));
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : 500).json({ error: e.message });
  }
});

router.post("/files/:fileId/versions/restore", async (req, res) => {
  try {
    const version = req.body?.version;
    if (version == null) return res.status(400).json({ error: "version required" });
    const result = await files.restoreFileVersion({
      fileId: req.params.fileId,
      version,
      userId: req.user.id,
      note: req.body?.note,
    });
    res.json({
      ok: true,
      file: result.file,
      restoredFrom: result.restoredFrom,
      newVersion: result.newVersion,
      language: result.language,
      diagnostics: result.diagnostics,
    });
  } catch (e) {
    const status =
      e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : e.code === "VALIDATION" ? 400 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.get("/files/:fileId/acl", (req, res) => {
  try {
    res.json(files.listFileAcl(req.params.fileId, req.user.id));
  } catch (e) {
    const status = e.code === "FORBIDDEN" ? 403 : e.code === "NOT_FOUND" ? 404 : 500;
    res.status(status).json({ error: e.message });
  }
});

router.post("/files/:fileId/acl", (req, res) => {
  try {
    files.setFileAcl({
      fileId: req.params.fileId,
      grants: req.body?.grants || [],
      inherit: !!req.body?.inherit,
      actorId: req.user.id,
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

router.delete("/files/:fileId", (req, res) => {
  try {
    files.deleteFile(req.params.fileId, req.user.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(e.code === "FORBIDDEN" ? 403 : 500).json({ error: e.message });
  }
});

export default router;
