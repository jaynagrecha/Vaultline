/**
 * Offline ACL smoke checks (no HTTP). Run: npm run smoke:acl
 */
import { db } from "../db.js";
import {
  fileAccess,
  canManageFileAcl,
  canDeleteFile,
  encodeFileAclLevel,
  decodeFileAclLevel,
} from "../services/files.js";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const levels = ["read", "edit", "edit_delete", "none"];
for (const level of levels) {
  const d = decodeFileAclLevel(level);
  assert(d, `decode ${level}`);
  const enc = encodeFileAclLevel(d.access, !!d.canDelete);
  assert(enc === level, `roundtrip ${level} got ${enc}`);
}

const folder = { id: "f1", created_by: "creator", visibility: "restricted" };
const file = { id: "smoke-file-1", created_by: "uploader", folder_id: "f1", project_id: "p1" };

db.exec("PRAGMA foreign_keys = OFF");
db.prepare(`DELETE FROM file_acl WHERE file_id = ?`).run(file.id);

assert(fileAccess(file, folder, "creator", "member") === "edit", "creator always edit without ACL");
assert(fileAccess(file, folder, "po", "admin") === "edit", "project owner always edit");

db.prepare(`INSERT INTO file_acl (file_id, user_id, access, can_delete) VALUES (?, ?, 'none', 0)`).run(
  file.id,
  "uploader"
);
assert(fileAccess(file, folder, "uploader", "member") === null, "uploader none → no access");
assert(fileAccess(file, folder, "creator", "member") === "edit", "creator still in after none on uploader");
assert(canManageFileAcl(file, folder, "uploader", "member") === false, "uploader cannot manage ACL when denied");
assert(canManageFileAcl(file, folder, "creator", "member") === true, "creator can manage ACL");
assert(canDeleteFile(file, folder, "uploader", "member") === false, "uploader cannot delete when none");

db.prepare(`DELETE FROM file_acl WHERE file_id = ?`).run(file.id);
db.exec("PRAGMA foreign_keys = ON");
console.log("smoke-acl: ok");
