/**
 * Audit action catalog: category + human template.
 * Templates use {actor}, {org}, {project}, {target}, {name}, and meta.* keys.
 */

export const AUDIT_CATEGORIES = {
  read: { id: "read", label: "View / read" },
  change: { id: "change", label: "Create / edit / delete" },
  restore: { id: "restore", label: "Restore / rollback" },
  access: { id: "access", label: "People & permissions" },
  auth: { id: "auth", label: "Sign-in & accounts" },
  admin: { id: "admin", label: "Platform admin" },
};

/** @type {Record<string, { category: keyof typeof AUDIT_CATEGORIES, label: string, template: string }>} */
export const AUDIT_ACTIONS = {
  // Auth
  "user.registered": { category: "auth", label: "Registered", template: "{actor} registered (pending email activation)" },
  "user.activated": { category: "auth", label: "Activated", template: "{actor} activated their account via email" },
  "user.activation_resent": { category: "auth", label: "Activation resent", template: "{actor} requested a new activation email" },
  "user.password_reset_requested": { category: "auth", label: "Password reset requested", template: "{actor} requested a password reset email" },
  "user.password_reset": { category: "auth", label: "Password reset", template: "{actor} set a new password via reset code/link" },
  "user.login": { category: "auth", label: "Signed in", template: "{actor} signed in" },
  "user.login_failed": { category: "auth", label: "Sign-in failed", template: "Failed sign-in attempt{email}" },
  "user.login_oidc": { category: "auth", label: "SSO sign-in", template: "{actor} signed in with SSO" },
  "user.logout": { category: "auth", label: "Signed out", template: "{actor} signed out" },
  "user.disabled": { category: "auth", label: "User disabled", template: "{actor} disabled account {targetUser}" },
  "user.enabled": { category: "auth", label: "User enabled", template: "{actor} re-enabled account {targetUser}" },
  "user.platform_admin_granted": {
    category: "admin",
    label: "Platform admin granted",
    template: "{actor} made {targetUser} a platform admin",
  },
  "user.platform_admin_revoked": {
    category: "admin",
    label: "Platform admin revoked",
    template: "{actor} removed platform admin from {targetUser}",
  },
  "user.can_create_org_granted": {
    category: "admin",
    label: "Org-create allowed",
    template: "{actor} allowed {targetUser} to create organizations",
  },
  "user.can_create_org_revoked": {
    category: "admin",
    label: "Org-create revoked",
    template: "{actor} revoked org-create for {targetUser}",
  },
  "user.platform_admin_bootstrap": {
    category: "admin",
    label: "Bootstrap admin",
    template: "{actor} was bootstrapped as platform admin",
  },

  // Orgs
  "org.created": { category: "change", label: "Org created", template: "{actor} created organization {org}" },
  "org.member_added": {
    category: "access",
    label: "Org member added",
    template: "{actor} added {member} to {org} as {role}",
  },
  "org.members_bulk_added": {
    category: "access",
    label: "Org members mass-added",
    template: "{actor} mass-added members to {org}",
  },
  "org.member_removed": {
    category: "access",
    label: "Org member removed",
    template: "{actor} removed a member from {org}",
  },
  "org.members_roles_bulk": {
    category: "access",
    label: "Org roles mass-updated",
    template: "{actor} changed roles for multiple members in {org}",
  },
  "org.retention_updated": {
    category: "change",
    label: "Retention updated",
    template: "{actor} updated retention settings for {org}",
  },
  "org.audit_viewed": { category: "read", label: "Org audit viewed", template: "{actor} viewed the audit log for {org}" },
  "org.audit_exported": {
    category: "read",
    label: "Org audit exported",
    template: "{actor} exported the audit log for {org}",
  },

  // Projects
  "project.created": { category: "change", label: "Project created", template: "{actor} created project {project} in {org}" },
  "project.joined": {
    category: "access",
    label: "Joined project",
    template: "{actor} joined project {project}{alreadyMemberPhrase}",
  },
  "project.join_failed": {
    category: "access",
    label: "Join project failed",
    template: "{actor} tried to join a project — failed{reasonPhrase}",
  },
  "project.opened": { category: "read", label: "Opened project", template: "{actor} opened project {project}" },
  "project.member_added": {
    category: "access",
    label: "Project member added",
    template: "{actor} added {member} to {project} as {role}",
  },
  "project.member_removed": {
    category: "access",
    label: "Project member removed",
    template: "{actor} removed a member from {project}",
  },
  "project.invite_rotated": {
    category: "access",
    label: "Invite rotated",
    template: "{actor} rotated the invite code for {project}",
  },
  "project.user_offboarded_folders": {
    category: "access",
    label: "Offboarded from folders",
    template: "{actor} removed folder access for a user across {project}",
  },
  "file.access_denied": {
    category: "access",
    label: "File access denied",
    template: "{actor} was denied access to {name}{folderPhrase}{reasonPhrase}",
  },

  // Folders
  "file.uploaded": {
    category: "change",
    label: "File uploaded",
    template: "{actor} uploaded {name}{folderPhrase} to {project}",
  },
  "file.read": { category: "read", label: "File opened", template: "{actor} opened {name}{folderPhrase}{versionPhrase}" },
  "file.version_saved": {
    category: "change",
    label: "File edited",
    template: "{actor} edited {name}{folderPhrase} and saved a new version{versionPhrase}",
  },
  "file.version_restored": {
    category: "restore",
    label: "File rolled back",
    template: "{actor} rolled back {name}{folderPhrase} {rollbackPhrase}{notePhrase}",
  },
  "file.deleted": { category: "change", label: "File deleted", template: "{actor} deleted {name}{folderPhrase} from {project}" },
  "file.acl_updated": {
    category: "access",
    label: "File permissions updated",
    template: "{actor} changed permissions on {name}{folderPhrase}",
  },
  "file.acl_viewed": {
    category: "read",
    label: "File permissions viewed",
    template: "{actor} viewed permissions for {name}{folderPhrase}",
  },
  "file.versions_listed": {
    category: "read",
    label: "Versions listed",
    template: "{actor} viewed version history for {name}{folderPhrase}",
  },
  "folder.created": { category: "change", label: "Folder created", template: "{actor} created folder {name} in {project}" },
  "folder.deleted": { category: "change", label: "Folder deleted", template: "{actor} deleted folder {name} in {project}" },
  "folder.acl_updated": {
    category: "access",
    label: "Folder share updated",
    template: "{actor} changed who can access folder {folderPathOrName}",
  },
  "folder.acl_viewed": {
    category: "read",
    label: "Folder share viewed",
    template: "{actor} viewed share settings for folder {folderPathOrName}",
  },
  "folder.visibility_updated": {
    category: "access",
    label: "Folder visibility updated",
    template: "{actor} changed visibility for folder {folderPathOrName}",
  },

  // Platform
  "platform.oversight.project_viewed": {
    category: "admin",
    label: "Oversight project view",
    template: "{actor} (platform admin) viewed project {project} in oversight mode",
  },
  "platform.oversight.file_content_denied": {
    category: "admin",
    label: "Oversight decrypt denied",
    template: "{actor} (platform admin) was blocked from opening file contents",
  },
  "platform.ops_denied": {
    category: "admin",
    label: "Ops denied",
    template: "{actor} was denied a platform operation",
  },
  "admin.console_opened": {
    category: "admin",
    label: "Admin console opened",
    template: "{actor} opened the Admin console",
  },
  "admin.audit_viewed": {
    category: "admin",
    label: "Platform audit viewed",
    template: "{actor} searched or viewed the platform audit trail",
  },
  "admin.audit_exported": {
    category: "admin",
    label: "Platform audit exported",
    template: "{actor} exported the platform audit trail",
  },
  "admin.backup_created": {
    category: "admin",
    label: "Backup created",
    template: "{actor} created a platform backup{pathPhrase}",
  },
  "admin.backup_restore_staged": {
    category: "restore",
    label: "Backup restore staged",
    template: "{actor} staged restore from backup {backupId} (service restart applies it)",
  },
  "admin.retention_run": {
    category: "admin",
    label: "Retention purge run",
    template: "{actor} ran retention purge (deleted {deleted} file(s))",
  },
  "file.retention_purged": {
    category: "admin",
    label: "File purged by retention",
    template: "System purged expired file {name} past retention",
  },
  "admin.catalog_opened": {
    category: "admin",
    label: "Estate catalog opened",
    template: "{actor} opened the platform estate catalog (metadata only)",
  },
  "admin.catalog_org_viewed": {
    category: "admin",
    label: "Catalog org viewed",
    template: "{actor} viewed organization {org} in the estate catalog",
  },
  "admin.catalog_project_viewed": {
    category: "admin",
    label: "Catalog project viewed",
    template: "{actor} viewed project {project} in the estate catalog (folders listing)",
  },
  "admin.catalog_folder_viewed": {
    category: "admin",
    label: "Catalog folder viewed",
    template: "{actor} viewed folder {name} in the estate catalog (file names only — no contents)",
  },
};

export const AUDIT_OUTCOMES = {
  success: { id: "success", label: "Succeeded" },
  failure: { id: "failure", label: "Failed" },
};

export function resolveAuditOutcome(event) {
  const raw = event?.outcome || event?.meta?.outcome;
  if (raw === "failure" || raw === "success") return raw;
  if (/_failed$|_denied$/.test(String(event?.action || ""))) return "failure";
  return "success";
}

function pick(meta, key, fallback = "") {
  if (!meta || meta[key] == null || meta[key] === "") return fallback;
  return String(meta[key]);
}

function fill(template, vars) {
  return template.replace(/\{(\w+)\}/g, (_, key) => (vars[key] != null && vars[key] !== "" ? vars[key] : ""));
}

const JOIN_FAIL_REASONS = {
  invalid_invite: ": invalid invite code",
  not_in_org: ": not a member of the organization",
  missing_code: ": invite code missing",
  forbidden: ": not allowed",
};

/**
 * @returns {{ category: string, categoryLabel: string, actionLabel: string, summary: string, outcome: string, outcomeLabel: string }}
 */
export function explainAuditEvent(event) {
  const def = AUDIT_ACTIONS[event.action] || {
    category: "change",
    label: event.action || "Unknown",
    template: "{actor} performed {action}",
  };
  const meta = event.meta || {};
  const actor = event.actor_name || event.actor_email || "Someone";
  const org = event.org_name || pick(meta, "orgName") || "an organization";
  const project = event.project_name || pick(meta, "projectName") || "a project";
  const name =
    event.target_name ||
    pick(meta, "name") ||
    (event.target_type === "file"
      ? "a file"
      : event.target_type === "folder"
        ? "a folder"
        : event.target_type === "user"
          ? event.target_user_name || event.target_user_email || "a user"
          : "an item");
  const folderPath = event.folder_path || pick(meta, "folderPath") || pick(meta, "folderName") || "";
  const folderPhrase = folderPath ? ` in ${folderPath}` : "";
  const folderPathOrName = folderPath || name;
  const version = meta.version != null ? meta.version : meta.newVersion;
  const versionPhrase = version != null ? ` (v${version})` : "";
  const note = pick(meta, "note");
  const notePhrase = note ? ` — note: “${note}”` : "";
  const pathPhrase = meta.path ? ` (${meta.path})` : "";
  const email = meta.email ? ` for ${meta.email}` : "";
  const member =
    pick(meta, "memberName") ||
    pick(meta, "email") ||
    event.target_user_name ||
    event.target_user_email ||
    "a user";
  const targetUser =
    pick(meta, "email") ||
    pick(meta, "name") ||
    event.target_user_name ||
    event.target_user_email ||
    "a user";
  const role = pick(meta, "role") || pick(meta, "memberRole") || "member";
  const reasonPhrase =
    JOIN_FAIL_REASONS[meta.reason] ||
    (meta.message ? `: ${meta.message}` : meta.reason ? `: ${meta.reason}` : "");
  const alreadyMemberPhrase = meta.alreadyMember ? " (already a member)" : "";
  const restoredFrom = pick(meta, "restoredFrom");
  const newVersion = pick(meta, "newVersion");
  let previousCurrent = pick(meta, "previousCurrent");
  if (!previousCurrent && newVersion !== "" && !Number.isNaN(Number(newVersion))) {
    previousCurrent = String(Number(newVersion) - 1);
  }
  let rollbackPhrase = "a prior version";
  if (previousCurrent && restoredFrom && newVersion) {
    rollbackPhrase = `from current v${previousCurrent} to v${restoredFrom} (history kept — saved as new v${newVersion})`;
  } else if (restoredFrom && newVersion) {
    rollbackPhrase = `to the contents of v${restoredFrom} (history kept — saved as new v${newVersion})`;
  }

  const summary = fill(def.template, {
    actor,
    org,
    project,
    name,
    folderPhrase,
    folderPathOrName,
    action: event.action,
    versionPhrase,
    restoredFrom,
    newVersion,
    previousCurrent,
    rollbackPhrase,
    notePhrase,
    pathPhrase,
    email,
    member,
    targetUser,
    role,
    reasonPhrase,
    alreadyMemberPhrase,
    target: name || event.target_id || "",
  })
    .replace(/\s{2,}/g, " ")
    .trim();

  const cat = AUDIT_CATEGORIES[def.category] || AUDIT_CATEGORIES.change;
  const outcome = resolveAuditOutcome(event);
  return {
    category: cat.id,
    categoryLabel: cat.label,
    actionLabel: def.label,
    summary,
    outcome,
    outcomeLabel: AUDIT_OUTCOMES[outcome]?.label || outcome,
  };
}

export function categorizeAction(action) {
  return AUDIT_ACTIONS[action]?.category || "change";
}

export function listActionCatalog() {
  return Object.entries(AUDIT_ACTIONS).map(([action, def]) => ({
    action,
    label: def.label,
    category: def.category,
    categoryLabel: AUDIT_CATEGORIES[def.category]?.label || def.category,
  }));
}
