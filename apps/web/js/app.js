import { detectLanguage, highlightCode } from "./lang.js";
import { createCodeEditor, applyDiagnostics } from "./codeEditor.js";

const $ = (id) => document.getElementById(id);
const root = $("root");

const state = {
  user: null,
  oidcEnabled: false,
  orgs: [],
  projects: [],
  org: null,
  orgMembers: [],
  project: null,
  folders: [],
  members: [],
  folderId: null,
  files: [],
  oversight: false,
  view: "home", // home | project | admin
  poll: null,
  memberSearch: "",
  selectedFileIds: [],
  selectedFolderIds: [],
  selectedOrgMemberIds: [],
  selectedProjectMemberIds: [],
  activeEditorDispose: null,
  diagTimer: null,
  adminTab: "users", // users | audit | catalog
  adminConsoleLogged: false,
  auditFilterOptions: null,
  auditLiveFp: "",
  auditExpandedIds: new Set(),
  adminUsersFp: "",
  catalog: {
    orgId: null,
    projectId: null,
    folderId: null,
    orgs: [],
    projects: [],
    folders: [],
    files: [],
    org: null,
    project: null,
    folder: null,
    notice: "",
  },
  auditFilters: {
    q: "",
    action: "",
    category: "",
    outcome: "",
    targetType: "",
    orgId: "",
    projectId: "",
    actorId: "",
    since: "",
    until: "",
  },
};

async function api(path, opts = {}) {
  const res = await fetch(`/api${path}`, {
    credentials: "same-origin",
    headers: opts.body && !(opts.body instanceof FormData) ? { "Content-Type": "application/json", ...(opts.headers || {}) } : opts.headers,
    ...opts,
    body: opts.body && !(opts.body instanceof FormData) ? JSON.stringify(opts.body) : opts.body,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  if (!res.ok) throw new Error(data?.error || res.statusText);
  return data;
}

function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) {
    t = document.createElement("div");
    t.className = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  clearTimeout(toast._tm);
  toast._tm = setTimeout(() => t.remove(), 3500);
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmtSize(n) {
  const num = Number(n) || 0;
  if (num < 1024) return num + " B";
  if (num < 1048576) return (num / 1024).toFixed(1) + " KB";
  return (num / 1048576).toFixed(2) + " MB";
}

function fileLanguageLabel(f) {
  if (f?.language) {
    const map = {
      javascript: "JavaScript",
      typescript: "TypeScript",
      csharp: "C#",
      cpp: "C++",
      powershell: "PowerShell",
      markdown: "Markdown",
      php: "PHP",
      plaintext: "Text",
    };
    return map[f.language] || f.language.charAt(0).toUpperCase() + f.language.slice(1);
  }
  return detectLanguage(f?.name || "").label;
}

function gate() {
  return `
  <div id="landing">
    <div class="gate">
      <div class="wordmark">Vaultline</div>
      <h1>Projects. Permissions. Audit.</h1>
      <p class="sub">Organization IAM, folder/file ACLs, versioned encrypted files, and exportable audit trails.</p>
      <div class="card">
        <div class="tabs" role="tablist">
          <button type="button" id="tabLogin" aria-selected="true">Sign in</button>
          <button type="button" id="tabRegister" aria-selected="false">Register</button>
        </div>
        <div id="paneLogin">
          <label>Email</label><input class="field" id="lEmail" type="email" autocomplete="username">
          <label>Password</label><input class="field" id="lPass" type="password" autocomplete="current-password">
          <button class="btn btn-primary" type="button" id="btnLogin">Sign in</button>
          <button class="btn btn-quiet hidden" type="button" id="btnOidc" style="width:100%;margin-top:10px">Login with SSO</button>
        </div>
        <div id="paneRegister" class="hidden">
          <label>Name</label><input class="field" id="rName" maxlength="48">
          <label>Email</label><input class="field" id="rEmail" type="email" autocomplete="username">
          <label>Password (min 10)</label><input class="field" id="rPass" type="password" autocomplete="new-password">
          <button class="btn btn-primary" type="button" id="btnRegister">Create account</button>
        </div>
        <p class="form-err" id="gateErr"></p>
      </div>
      <p class="fine">New accounts cannot create orgs until a platform admin grants that. SSO via OIDC_* when ready.</p>
    </div>
  </div>`;
}

function orgRoleLabel(role) {
  if (role === "owner") return "Org Owner";
  if (role === "admin") return "Org Admin";
  if (role === "member") return "Org Member";
  return "";
}

function shell(mainHtml) {
  const canCreate = !!state.user.canCreateOrg || !!state.user.isPlatformAdmin;
  const roleBit = state.org?.my_role ? orgRoleLabel(state.org.my_role) : "";
  return `
  <div id="app">
    <aside>
      <div>
        <div class="room-name">Vaultline</div>
        <div class="you">${esc(state.user.name)}</div>
        <div class="you-email">${esc(state.user.email)}${roleBit ? ` · ${esc(roleBit)}` : ""}</div>
      </div>
      <nav>
        <div class="side-h">Organizations</div>
        <div id="orgList"></div>
        <div class="side-h" style="margin-top:16px">Projects <button type="button" id="btnNewProject">+ New</button></div>
        <div id="projectList"></div>
      </nav>
      <div class="foot">
        <button class="btn btn-quiet" type="button" id="btnJoinInvite">Join with invite</button>
        ${canCreate ? '<button class="btn btn-quiet" type="button" id="btnNewOrg">New organization</button>' : ""}
        ${state.user.isPlatformAdmin ? '<button class="btn btn-quiet" type="button" id="btnAdmin">Admin console</button>' : ""}
        <button class="btn btn-quiet btn-danger" type="button" id="btnLogout">Sign out</button>
      </div>
    </aside>
    <main id="main">${mainHtml}</main>
  </div>
  <div id="modalRoot"></div>`;
}

function projectRoleLabel(role) {
  if (role === "admin") return "Project Owner";
  if (role === "member") return "Project member";
  return role || "";
}

function canManageProject() {
  return state.project?.my_role === "admin";
}

function renderOrgList() {
  const el = $("orgList");
  if (!el) return;
  el.innerHTML =
    state.orgs
      .map(
        (o) => `<button class="folder-item" type="button" data-org="${o.id}" aria-current="${state.org?.id === o.id}">
      ${esc(o.name)} <span class="badge">${esc(o.my_role)}${o.oversight ? " · view" : ""}</span></button>`
      )
      .join("") || `<p style="font-size:13px;color:var(--ink-soft)">No orgs yet.</p>`;
}

function renderProjectList() {
  const el = $("projectList");
  if (!el) return;
  const list = state.org ? state.projects.filter((p) => p.org_id === state.org.id) : state.projects;
  el.innerHTML =
    list
      .map(
        (p) => `<button class="folder-item" type="button" data-project="${p.id}" aria-current="${state.project?.id === p.id}">
      ${esc(p.name)} <span class="badge">${esc(projectRoleLabel(p.my_role) || p.my_role)}${p.oversight ? " · view" : ""}</span></button>`
      )
      .join("") || `<p style="font-size:13px;color:var(--ink-soft)">No projects yet.</p>`;
}

function canManageOrg() {
  const r = state.org?.my_role;
  return r === "owner" || r === "admin";
}

function memberMatches(m, q) {
  if (!q) return true;
  return `${m.name} ${m.email} ${m.role}`.toLowerCase().includes(q);
}

function orgMemberResultsHtml() {
  const q = (state.memberSearch || "").trim().toLowerCase();
  const filtered = (state.orgMembers || []).filter((m) => memberMatches(m, q));
  if (!filtered.length) {
    return `<div class="empty"><h3>No matches</h3><p>Try another search.</p></div>`;
  }
  return filtered
    .map((m) => {
      const checked = state.selectedOrgMemberIds.includes(m.id);
      const selectable = canManageOrg() && m.role !== "owner" && m.id !== state.user.id;
      return `<div class="file-row">
      ${selectable ? `<input type="checkbox" data-org-check="${m.id}" ${checked ? "checked" : ""}>` : `<span style="width:16px"></span>`}
      <span class="fname">${esc(m.name)} · ${esc(m.email)}</span>
      <span class="fmeta">${esc(m.role)}</span>
      <span class="row-actions">
        ${
          canManageOrg() && m.id !== state.user.id
            ? `<button class="btn btn-quiet btn-danger" type="button" data-rm-org="${m.id}">Remove</button>`
            : ""
        }
      </span></div>`;
    })
    .join("");
}

function projectMemberResultsHtml() {
  const manage = canManageProject() || canManageOrg();
  const q = (state.memberSearch || "").trim().toLowerCase();
  const filtered = (state.members || []).filter((m) => memberMatches(m, q));
  if (!filtered.length) {
    return `<p style="font-size:13px;color:var(--ink-soft)">No matches.</p>`;
  }
  return filtered
    .map((m) => {
      const checked = state.selectedProjectMemberIds.includes(m.id);
      const selectable = manage && m.id !== state.user.id;
      return `<div class="member">
      ${selectable ? `<input type="checkbox" data-proj-check="${m.id}" ${checked ? "checked" : ""}>` : ""}
      <span class="avatar">${esc(m.name.slice(0, 2).toUpperCase())}</span>
      <span class="member-meta"><span class="member-name">${esc(m.name)}</span>
      <span class="tag">${esc(m.role)}</span></span>
      ${
        manage && m.id !== state.user.id
          ? `<button class="icon-btn danger" type="button" title="Remove" data-rm-project="${m.id}">✕</button>`
          : ""
      }
      </div>`;
    })
    .join("");
}

function refreshOrgMemberResults() {
  const el = $("orgMemberResults");
  if (!el) return;
  el.innerHTML = orgMemberResultsHtml();
  document.querySelectorAll("[data-org-check]").forEach((c) => {
    c.onchange = () => {
      const id = c.dataset.orgCheck;
      if (c.checked) {
        if (!state.selectedOrgMemberIds.includes(id)) state.selectedOrgMemberIds.push(id);
      } else {
        state.selectedOrgMemberIds = state.selectedOrgMemberIds.filter((x) => x !== id);
      }
    };
  });
  document.querySelectorAll("[data-rm-org]").forEach((b) => {
    b.onclick = async () => {
      if (!confirm("Remove this member from the organization (and its projects)?")) return;
      try {
        await api(`/orgs/${state.org.id}/members/${b.dataset.rmOrg}`, { method: "DELETE" });
        state.memberSearch = "";
        state.selectedOrgMemberIds = state.selectedOrgMemberIds.filter((id) => id !== b.dataset.rmOrg);
        const search = $("orgMemberSearch");
        if (search) search.value = "";
        await loadOrgsProjects();
        paint();
        toast("Member removed from organization.");
      } catch (e) {
        toast(e.message);
      }
    };
  });
}

function refreshProjectMemberResults() {
  const el = $("projectMemberResults");
  if (!el) return;
  el.innerHTML = projectMemberResultsHtml();
  wireMemberListControls();
}

function syncFileBulkButtons() {
  const n = state.selectedFileIds.length;
  for (const id of ["btnBulkFileAcl", "btnResetFileAcl", "btnBulkDeleteFiles"]) {
    const btn = $(id);
    if (!btn) continue;
    btn.disabled = !n;
    if (id === "btnBulkFileAcl") {
      btn.textContent = n ? `Mass file permissions (${n})` : "Mass file permissions";
    }
  }
}

function homeMain() {
  if (!state.org) {
    if (state.user?.isPlatformAdmin) {
      return `<div class="main-head"><div><h2>Platform admin</h2>
        <p class="meta">You only see orgs you belong to in the work sidebar. Use Admin → Catalog for estate metadata, and Audit for activity across the platform.</p></div></div>
        <div class="empty"><h3>No organization memberships</h3><p>Open Admin console for Catalog and Audit, or use a normal membership to create/join orgs.</p></div>`;
    }
    return `<div class="main-head"><div><h2>Welcome</h2>
      <p class="meta">Create an organization, add colleagues, then create projects and share folders.</p></div></div>
      <div class="empty"><h3>Create or select an organization</h3><p>Use the sidebar to get started.</p></div>`;
  }
  return `<div class="main-head"><div><h2>${esc(state.org.name)}</h2>
    <p class="meta">Your org role: ${esc(orgRoleLabel(state.org.my_role) || state.org.my_role)}</p></div>
    <div class="head-actions">
      ${canManageOrg() ? '<button class="btn btn-quiet" type="button" id="btnAddOrgMember">Add members</button>' : ""}
      ${canManageOrg() ? '<button class="btn btn-quiet" type="button" id="btnOrgBulkManage">Manage selected</button>' : ""}
    </div></div>
    <div class="member-toolbar">
      <input class="field member-search" id="orgMemberSearch" type="search" autocomplete="off" placeholder="Search members…" value="">
    </div>
    <h3 style="margin:8px 0 12px">Organization members</h3>
    <div id="orgMemberResults"></div>
    <p class="fine" style="margin-top:16px">Add someone to the org first, then share a project invite code — or use <strong>Add member</strong> on a project (org owners/admins can add to org + project in one step).</p>`;
}

function projectMain() {
  const p = state.project;
  if (!p) return homeMain();
  const folder = state.folders.find((f) => f.id === state.folderId);
  const manage = canManageProject();
  const canBulkFolders = state.folders.some((f) => f.canManageAcl);
  return `
  <div class="main-head">
    <div><h2>${esc(p.name)}</h2>
      <p class="meta">${esc(p.org_name || "")} · your role: ${esc(projectRoleLabel(p.my_role) || p.my_role || "")}</p></div>
    <div class="head-actions">
      ${manage ? '<button class="btn btn-quiet" type="button" id="btnAddMember">Add member</button>' : ""}
      ${manage || canManageOrg() ? '<button class="btn btn-quiet" type="button" id="btnMassProjectMembers">Mass project members</button>' : ""}
      ${manage ? '<button class="btn btn-quiet" type="button" id="btnRotateInvite">Invite code</button>' : ""}
      ${canBulkFolders ? '<button class="btn btn-quiet" type="button" id="btnBulkFolderAcl">Mass share folders</button>' : ""}
      ${canBulkFolders ? '<button class="btn btn-quiet" type="button" id="btnCopyFolderAcl">Copy folder share</button>' : ""}
      ${manage || canManageOrg() ? '<button class="btn btn-quiet" type="button" id="btnOffboardFolders">Offboard from folders</button>' : ""}
      ${manage || canManageOrg() ? '<button class="btn btn-quiet" type="button" id="btnProjectAudit">Audit</button>' : ""}
    </div>
  </div>
  <div style="display:grid;grid-template-columns:240px 1fr;gap:18px;min-height:60vh">
    <div>
      <div class="side-h">Folders <button type="button" id="btnNewFolder">+ New</button></div>
      <div id="folderList"></div>
      <div class="side-h" style="margin-top:18px">Members
        ${manage || canManageOrg() ? '<button type="button" id="btnProjectBulkManage">Manage selected</button>' : ""}
      </div>
      <input class="field member-search" id="projectMemberSearch" type="search" autocomplete="off" placeholder="Search members…" value="">
      <div id="projectMemberResults"></div>
    </div>
    <div id="folderPanel">${folderPanel(folder)}</div>
  </div>`;
}

function folderPanel(folder) {
  if (!folder) {
    return `<div class="empty"><h3>Pick a folder</h3><p>Create a shared folder to upload configs.</p></div>`;
  }
  const canUpload = folder.access === "edit";
  const folderLabel = folder.access === "edit" ? "Can edit · uploads on" : folder.access === "read" ? "Read only · no uploads" : esc(folder.access);
  const crumb = (folder.path || [folder.name]).map((n) => esc(n)).join(" / ");
  return `
  <div class="main-head">
    <div><h2>${folder.number}. ${esc(folder.name)}</h2>
      <p class="meta">${crumb} · ${state.files.length} file(s) · folder: ${folderLabel}${
        folder.childCount ? ` · ${folder.childCount} subfolder(s)` : ""
      }</p></div>
    <div class="head-actions">
      ${folder.canManageAcl ? '<button class="btn btn-quiet" type="button" id="btnFolderAcl">Share folder</button>' : ""}
      ${
        folder.canManageAcl && state.files.length
          ? `<button class="btn btn-quiet" type="button" id="btnBulkFileAcl" ${state.selectedFileIds.length ? "" : "disabled"}>Mass file permissions${
              state.selectedFileIds.length ? ` (${state.selectedFileIds.length})` : ""
            }</button>
            <button class="btn btn-quiet" type="button" id="btnResetFileAcl" ${state.selectedFileIds.length ? "" : "disabled"}>Reset to folder ACL</button>
            <button class="btn btn-quiet btn-danger" type="button" id="btnBulkDeleteFiles" ${state.selectedFileIds.length ? "" : "disabled"}>Delete selected</button>`
          : ""
      }
      ${folder.created_by === state.user.id ? '<button class="btn btn-quiet btn-danger" type="button" id="btnDelFolder">Delete folder</button>' : ""}
    </div>
  </div>
  ${
    canUpload
      ? `<div class="dropzone" id="dropzone"><strong>Drag & drop files</strong><div class="fine">or <button type="button" id="btnBrowse">browse</button> · up to 50 MB</div>
      <input type="file" id="filePick" multiple class="hidden"></div>`
      : `<p class="fine" style="margin:0 0 12px">You can view files here, but uploading needs <strong>Can edit</strong> on this folder (Share folder) — file-level Read only does not remove upload rights.</p>`
  }
  <div id="fileList"></div>`;
}

function fileDiagnostics(f) {
  if (Array.isArray(f?.diagnostics)) return f.diagnostics;
  if (typeof f?.diagnostics_json === "string") {
    try {
      const parsed = JSON.parse(f.diagnostics_json);
      return Array.isArray(parsed?.diagnostics) ? parsed.diagnostics : [];
    } catch {
      return [];
    }
  }
  return [];
}

function renderFoldersFiles() {
  const fl = $("folderList");
  if (fl) {
    const showFolderCheck = state.folders.some((f) => f.canManageAcl);
    const byParent = new Map();
    for (const f of state.folders) {
      const pid = f.parent_id || "";
      if (!byParent.has(pid)) byParent.set(pid, []);
      byParent.get(pid).push(f);
    }
    const ordered = [];
    const walk = (parentKey, depth) => {
      const kids = byParent.get(parentKey) || [];
      for (const f of kids) {
        ordered.push({ ...f, depth });
        walk(f.id, depth + 1);
      }
    };
    walk("", 0);
    for (const f of state.folders) {
      if (!ordered.find((x) => x.id === f.id)) ordered.push({ ...f, depth: f.depth || 0 });
    }
    fl.innerHTML =
      ordered
        .map((f) => {
          const checked = state.selectedFolderIds.includes(f.id);
          const pad = Math.min(f.depth || 0, 8) * 12;
          return `<div class="folder-item-row" style="display:flex;align-items:center;gap:6px;padding-left:${pad}px">
          ${
            showFolderCheck && f.canManageAcl
              ? `<input type="checkbox" data-folder-check="${f.id}" ${checked ? "checked" : ""} title="Select for mass share">`
              : ""
          }
          <button class="folder-item" type="button" data-folder="${f.id}" aria-current="${f.id === state.folderId}" style="flex:1">
            <span class="item-num">${f.number}.</span> ${esc(f.name)}${
              f.childCount ? ` <span class="fmeta">(${f.childCount})</span>` : ""
            }
            <span class="badge ${f.access}">${esc(f.access)}</span>
          </button>
        </div>`;
        })
        .join("") || `<p style="font-size:13px;color:var(--ink-soft)">No folders.</p>`;
  }
  try {
    refreshProjectMemberResults();
  } catch (e) {
    console.error("member list render failed", e);
  }
  const list = $("fileList");
  if (!list) return;
  if (!state.files.length) {
    state.selectedFileIds = [];
    list.innerHTML = `<div class="empty"><h3>Empty</h3><p>Upload configs to get started.</p></div>`;
    return;
  }
  const folder = state.folders.find((f) => f.id === state.folderId);
  const showFileCheck = !!folder?.canManageAcl;
  try {
    list.innerHTML = state.files
      .map((f) => {
        const canEdit = f.access === "edit";
        const checked = state.selectedFileIds.includes(f.id);
        const langLabel = fileLanguageLabel(f);
        const diags = fileDiagnostics(f);
        const errCount = diags.filter((d) => d && d.severity === "error").length;
        const warnCount = diags.filter((d) => d && d.severity === "warning").length;
        const diagHint =
          errCount || warnCount
            ? ` · ${errCount ? errCount + " err" : ""}${errCount && warnCount ? ", " : ""}${warnCount ? warnCount + " warn" : ""}`
            : "";
        return `<div class="file-row${showFileCheck ? " has-check" : ""}">
        ${
          showFileCheck
            ? `<input type="checkbox" data-file-check="${f.id}" ${checked ? "checked" : ""} title="Select for mass permissions">`
            : ""
        }
        <span class="item-num">${f.number ?? ""}.</span>
        <div class="file-main">
          <button class="fname" type="button" data-open="${f.id}">${esc(f.name)}</button>
          <span class="lang-tag" title="${esc(langLabel)}">${esc(langLabel)}</span>
          ${f.isCode ? `<span class="code-badge" title="Detected as code">code</span>` : ""}
        </div>
        <span class="fmeta">${fmtSize(f.size || 0)} · v${f.current_version || 1} · ${esc(
          f.createdByName || "unknown"
        )}${canEdit ? "" : " · this file: read-only"}${f.canDelete ? " · can delete" : ""}${diagHint}</span>
        <span class="row-actions">
          ${canEdit ? `<button class="icon-btn" type="button" title="Edit" data-edit="${f.id}">✎</button>` : ""}
          ${f.canManageAcl ? `<button class="icon-btn" type="button" title="Permissions" data-facl="${f.id}">⚙</button>` : ""}
          <button class="icon-btn" type="button" title="Versions" data-vers="${f.id}">◉</button>
          ${
            f.canDelete
              ? `<button class="btn btn-quiet btn-danger" type="button" style="width:auto;margin:0;padding:6px 10px" data-delfile="${f.id}">Delete</button>`
              : ""
          }
        </span>
      </div>`;
      })
      .join("");
  } catch (e) {
    console.error("file list render failed", e, state.files);
    list.innerHTML = `<div class="empty"><h3>Couldn’t render files</h3><p>${esc(e.message)}. Hard-refresh and try again.</p></div>`;
  }
}

function formatGrantLine(g) {
  if (!g || typeof g !== "object") return String(g);
  const who = g.name || g.email || g.userId || "someone";
  const access = g.access || g.fileAccess || g.folderAccess || "access";
  const del = g.canDelete ? " + delete" : "";
  return `${who}: ${access}${del}`;
}

function formatAuditDetailHtml(e) {
  const meta = e.meta || {};
  const rows = [
    ["What happened", e.summary || e.actionLabel || e.action],
    ["Result", e.outcomeLabel || (e.outcome === "failure" ? "Failed" : "Succeeded")],
    ["Kind", e.categoryLabel || e.category],
    ["Action", e.actionLabel ? `${e.actionLabel} (${e.action})` : e.action],
    ["Who", e.actor_name || e.actor_email ? `${e.actor_name || ""}${e.actor_email ? ` <${e.actor_email}>` : ""}`.trim() : "—"],
    ["Organization", e.org_name || "—"],
    ["Project", e.project_name || "—"],
  ];
  if (e.target_type || e.target_name) {
    const type = e.target_type || "item";
    rows.push(["Target", e.target_name ? `${type}: ${e.target_name}` : type]);
  }
  if (e.folder_path || meta.folderPath || meta.folderName) {
    rows.push(["Folder", e.folder_path || meta.folderPath || meta.folderName]);
  }
  if (meta.reason) rows.push(["Failure reason", meta.message || meta.reason]);
  if (meta.inviteTried || meta.invitePrefix) rows.push(["Invite tried", meta.inviteTried || meta.invitePrefix]);
  if (meta.version != null) rows.push(["Version", `v${meta.version}`]);
  if (meta.previousCurrent != null) rows.push(["Was current", `v${meta.previousCurrent}`]);
  if (meta.restoredFrom != null) rows.push(["Rolled back to contents of", `v${meta.restoredFrom}`]);
  if (meta.newVersion != null) rows.push(["Saved as new version", `v${meta.newVersion}`]);
  if (meta.note) rows.push(["Note", meta.note]);
  if (meta.language) rows.push(["Language", meta.language]);
  if (meta.size != null) rows.push(["Size", `${meta.size} bytes`]);
  if (meta.inherit != null) rows.push(["Permissions mode", meta.inherit ? "Inherit from folder" : "Custom file ACL"]);
  if (Array.isArray(meta.grants) && meta.grants.length) {
    rows.push(["Permissions set", meta.grants.map(formatGrantLine).join("; ")]);
  } else if (meta.grants === null && meta.inherit) {
    rows.push(["Permissions set", "Cleared — inherit folder access"]);
  }
  if (meta.everyoneAccess) rows.push(["Everyone access", meta.everyoneAccess]);
  if (meta.role || meta.memberRole) rows.push(["Role", meta.role || meta.memberRole]);
  if (meta.email && !String(rows.find((r) => r[0] === "Who")?.[1] || "").includes(meta.email)) {
    rows.push(["Related user", meta.memberName ? `${meta.memberName} <${meta.email}>` : meta.email]);
  }
  if (e.target_user_email || e.target_user_name) {
    rows.push([
      "Affected user",
      `${e.target_user_name || ""}${e.target_user_email ? ` <${e.target_user_email}>` : ""}`.trim(),
    ]);
  }
  if (meta.path) rows.push(["Path", meta.path]);
  if (e.ip) rows.push(["IP", e.ip]);
  if (e.user_agent) rows.push(["Browser", e.user_agent]);
  rows.push(["When", new Date(e.ts).toLocaleString()]);

  const body = rows
    .map(
      ([k, v]) =>
        `<div class="audit-kv"><span class="audit-k">${esc(k)}</span><span class="audit-v">${esc(String(v))}</span></div>`
    )
    .join("");

  return `${body}<p class="fine" style="margin:10px 0 0">IDs are kept for support only — names above are what matters.</p>`;
}

function renderAuditEventRows(events, expandedIds = state.auditExpandedIds) {
  if (!events || !events.length) return `<p class="fine">No events match these filters.</p>`;
  return events
    .map((e) => {
      const cat = e.category || "change";
      const outcome = e.outcome || "success";
      const detailId = `audit-${e.id}`;
      const open = expandedIds && expandedIds.has(e.id);
      const targetLabel = e.target_name
        ? e.target_type
          ? `${e.target_type}: ${e.target_name}`
          : e.target_name
        : null;
      const contextBits = [
        e.actionLabel || e.action,
        e.org_name && `Org: ${e.org_name}`,
        e.project_name && `Project: ${e.project_name}`,
        e.folder_path && `Folder: ${e.folder_path}`,
        targetLabel,
        e.actor_email && `By: ${e.actor_name || e.actor_email} <${e.actor_email}>`,
        e.ip && `IP: ${e.ip}`,
      ].filter(Boolean);
      return `<div class="act-row audit-event" data-audit-id="${esc(e.id)}">
      <div class="audit-event-top">
        <span class="audit-badges">
          <span class="audit-cat audit-cat-${esc(cat)}">${esc(e.categoryLabel || cat)}</span>
          <span class="audit-outcome audit-outcome-${esc(outcome)}">${esc(e.outcomeLabel || (outcome === "failure" ? "Failed" : "Succeeded"))}</span>
        </span>
        <span class="when">${new Date(e.ts).toLocaleString()}</span>
      </div>
      <div class="audit-summary">${esc(e.summary || e.action)}</div>
      <div class="fmeta">${contextBits.map(esc).join(" · ")}</div>
      <button class="btn btn-quiet audit-toggle" type="button" data-audit-toggle="${esc(detailId)}" data-audit-event="${esc(e.id)}" style="width:auto;margin:6px 0 0;font-size:12px">${open ? "Hide details" : "Details"}</button>
      ${
        e.org_id || e.project_id || (e.target_type === "folder" && e.target_id)
          ? `<button class="btn btn-quiet" type="button" data-catalog-jump-org="${esc(e.org_id || "")}" data-catalog-jump-project="${esc(e.project_id || "")}" data-catalog-jump-folder="${esc(e.target_type === "folder" ? e.target_id || "" : "")}" style="width:auto;margin:6px 0 0;font-size:12px">Open in catalog</button>`
          : ""
      }
      <div class="audit-json${open ? "" : " hidden"}" id="${esc(detailId)}" data-event-id="${esc(e.id)}">${formatAuditDetailHtml(e)}</div>
    </div>`;
    })
    .join("");
}

function wireAuditToggles() {
  document.querySelectorAll("[data-audit-toggle]").forEach((b) => {
    b.onclick = () => {
      const el = $(b.dataset.auditToggle);
      if (!el) return;
      el.classList.toggle("hidden");
      const open = !el.classList.contains("hidden");
      b.textContent = open ? "Hide details" : "Details";
      const id = b.dataset.auditEvent;
      if (id) {
        if (open) state.auditExpandedIds.add(id);
        else state.auditExpandedIds.delete(id);
      }
    };
  });
  document.querySelectorAll("[data-catalog-jump-org]").forEach((b) => {
    b.onclick = async () => {
      try {
        await openCatalogAt({
          orgId: b.dataset.catalogJumpOrg || null,
          projectId: b.dataset.catalogJumpProject || null,
          folderId: b.dataset.catalogJumpFolder || null,
        });
      } catch (e) {
        toast(e.message);
      }
    };
  });
}

function auditEventsFingerprint(events) {
  return (events || []).map((e) => `${e.id}:${e.ts}:${e.action}`).join("|");
}

async function refreshAdminAuditLive() {
  if (state.view !== "admin" || state.adminTab !== "audit") return;
  try {
    const events = (await api(`/auth/admin/audit?${auditQueryParams()}`)).events;
    const fp = auditEventsFingerprint(events);
    if (fp === state.auditLiveFp) return;
    const had = state.auditLiveFp;
    state.auditLiveFp = fp;
    const list = document.querySelector(".audit-list");
    const countEl = document.querySelector(".audit-live-count");
    if (!list) {
      await paint();
      return;
    }
    list.innerHTML = renderAuditEventRows(events);
    if (countEl) {
      countEl.textContent = `${events.length} event${events.length === 1 ? "" : "s"} (cap 200) · live`;
    }
    wireAuditToggles();
    if (had && events[0] && !had.includes(events[0].id)) {
      const first = list.querySelector(".audit-event");
      first?.classList.add("audit-event-new");
      setTimeout(() => first?.classList.remove("audit-event-new"), 1800);
    }
  } catch {
    /* ignore transient poll errors */
  }
}

async function refreshUserFlagsLive() {
  if (!state.user) return false;
  try {
    const me = await api("/auth/me");
    if (!me?.user) return false;
    const before = `${!!state.user.canCreateOrg}:${!!state.user.isPlatformAdmin}:${state.user.status}`;
    const after = `${!!me.user.canCreateOrg}:${!!me.user.isPlatformAdmin}:${me.user.status}`;
    const gainedOrgCreate = !state.user.canCreateOrg && !!me.user.canCreateOrg && !me.user.isPlatformAdmin;
    const lostOrgCreate = !!state.user.canCreateOrg && !me.user.canCreateOrg && !me.user.isPlatformAdmin;
    state.user = me.user;
    if (before === after) return false;
    paint();
    if (gainedOrgCreate) toast("You can create organizations now.");
    else if (lostOrgCreate) toast("Organization create permission was revoked.");
    return true;
  } catch {
    return false;
  }
}

async function liveTick() {
  if (await refreshUserFlagsLive()) return;
  if (state.view === "admin" && state.adminTab === "audit") {
    await refreshAdminAuditLive();
    return;
  }
  if (state.view === "admin" && state.adminTab === "users") {
    try {
      const users = (await api("/auth/admin/users")).users;
      const fp = users.map((u) => `${u.id}:${u.status}:${!!u.canCreateOrg}:${!!u.isPlatformAdmin}`).join("|");
      if (fp !== state.adminUsersFp) {
        state.adminUsersFp = fp;
        paint();
      }
    } catch {
      /* ignore */
    }
    return;
  }
  await syncSilent();
}

function adminMain(users, events, filterOpts) {
  const f = state.auditFilters;
  const opts = filterOpts || { categories: [], actions: [], orgs: [], projects: [], actors: [], targetTypes: [] };
  const projectsForOrg = f.orgId
    ? (opts.projects || []).filter((p) => p.org_id === f.orgId)
    : opts.projects || [];

  const usersPane = `
  <div class="admin-pane">
    <p class="fine" style="margin:0 0 12px">Disable accounts, grant org-create to non-admins, or promote platform admins. Platform admins always may create orgs.</p>
    ${(users || [])
      .map((u) => {
        const orgCreateBtn = u.isPlatformAdmin
          ? `<span class="fmeta">org create: always (platform admin)</span>`
          : u.canCreateOrg
            ? `<button class="btn btn-quiet" type="button" data-revoke-org="${u.id}">Revoke org create</button>`
            : `<button class="btn btn-quiet" type="button" data-grant-org="${u.id}">Allow org create</button>`;
        return `<div class="file-row" style="flex-wrap:wrap"><span class="fname">${esc(u.name)} · ${esc(u.email)}</span>
      <span class="fmeta">${esc(u.status)}${u.isPlatformAdmin ? " · platform admin" : ""}${
          !u.isPlatformAdmin && u.canCreateOrg ? " · can create orgs" : ""
        }</span>
      <span class="row-actions">
        ${orgCreateBtn}
        ${
          u.isPlatformAdmin
            ? u.id !== state.user.id
              ? `<button class="btn btn-quiet" type="button" data-demote="${u.id}">Demote</button>`
              : ""
            : `<button class="btn btn-quiet" type="button" data-promote="${u.id}">Make platform admin</button>`
        }
        ${
          u.status === "active"
            ? `<button class="btn btn-quiet btn-danger" type="button" data-disable="${u.id}">Disable</button>`
            : `<button class="btn btn-quiet" type="button" data-enable="${u.id}">Enable</button>`
        }
      </span></div>`;
      })
      .join("")}
  </div>`;

  const catOpts = (opts.categories || [])
    .map(
      (c) =>
        `<option value="${esc(c.id)}" ${f.category === c.id ? "selected" : ""}>${esc(c.label)}</option>`
    )
    .join("");
  const actionOpts = (opts.actions || [])
    .map(
      (a) =>
        `<option value="${esc(a.action)}" ${f.action === a.action ? "selected" : ""}>${esc(a.label)} (${esc(a.action)})</option>`
    )
    .join("");
  const orgOpts = (opts.orgs || [])
    .map((o) => `<option value="${esc(o.id)}" ${f.orgId === o.id ? "selected" : ""}>${esc(o.name)}</option>`)
    .join("");
  const projectOpts = projectsForOrg
    .map((p) => `<option value="${esc(p.id)}" ${f.projectId === p.id ? "selected" : ""}>${esc(p.name)}</option>`)
    .join("");
  const actorOpts = (opts.actors || [])
    .map(
      (a) =>
        `<option value="${esc(a.id)}" ${f.actorId === a.id ? "selected" : ""}>${esc(a.name || a.email)} · ${esc(a.email)}</option>`
    )
    .join("");
  const targetOpts = (opts.targetTypes || [])
    .map(
      (t) =>
        `<option value="${esc(t.id)}" ${f.targetType === t.id ? "selected" : ""}>${esc(t.label || t.id)}</option>`
    )
    .join("");
  const outcomeOpts = (opts.outcomes || [
    { id: "success", label: "Succeeded" },
    { id: "failure", label: "Failed" },
  ])
    .map(
      (o) =>
        `<option value="${esc(o.id)}" ${f.outcome === o.id ? "selected" : ""}>${esc(o.label)}</option>`
    )
    .join("");

  state.auditLiveFp = auditEventsFingerprint(events);
  const eventRows = renderAuditEventRows(events);

  const auditPane = `
  <div class="admin-pane">
    <div class="audit-filters">
      <input class="field" id="auditQ" placeholder="Search text, email, IP, action…" value="${esc(f.q || "")}">
      <select class="field" id="auditOutcome"><option value="">All results</option>${outcomeOpts}</select>
      <select class="field" id="auditCategory"><option value="">All severities</option>${catOpts}</select>
      <select class="field" id="auditAction"><option value="">All actions</option>${actionOpts}</select>
      <select class="field" id="auditTargetType"><option value="">All target types</option>${targetOpts}</select>
      <select class="field" id="auditOrg"><option value="">All orgs</option>${orgOpts}</select>
      <select class="field" id="auditProject"><option value="">All projects</option>${projectOpts}</select>
      <select class="field" id="auditActor"><option value="">All people</option>${actorOpts}</select>
      <input class="field" id="auditSince" type="date" value="${esc(f.since || "")}" title="From date">
      <input class="field" id="auditUntil" type="date" value="${esc(f.until || "")}" title="To date">
      <div class="audit-filter-actions">
        <button class="btn btn-primary" type="button" id="btnAuditSearch" style="width:auto;margin:0">Apply filters</button>
        <button class="btn btn-quiet" type="button" id="btnAuditClear" style="width:auto;margin:0">Clear</button>
        <button class="btn btn-quiet" type="button" id="btnExportAudit" style="width:auto;margin:0">Export JSON</button>
      </div>
    </div>
    <p class="fine audit-live-count" style="margin:0 0 10px">${(events || []).length} event${(events || []).length === 1 ? "" : "s"} (cap 200) · live</p>
    <div class="audit-list">${eventRows}</div>
  </div>`;

  const catalogPane = renderCatalogPane();

  const body =
    state.adminTab === "users" ? usersPane : state.adminTab === "audit" ? auditPane : catalogPane;

  return `
  <div class="main-head"><div><h2>Admin console</h2><p class="meta">Users, live audit, and estate catalog (metadata only — never file contents). Work sidebar stays membership-only.</p></div>
    <div class="head-actions">
      <button class="btn btn-quiet" type="button" id="btnBackup">Run backup</button>
      <button class="btn btn-quiet" type="button" id="btnBackups">Manage backups</button>
      <button class="btn btn-quiet" type="button" id="btnBackHome">Back</button>
    </div>
  </div>
  <div class="tabs admin-tabs" role="tablist">
    <button type="button" id="tabAdminUsers" aria-selected="${state.adminTab === "users" ? "true" : "false"}">Users</button>
    <button type="button" id="tabAdminAudit" aria-selected="${state.adminTab === "audit" ? "true" : "false"}">Audit</button>
    <button type="button" id="tabAdminCatalog" aria-selected="${state.adminTab === "catalog" ? "true" : "false"}">Catalog</button>
  </div>
  ${body}`;
}

function renderCatalogPane() {
  const c = state.catalog;
  const crumbs = [
    `<button type="button" class="btn btn-quiet catalog-crumb" data-catalog-level="root" style="width:auto;margin:0;padding:4px 8px">All orgs</button>`,
  ];
  if (c.org) {
    crumbs.push(`<span class="fmeta">/</span>
      <button type="button" class="btn btn-quiet catalog-crumb" data-catalog-level="org" data-catalog-org="${esc(c.org.id)}" style="width:auto;margin:0;padding:4px 8px">${esc(c.org.name)}</button>`);
  }
  if (c.project) {
    crumbs.push(`<span class="fmeta">/</span>
      <button type="button" class="btn btn-quiet catalog-crumb" data-catalog-level="project" data-catalog-project="${esc(c.project.id)}" style="width:auto;margin:0;padding:4px 8px">${esc(c.project.name)}</button>`);
  }
  if (c.folder) {
    crumbs.push(`<span class="fmeta">/</span>
      <span class="fname">${esc(c.folder.name)}</span>`);
  }

  let list = "";
  if (!c.orgId) {
    list =
      (c.orgs || [])
        .map(
          (o) => `<button type="button" class="file-row catalog-row" data-catalog-open-org="${esc(o.id)}" style="width:100%;text-align:left">
        <span class="fname">${esc(o.name)}</span>
        <span class="fmeta">${o.project_count || 0} projects · ${o.member_count || 0} members</span>
      </button>`
        )
        .join("") || `<p class="fine">No organizations on the platform.</p>`;
  } else if (!c.projectId) {
    list =
      (c.projects || [])
        .map(
          (p) => `<button type="button" class="file-row catalog-row" data-catalog-open-project="${esc(p.id)}" style="width:100%;text-align:left">
        <span class="fname">${esc(p.name)}</span>
        <span class="fmeta">${p.folder_count || 0} folders · ${p.member_count || 0} members</span>
      </button>`
        )
        .join("") || `<p class="fine">No projects in this organization.</p>`;
  } else if (!c.folderId) {
    list =
      (c.folders || [])
        .map(
          (f) => `<button type="button" class="file-row catalog-row" data-catalog-open-folder="${esc(f.id)}" style="width:100%;text-align:left">
        <span class="fname">${f.number || ""}. ${esc(f.name)}</span>
        <span class="fmeta">${f.file_count || 0} files · ${esc(f.visibility || "")}${f.created_by_name ? ` · by ${esc(f.created_by_name)}` : ""}</span>
      </button>`
        )
        .join("") || `<p class="fine">No folders in this project.</p>`;
  } else {
    list =
      (c.files || [])
        .map(
          (f) => `<div class="file-row catalog-row catalog-file-meta">
        <span class="fname">${esc(f.name)}</span>
        <span class="fmeta">v${f.current_version || 0} · ${fmtSize(f.size)}${f.created_by_name ? ` · by ${esc(f.created_by_name)}` : ""}${f.language ? ` · ${esc(f.language)}` : ""}</span>
        <span class="fmeta" style="flex-basis:100%">Contents sealed — platform catalog cannot open or decrypt this file.</span>
      </div>`
        )
        .join("") || `<p class="fine">No files in this folder.</p>`;
  }

  return `
  <div class="admin-pane">
    <div class="catalog-banner">Platform catalog · metadata only · no file contents · no edit/share/delete</div>
    <div class="catalog-crumbs" style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:12px 0">${crumbs.join("")}</div>
    <div class="catalog-list">${list}</div>
  </div>`;
}

async function loadCatalogRoot() {
  const data = await api("/auth/admin/catalog/orgs");
  state.catalog = {
    ...state.catalog,
    orgId: null,
    projectId: null,
    folderId: null,
    org: null,
    project: null,
    folder: null,
    orgs: data.orgs || [],
    projects: [],
    folders: [],
    files: [],
    notice: data.notice || "",
  };
}

async function loadCatalogOrg(orgId) {
  const data = await api(`/auth/admin/catalog/orgs/${orgId}/projects`);
  state.catalog = {
    ...state.catalog,
    orgId,
    projectId: null,
    folderId: null,
    org: data.org,
    project: null,
    folder: null,
    projects: data.projects || [],
    folders: [],
    files: [],
    notice: data.notice || "",
  };
}

async function loadCatalogProject(projectId) {
  const data = await api(`/auth/admin/catalog/projects/${projectId}/folders`);
  state.catalog = {
    ...state.catalog,
    orgId: data.project.org_id,
    projectId,
    folderId: null,
    org: state.catalog.org || { id: data.project.org_id, name: data.project.org_name },
    project: data.project,
    folder: null,
    folders: data.folders || [],
    files: [],
    notice: data.notice || "",
  };
}

async function loadCatalogFolder(folderId) {
  const data = await api(`/auth/admin/catalog/folders/${folderId}/files`);
  state.catalog = {
    ...state.catalog,
    orgId: data.folder.org_id,
    projectId: data.folder.project_id,
    folderId,
    org: state.catalog.org || { id: data.folder.org_id, name: data.folder.org_name },
    project: state.catalog.project || { id: data.folder.project_id, name: data.folder.project_name },
    folder: data.folder,
    files: data.files || [],
    notice: data.notice || "",
  };
}

async function openCatalogAt({ orgId = null, projectId = null, folderId = null } = {}) {
  state.adminTab = "catalog";
  state.view = "admin";
  if (folderId) {
    await loadCatalogFolder(folderId);
  } else if (projectId) {
    await loadCatalogProject(projectId);
  } else if (orgId) {
    await loadCatalogOrg(orgId);
  } else {
    await loadCatalogRoot();
  }
  await paint();
}


function auditQueryParams({ forExport = false } = {}) {
  const f = state.auditFilters;
  const params = new URLSearchParams();
  params.set("limit", forExport ? "10000" : "200");
  if (f.q) params.set("q", f.q);
  if (f.action) params.set("action", f.action);
  if (f.category) params.set("category", f.category);
  if (f.outcome) params.set("outcome", f.outcome);
  if (f.targetType) params.set("targetType", f.targetType);
  if (f.orgId) params.set("orgId", f.orgId);
  if (f.projectId) params.set("projectId", f.projectId);
  if (f.actorId) params.set("actorId", f.actorId);
  if (f.since) {
    const t = new Date(`${f.since}T00:00:00`).getTime();
    if (!Number.isNaN(t)) params.set("since", String(t));
  }
  if (f.until) {
    const t = new Date(`${f.until}T23:59:59.999`).getTime();
    if (!Number.isNaN(t)) params.set("until", String(t));
  }
  return params.toString();
}

function readAuditFiltersFromDom() {
  state.auditFilters = {
    q: $("auditQ")?.value?.trim() || "",
    action: $("auditAction")?.value || "",
    category: $("auditCategory")?.value || "",
    outcome: $("auditOutcome")?.value || "",
    targetType: $("auditTargetType")?.value || "",
    orgId: $("auditOrg")?.value || "",
    projectId: $("auditProject")?.value || "",
    actorId: $("auditActor")?.value || "",
    since: $("auditSince")?.value || "",
    until: $("auditUntil")?.value || "",
  };
  if (state.auditFilters.orgId && state.auditFilters.projectId) {
    const p = (state.auditFilterOptions?.projects || []).find((x) => x.id === state.auditFilters.projectId);
    if (p && p.org_id !== state.auditFilters.orgId) state.auditFilters.projectId = "";
  }
}

function clearAuditFilters() {
  state.auditFilters = {
    q: "",
    action: "",
    category: "",
    outcome: "",
    targetType: "",
    orgId: "",
    projectId: "",
    actorId: "",
    since: "",
    until: "",
  };
}

function modal(html, { size = "" } = {}) {
  const cls = size ? `modal ${size}` : "modal";
  $("modalRoot").innerHTML = `<div class="overlay" id="overlay"><div class="${cls}" role="dialog">${html}</div></div>`;
  $("overlay").onclick = (e) => {
    if (e.target === e.currentTarget) closeModal();
  };
}
function closeModal() {
  if (state.diagTimer) {
    clearTimeout(state.diagTimer);
    state.diagTimer = null;
  }
  if (state.activeEditorDispose) {
    try {
      state.activeEditorDispose();
    } catch {
      /* ignore */
    }
    state.activeEditorDispose = null;
  }
  if ($("modalRoot")) $("modalRoot").innerHTML = "";
}

async function refreshSession() {
  const meta = await api("/auth/meta");
  state.oidcEnabled = meta.oidcEnabled;
  const me = await api("/auth/me");
  state.user = me.user;
}

async function loadOrgsProjects() {
  state.orgs = (await api("/orgs")).orgs;
  state.projects = (await api("/projects")).projects;
  if (state.org && !state.orgs.find((o) => o.id === state.org.id)) state.org = state.orgs[0] || null;
  if (!state.org && state.orgs[0]) state.org = state.orgs[0];
  if (state.org) {
    const live = state.orgs.find((o) => o.id === state.org.id);
    if (live) state.org = live;
    try {
      const data = await api(`/orgs/${state.org.id}?sync=1`);
      state.orgMembers = data.members || [];
    } catch {
      state.orgMembers = [];
    }
  } else {
    state.orgMembers = [];
  }
}

async function openProject(id) {
  const data = await api(`/projects/${id}`);
  const listed = state.projects.find((p) => p.id === id);
  state.oversight = !!data.oversight;
  state.project = {
    ...data.project,
    my_role: data.myRole || listed?.my_role,
    org_name: listed?.org_name || state.orgs.find((o) => o.id === data.project.org_id)?.name,
  };
  if (!state.org || state.org.id !== data.project.org_id) {
    state.org = state.orgs.find((o) => o.id === data.project.org_id) || state.org;
  }
  if (state.org?.id === data.project.org_id && !(state.orgMembers || []).length) {
    try {
      const orgData = await api(`/orgs/${state.org.id}?sync=1`);
      state.orgMembers = orgData.members || [];
    } catch {
      /* keep */
    }
  }
  state.folders = data.folders;
  state.members = data.members;
  state.view = "project";
  if (state.folderId && !state.folders.find((f) => f.id === state.folderId)) state.folderId = null;
  if (state.folderId) await loadFiles();
  else state.files = [];
  paint();
}

async function loadFiles() {
  if (!state.folderId) {
    state.files = [];
    return;
  }
  const data = await api(`/folders/${state.folderId}/files`);
  state.files = (data.files || []).map((f) => ({
    ...f,
    size: f.size || 0,
    diagnostics: Array.isArray(f.diagnostics) ? f.diagnostics : [],
    isCode: !!(f.isCode ?? f.is_code),
  }));
}

async function paint() {
  if (!state.user) {
    root.innerHTML = gate();
    wireGate();
    return;
  }
  if (state.view === "admin") {
    if (!state.adminConsoleLogged) {
      state.adminConsoleLogged = true;
      api("/admin/console-opened", { method: "POST" }).catch(() => {});
    }
    if (!state.auditFilterOptions) {
      try {
        state.auditFilterOptions = await api("/auth/admin/audit/filters");
      } catch {
        state.auditFilterOptions = {
          categories: [],
          outcomes: [
            { id: "success", label: "Succeeded" },
            { id: "failure", label: "Failed" },
          ],
          actions: [],
          orgs: [],
          projects: [],
          actors: [],
          targetTypes: [],
        };
      }
    } else if (!state.auditFilterOptions.outcomes) {
      state.auditFilterOptions.outcomes = [
        { id: "success", label: "Succeeded" },
        { id: "failure", label: "Failed" },
      ];
    }
    let users = [];
    let events = [];
    if (state.adminTab === "users") {
      users = (await api("/auth/admin/users")).users;
      state.adminUsersFp = users.map((u) => `${u.id}:${u.status}:${!!u.canCreateOrg}:${!!u.isPlatformAdmin}`).join("|");
    } else if (state.adminTab === "audit") {
      events = (await api(`/auth/admin/audit?${auditQueryParams()}`)).events;
    } else if (state.adminTab === "catalog") {
      if (!state.catalog.orgs?.length && !state.catalog.orgId) {
        await loadCatalogRoot();
      }
    }
    root.innerHTML = shell(adminMain(users, events, state.auditFilterOptions));
  } else if (state.view === "project" && state.project) {
    root.innerHTML = shell(projectMain());
  } else {
    root.innerHTML = shell(homeMain());
  }
  renderOrgList();
  renderProjectList();
  try {
    renderFoldersFiles();
  } catch (e) {
    console.error("renderFoldersFiles", e);
  }
  wireShell();
  if ($("orgMemberSearch")) {
    $("orgMemberSearch").value = state.memberSearch || "";
    refreshOrgMemberResults();
  }
  if ($("projectMemberSearch")) {
    $("projectMemberSearch").value = state.memberSearch || "";
  }
}

function wireGate() {
  const err = (m) => ($("gateErr").textContent = m || "");
  $("tabLogin").onclick = () => {
    $("tabLogin").setAttribute("aria-selected", "true");
    $("tabRegister").setAttribute("aria-selected", "false");
    $("paneLogin").classList.remove("hidden");
    $("paneRegister").classList.add("hidden");
    err("");
  };
  $("tabRegister").onclick = () => {
    $("tabRegister").setAttribute("aria-selected", "true");
    $("tabLogin").setAttribute("aria-selected", "false");
    $("paneRegister").classList.remove("hidden");
    $("paneLogin").classList.add("hidden");
    err("");
  };
  if (state.oidcEnabled) $("btnOidc").classList.remove("hidden");
  $("btnOidc").onclick = async () => {
    try {
      const { url } = await api("/auth/oidc/start");
      location.href = url;
    } catch (e) {
      err(e.message);
    }
  };
  $("btnLogin").onclick = async () => {
    try {
      await api("/auth/login", { method: "POST", body: { email: $("lEmail").value, password: $("lPass").value } });
      await boot();
    } catch (e) {
      err(e.message);
    }
  };
  $("btnRegister").onclick = async () => {
    try {
      await api("/auth/register", {
        method: "POST",
        body: { name: $("rName").value, email: $("rEmail").value, password: $("rPass").value },
      });
      await boot();
    } catch (e) {
      err(e.message);
    }
  };
}

function wireMemberListControls() {
  document.querySelectorAll("[data-proj-check]").forEach((c) => {
    c.onchange = () => {
      const id = c.dataset.projCheck;
      if (c.checked) {
        if (!state.selectedProjectMemberIds.includes(id)) state.selectedProjectMemberIds.push(id);
      } else {
        state.selectedProjectMemberIds = state.selectedProjectMemberIds.filter((x) => x !== id);
      }
    };
  });
  document.querySelectorAll("[data-rm-project]").forEach((b) => {
    b.onclick = async () => {
      if (!confirm("Remove this member from the project?")) return;
      try {
        const res = await api(`/projects/${state.project.id}/members/${b.dataset.rmProject}`, {
          method: "DELETE",
        });
        state.members = res.members;
        state.memberSearch = "";
        state.selectedProjectMemberIds = state.selectedProjectMemberIds.filter((id) => id !== b.dataset.rmProject);
        paint();
        toast("Member removed from project.");
      } catch (e) {
        toast(e.message);
      }
    };
  });
}

function wireShell() {
  $("btnLogout").onclick = async () => {
    await api("/auth/logout", { method: "POST" });
    state.user = null;
    clearInterval(state.poll);
    paint();
  };
  $("btnNewOrg")?.addEventListener("click", () => {
    modal(`<h3>New organization</h3>
      <label>Name</label><input class="field" id="oName">
      <label>Retention (days)</label><input class="field" id="oRet" type="number" value="365">
      <div class="modal-actions"><button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Create</button></div>`);
    $("mCancel").onclick = closeModal;
    $("mOk").onclick = async () => {
      await api("/orgs", { method: "POST", body: { name: $("oName").value, retentionDays: Number($("oRet").value) || 365 } });
      closeModal();
      await loadOrgsProjects();
      paint();
      toast("Organization created.");
    };
  });
  $("btnNewProject")?.addEventListener("click", () => {
    if (!state.org) return toast("Create/select an organization first.");
    modal(`<h3>New project</h3>
      <label>Name</label><input class="field" id="pName">
      <div class="modal-actions"><button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Create</button></div>`);
    $("mCancel").onclick = closeModal;
    $("mOk").onclick = async () => {
      const res = await api("/projects", { method: "POST", body: { orgId: state.org.id, name: $("pName").value } });
      closeModal();
      modal(`<h3>Project ready</h3><p class="sub">Share this invite with org members (not a decrypt key — membership only).</p>
        <div class="key-tag"><div><span class="lbl">Invite</span><span class="code">${esc(res.inviteCode)}</span></div></div>
        <div class="modal-actions"><button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mDone">Done</button></div>`);
      $("mDone").onclick = closeModal;
      await loadOrgsProjects();
      await openProject(res.project.id);
    };
  });
  $("btnJoinInvite")?.addEventListener("click", () => {
    modal(`<h3>Join project</h3><label>Invite code</label><input class="field mono" id="jInv">
      <div class="modal-actions"><button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Join</button></div>`);
    $("mCancel").onclick = closeModal;
    $("mOk").onclick = async () => {
      try {
        const res = await api("/projects/join", { method: "POST", body: { inviteCode: $("jInv").value } });
        closeModal();
        await loadOrgsProjects();
        await openProject(res.project.id);
        toast("Joined project.");
      } catch (e) {
        toast(e.message);
      }
    };
  });
  $("btnAdmin")?.addEventListener("click", async () => {
    state.view = "admin";
    state.adminTab = "users";
    state.auditFilterOptions = null;
    paint();
  });
  $("btnBackHome")?.addEventListener("click", () => {
    state.view = "home";
    paint();
  });
  $("tabAdminUsers")?.addEventListener("click", () => {
    state.adminTab = "users";
    paint();
  });
  $("tabAdminAudit")?.addEventListener("click", () => {
    state.adminTab = "audit";
    paint();
  });
  $("tabAdminCatalog")?.addEventListener("click", async () => {
    state.adminTab = "catalog";
    if (!state.catalog.orgId && !(state.catalog.orgs || []).length) {
      try {
        await loadCatalogRoot();
      } catch (e) {
        toast(e.message);
      }
    }
    paint();
  });
  document.querySelectorAll("[data-catalog-open-org]").forEach((b) => {
    b.onclick = async () => {
      try {
        await loadCatalogOrg(b.dataset.catalogOpenOrg);
        paint();
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-catalog-open-project]").forEach((b) => {
    b.onclick = async () => {
      try {
        await loadCatalogProject(b.dataset.catalogOpenProject);
        paint();
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-catalog-open-folder]").forEach((b) => {
    b.onclick = async () => {
      try {
        await loadCatalogFolder(b.dataset.catalogOpenFolder);
        paint();
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-catalog-level]").forEach((b) => {
    b.onclick = async () => {
      try {
        const level = b.dataset.catalogLevel;
        if (level === "root") await loadCatalogRoot();
        else if (level === "org") await loadCatalogOrg(b.dataset.catalogOrg);
        else if (level === "project") await loadCatalogProject(b.dataset.catalogProject);
        paint();
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-catalog-jump-org]").forEach((b) => {
    b.onclick = async () => {
      try {
        await openCatalogAt({
          orgId: b.dataset.catalogJumpOrg || null,
          projectId: b.dataset.catalogJumpProject || null,
          folderId: b.dataset.catalogJumpFolder || null,
        });
      } catch (e) {
        toast(e.message);
      }
    };
  });
  $("btnExportAudit")?.addEventListener("click", () => {
    window.location.href = `/api/auth/admin/audit/export?${auditQueryParams({ forExport: true })}`;
  });
  $("btnBackup")?.addEventListener("click", async () => {
    try {
      const res = await api("/admin/backup", { method: "POST" });
      toast("Backup created: " + res.path);
    } catch (e) {
      toast(e.message);
    }
  });
  $("btnBackups")?.addEventListener("click", () => openBackupManager());
  $("btnAuditSearch")?.addEventListener("click", () => {
    readAuditFiltersFromDom();
    paint();
  });
  $("btnAuditClear")?.addEventListener("click", () => {
    clearAuditFilters();
    paint();
  });
  $("auditQ")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      readAuditFiltersFromDom();
      paint();
    }
  });
  $("auditOrg")?.addEventListener("change", () => {
    readAuditFiltersFromDom();
    paint();
  });
  document.querySelectorAll("[data-audit-toggle]").forEach((b) => {
    b.onclick = () => {
      const el = $(b.dataset.auditToggle);
      if (!el) return;
      el.classList.toggle("hidden");
      const open = !el.classList.contains("hidden");
      b.textContent = open ? "Hide details" : "Details";
      const id = b.dataset.auditEvent;
      if (id) {
        if (open) state.auditExpandedIds.add(id);
        else state.auditExpandedIds.delete(id);
      }
    };
  });
  document.querySelectorAll("[data-disable]").forEach((b) => {
    b.onclick = async () => {
      await api(`/auth/admin/users/${b.dataset.disable}/status`, { method: "POST", body: { status: "disabled" } });
      paint();
    };
  });
  document.querySelectorAll("[data-enable]").forEach((b) => {
    b.onclick = async () => {
      await api(`/auth/admin/users/${b.dataset.enable}/status`, { method: "POST", body: { status: "active" } });
      paint();
    };
  });
  document.querySelectorAll("[data-promote]").forEach((b) => {
    b.onclick = async () => {
      try {
        await api(`/auth/admin/users/${b.dataset.promote}/platform-admin`, { method: "POST", body: { grant: true } });
        paint();
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-demote]").forEach((b) => {
    b.onclick = async () => {
      try {
        await api(`/auth/admin/users/${b.dataset.demote}/platform-admin`, { method: "POST", body: { grant: false } });
        paint();
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-grant-org]").forEach((b) => {
    b.onclick = async () => {
      try {
        await api(`/auth/admin/users/${b.dataset.grantOrg}/can-create-org`, { method: "POST", body: { grant: true } });
        paint();
        toast("User can create organizations.");
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-revoke-org]").forEach((b) => {
    b.onclick = async () => {
      try {
        await api(`/auth/admin/users/${b.dataset.revokeOrg}/can-create-org`, { method: "POST", body: { grant: false } });
        paint();
        toast("Org-create permission revoked.");
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-org]").forEach((b) => {
    b.onclick = async () => {
      state.org = state.orgs.find((o) => o.id === b.dataset.org);
      state.view = "home";
      state.project = null;
      state.oversight = false;
      await loadOrgsProjects();
      paint();
    };
  });
  document.querySelectorAll("[data-project]").forEach((b) => {
    b.onclick = () => openProject(b.dataset.project);
  });

  $("btnAddOrgMember")?.addEventListener("click", () => openMassAddOrgMembers());
  $("btnOrgBulkManage")?.addEventListener("click", () => openOrgBulkManage());
  $("btnMassProjectMembers")?.addEventListener("click", () => openMassProjectMembers());
  $("btnProjectBulkManage")?.addEventListener("click", () => openProjectBulkManage());
  $("btnOffboardFolders")?.addEventListener("click", () => openOffboardFolders());
  $("btnCopyFolderAcl")?.addEventListener("click", () => openCopyFolderAcl());
  $("btnResetFileAcl")?.addEventListener("click", () => resetSelectedFilesAcl());
  $("btnBulkDeleteFiles")?.addEventListener("click", () => bulkDeleteSelectedFiles());

  const bindMemberSearch = (id, refresh) => {
    const el = $(id);
    if (!el) return;
    el.oninput = () => {
      state.memberSearch = el.value;
      refresh();
    };
  };
  bindMemberSearch("orgMemberSearch", refreshOrgMemberResults);
  bindMemberSearch("projectMemberSearch", refreshProjectMemberResults);
  refreshOrgMemberResults();
  refreshProjectMemberResults();

  $("btnOrgAudit")?.addEventListener("click", async () => {
    try {
      const res = await api(`/orgs/${state.org.id}/audit?limit=80`);
      modal(`<h3>Org audit — ${esc(state.org.name)}</h3>${res.events
        .map(
          (e) => `<div class="act-row" style="flex-direction:column;align-items:stretch;gap:4px">
          <div style="display:flex;justify-content:space-between;gap:12px">
            <span><strong>${esc(e.actor_name || e.actor_email || "?")}</strong> · ${esc(e.action)}</span>
            <span class="when">${new Date(e.ts).toLocaleString()}</span>
          </div>
          ${e.meta ? `<span class="fmeta mono" style="font-size:11px">${esc(JSON.stringify(e.meta))}</span>` : ""}
        </div>`
        )
        .join("")}
        <div class="modal-actions"><a class="btn btn-quiet" href="/api/orgs/${state.org.id}/audit/export">Export JSON</a>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mDone">Close</button></div>`);
      $("mDone").onclick = closeModal;
    } catch (e) {
      toast(e.message);
    }
  });

  $("btnNewFolder")?.addEventListener("click", () => {
    const parent = state.folders.find((f) => f.id === state.folderId);
    modal(`<h3>New folder</h3>
      <label>Name</label><input class="field" id="fName">
      <div class="switch-row" style="margin-top:10px">
        <input type="checkbox" id="fNest" ${parent ? "checked" : ""} ${parent ? "" : "disabled"}>
        <label for="fNest" style="margin:0">${
          parent ? `Create inside <strong>${esc(parent.name)}</strong>` : "Select a folder first to nest inside it"
        }</label>
      </div>
      <div class="modal-actions"><button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Create</button></div>`);
    $("mCancel").onclick = closeModal;
    $("mOk").onclick = async () => {
      const nest = $("fNest")?.checked && parent;
      await api(`/projects/${state.project.id}/folders`, {
        method: "POST",
        body: { name: $("fName").value, parentId: nest ? parent.id : null },
      });
      closeModal();
      await openProject(state.project.id);
      toast(nest ? `Folder created inside ${parent.name}.` : "Folder created.");
    };
  });
  $("btnAddMember")?.addEventListener("click", () => {
    openAddPersonModal({
      title: "Add project member",
      sub: "Search registered users. Org owners/admins can add someone not yet in the org (they join the org as member). Or share an invite code after they’re in the org.",
      roleLabel: "Project role",
      roleOptions: `<option value="member">Project member</option><option value="admin">Project Owner</option>`,
      searchParams: () => ({ projectId: state.project.id }),
      confirmLabel: "Add",
      onAdd: async ({ userId, role }) => {
        await api(`/projects/${state.project.id}/members`, { method: "POST", body: { userId, role } });
        await openProject(state.project.id);
        toast("Member added.");
      },
    });
  });
  $("btnRotateInvite")?.addEventListener("click", async () => {
    const res = await api(`/projects/${state.project.id}/invite/rotate`, { method: "POST" });
    modal(`<h3>New invite code</h3><div class="key-tag"><div><span class="lbl">Invite</span><span class="code">${esc(res.inviteCode)}</span></div></div>
      <div class="modal-actions"><button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mDone">Done</button></div>`);
    $("mDone").onclick = closeModal;
  });
  $("btnProjectAudit")?.addEventListener("click", async () => {
    const res = await api(`/orgs/${state.project.org_id}/audit?limit=50`);
    modal(`<h3>Org audit</h3>${res.events
      .map((e) => `<div class="act-row"><span><strong>${esc(e.actor_name || "?")}</strong> ${esc(e.action)}</span><span class="when">${new Date(e.ts).toLocaleString()}</span></div>`)
      .join("")}
      <div class="modal-actions"><a class="btn btn-quiet" href="/api/orgs/${state.project.org_id}/audit/export">Export JSON</a>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mDone">Close</button></div>`,);
    $("mDone").onclick = closeModal;
  });

  document.querySelectorAll("[data-folder]").forEach((b) => {
    b.onclick = async () => {
      state.folderId = b.dataset.folder;
      state.selectedFileIds = [];
      await loadFiles();
      paint();
    };
  });
  $("btnFolderAcl")?.addEventListener("click", () => openFolderAcl());
  $("btnBulkFolderAcl")?.addEventListener("click", () => openBulkFolderAcl());
  $("btnBulkFileAcl")?.addEventListener("click", () => openBulkFileAcl());
  document.querySelectorAll("[data-folder-check]").forEach((c) => {
    c.onchange = () => {
      const id = c.dataset.folderCheck;
      if (c.checked) {
        if (!state.selectedFolderIds.includes(id)) state.selectedFolderIds.push(id);
      } else {
        state.selectedFolderIds = state.selectedFolderIds.filter((x) => x !== id);
      }
    };
    c.onclick = (e) => e.stopPropagation();
  });
  document.querySelectorAll("[data-file-check]").forEach((c) => {
    c.onchange = () => {
      const id = c.dataset.fileCheck;
      if (c.checked) {
        if (!state.selectedFileIds.includes(id)) state.selectedFileIds.push(id);
      } else {
        state.selectedFileIds = state.selectedFileIds.filter((x) => x !== id);
      }
      syncFileBulkButtons();
    };
  });
  $("btnDelFolder")?.addEventListener("click", async () => {
    if (!confirm("Delete this folder?")) return;
    try {
      await api(`/folders/${state.folderId}`, { method: "DELETE" });
      state.folderId = null;
      await openProject(state.project.id);
    } catch (e) {
      toast(e.message);
    }
  });
  $("btnBrowse")?.addEventListener("click", () => $("filePick").click());
  $("filePick")?.addEventListener("change", async (e) => {
    await uploadFiles(e.target.files);
    e.target.value = "";
  });
  const dz = $("dropzone");
  if (dz) {
    dz.ondragover = (e) => {
      e.preventDefault();
      dz.classList.add("armed");
    };
    dz.ondragleave = () => dz.classList.remove("armed");
    dz.ondrop = async (e) => {
      e.preventDefault();
      dz.classList.remove("armed");
      await uploadFiles(e.dataTransfer.files);
    };
  }
  document.querySelectorAll("[data-open],[data-edit]").forEach((b) => {
    b.onclick = () => openFile(b.dataset.open || b.dataset.edit, !!b.dataset.edit);
  });
  document.querySelectorAll("[data-facl]").forEach((b) => {
    b.onclick = () => openFileAcl(b.dataset.facl);
  });
  document.querySelectorAll("[data-vers]").forEach((b) => {
    b.onclick = () => openVersions(b.dataset.vers);
  });
  document.querySelectorAll("[data-delfile]").forEach((b) => {
    b.onclick = async () => {
      if (!confirm("Delete this file?")) return;
      await api(`/files/${b.dataset.delfile}`, { method: "DELETE" });
      await loadFiles();
      paint();
    };
  });
}

async function uploadFiles(fileList) {
  const notes = [];
  let failed = 0;
  for (const file of fileList) {
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await api(`/folders/${state.folderId}/files`, { method: "POST", body: fd });
      const errs = (res.diagnostics || []).filter((d) => d.severity === "error").length;
      const warns = (res.diagnostics || []).filter((d) => d.severity === "warning").length;
      if (res.isCode) {
        notes.push(
          `${file.name}: ${res.language || "code"} · ${res.formatStatus || "ok"}${
            errs || warns ? ` · ${errs} err / ${warns} warn` : ""
          }`
        );
      } else {
        notes.push(`${file.name}: uploaded`);
      }
    } catch (e) {
      failed += 1;
      notes.push(`${file.name}: failed — ${e.message}`);
    }
  }
  await loadFiles();
  paint();
  toast(
    failed
      ? `Upload finished with errors. ${notes.join(" · ")}`
      : notes.length
        ? `Upload complete. ${notes.join(" · ")}`
        : "Upload complete."
  );
}

function matchPeople(list, q) {
  const needle = (q || "").trim().toLowerCase();
  if (!needle) return list.slice(0, 40);
  return list
    .filter((m) => {
      const hay = `${m.name || ""} ${m.email || ""}`.toLowerCase();
      return hay.includes(needle);
    })
    .slice(0, 40);
}

/** Server typeahead add-person modal (org / project). */
function openAddPersonModal({ title, sub, roleLabel, roleOptions, searchParams, confirmLabel, onAdd }) {
  let q = "";
  let hits = [];
  let selected = null;
  let searchGen = 0;
  let debounceTimer = null;

  const renderHits = () => {
    if (q.trim().length < 2) {
      return `<div class="picker-empty">Type at least 2 characters to search registered users.</div>`;
    }
    if (!hits.length) {
      return `<div class="picker-empty">No matches (or they’re already added). They must register first.</div>`;
    }
    return hits
      .map(
        (u) => `<button type="button" class="picker-hit ${selected?.id === u.id ? "picked" : ""}" data-uid="${u.id}">
          <span class="who">${esc(u.name)}</span>
          <span class="hint">${esc(u.email)}</span>
        </button>`
      )
      .join("");
  };

  const renderBody = () => `<h3>${esc(title)}</h3>
    <p class="sub">${sub}</p>
    <label>Search users</label>
    <input class="field share-search" id="userSearchQ" type="search" placeholder="Name or email…" value="${esc(q)}" autocomplete="off" style="margin-bottom:8px">
    <div class="picker-panel" id="userPicker">${renderHits()}</div>
    <div id="userPicked" class="fine" style="margin:10px 0">${
      selected ? `Selected: <strong>${esc(selected.name)}</strong> · ${esc(selected.email)}` : "No one selected yet."
    }</div>
    <label>${esc(roleLabel)}</label>
    <select class="field" id="mRole">${roleOptions}</select>
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">${esc(confirmLabel)}</button>
    </div>`;

  const wireHits = () => {
    document.querySelectorAll("#userPicker [data-uid]").forEach((b) => {
      b.onclick = () => {
        selected = hits.find((u) => u.id === b.dataset.uid) || null;
        const picked = $("userPicked");
        if (picked) {
          picked.innerHTML = selected
            ? `Selected: <strong>${esc(selected.name)}</strong> · ${esc(selected.email)}`
            : "No one selected yet.";
        }
        document.querySelectorAll("#userPicker .picker-hit").forEach((el) => {
          el.classList.toggle("picked", el.dataset.uid === selected?.id);
        });
      };
    });
  };

  const runSearch = async () => {
    const myGen = ++searchGen;
    const needle = q.trim();
    if (needle.length < 2) {
      hits = [];
      const panel = $("userPicker");
      if (panel) {
        panel.innerHTML = renderHits();
        wireHits();
      }
      return;
    }
    try {
      const params = new URLSearchParams({ q: needle, limit: "20", ...searchParams() });
      const res = await api(`/users/search?${params}`);
      if (myGen !== searchGen) return;
      hits = res.users || [];
      const panel = $("userPicker");
      if (panel) {
        panel.innerHTML = renderHits();
        wireHits();
      }
    } catch (e) {
      if (myGen !== searchGen) return;
      hits = [];
      const panel = $("userPicker");
      if (panel) panel.innerHTML = `<div class="picker-empty">${esc(e.message)}</div>`;
    }
  };

  modal(renderBody(), { size: "wide" });
  $("mCancel").onclick = closeModal;
  const input = $("userSearchQ");
  input.focus();
  input.oninput = () => {
    q = input.value;
    selected = null;
    const picked = $("userPicked");
    if (picked) picked.textContent = "No one selected yet.";
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runSearch, 220);
  };
  wireHits();
  $("mOk").onclick = async () => {
    if (!selected) return toast("Search and select a user first.");
    try {
      await onAdd({ userId: selected.id, role: $("mRole").value });
      closeModal();
    } catch (e) {
      toast(e.message);
    }
  };
}

function parseOrgMembersCsv(text) {
  const lines = String(text || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const entries = [];
  for (let i = 0; i < lines.length; i++) {
    const parts = lines[i].split(/[,;\t]/).map((p) => p.trim().replace(/^"|"$/g, ""));
    if (!parts[0]) continue;
    const email = parts[0].toLowerCase();
    if (i === 0 && (email === "email" || email === "e-mail")) continue;
    let role = (parts[1] || "member").toLowerCase();
    if (role !== "admin" && role !== "member") role = "member";
    entries.push({ email, role });
  }
  return entries;
}

/** Multi-select search + CSV import for org members. */
function openMassAddOrgMembers() {
  let tab = "search"; // search | csv
  let q = "";
  let hits = [];
  let picked = new Map(); // id -> {id,name,email}
  let searchGen = 0;
  let debounceTimer = null;

  const renderHits = () => {
    if (q.trim().length < 2) {
      return `<div class="picker-empty">Type at least 2 characters to search. Click to toggle selection.</div>`;
    }
    if (!hits.length) return `<div class="picker-empty">No matches (or already in this org).</div>`;
    return hits
      .map((u) => {
        const on = picked.has(u.id);
        return `<button type="button" class="picker-hit ${on ? "picked" : ""}" data-uid="${u.id}">
          <span class="who">${on ? "✓ " : ""}${esc(u.name)}</span>
          <span class="hint">${esc(u.email)}</span>
        </button>`;
      })
      .join("");
  };

  const renderPicked = () => {
    if (!picked.size) return `<p class="fine">No one selected yet.</p>`;
    return `<div class="share-list">${[...picked.values()]
      .map(
        (u) => `<div class="share-row">
        <div class="who-block"><span class="who">${esc(u.name)}</span><span class="hint">${esc(u.email)}</span></div>
        <button class="btn btn-quiet btn-danger" type="button" style="width:auto;margin:0" data-unpick="${u.id}">Remove</button>
      </div>`
      )
      .join("")}</div>`;
  };

  const renderBody = () => `<h3>Add organization members</h3>
    <p class="sub">Multi-select from search, or import a CSV (<code>email,role</code> with role member|admin). Unknown emails are skipped.</p>
    <div class="share-toolbar" style="margin-bottom:12px">
      <button type="button" class="btn btn-quiet ${tab === "search" ? "picked-tab" : ""}" id="tabSearch" style="width:auto;margin:0">Search</button>
      <button type="button" class="btn btn-quiet ${tab === "csv" ? "picked-tab" : ""}" id="tabCsv" style="width:auto;margin:0">CSV import</button>
    </div>
    ${
      tab === "search"
        ? `<label>Search users</label>
      <input class="field share-search" id="userSearchQ" type="search" placeholder="Name or email…" value="${esc(q)}" autocomplete="off">
      <div class="picker-panel" id="userPicker">${renderHits()}</div>
      <h4 style="margin:14px 0 8px;font-size:13px">Selected (${picked.size})</h4>
      <div id="pickedBox">${renderPicked()}</div>
      <label>Org role for all selected</label>
      <select class="field" id="mRole"><option value="member">member</option><option value="admin">admin</option></select>`
        : `<label>CSV file</label>
      <input class="field" id="csvFile" type="file" accept=".csv,text/csv,text/plain">
      <label style="margin-top:10px">Or paste CSV</label>
      <textarea class="field" id="csvText" rows="8" placeholder="email,role&#10;alice@corp.com,member&#10;bob@corp.com,admin"></textarea>
      <p class="fine">Header row optional. Role defaults to member if omitted.</p>`
    }
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">${
        tab === "search" ? "Add selected" : "Import CSV"
      }</button>
    </div>`;

  const paintModal = () => {
    modal(renderBody(), { size: "wide" });
    $("mCancel").onclick = closeModal;
    $("tabSearch").onclick = () => {
      tab = "search";
      paintModal();
    };
    $("tabCsv").onclick = () => {
      tab = "csv";
      paintModal();
    };
    if (tab === "search") {
      const input = $("userSearchQ");
      input.focus();
      input.oninput = () => {
        q = input.value;
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(runSearch, 220);
      };
      wireSearch();
      $("mOk").onclick = async () => {
        if (!picked.size) return toast("Select at least one user.");
        try {
          const res = await api(`/orgs/${state.org.id}/members/bulk`, {
            method: "POST",
            body: { userIds: [...picked.keys()], role: $("mRole").value },
          });
          closeModal();
          await loadOrgsProjects();
          paint();
          toast(
            `Added ${res.added?.length || 0}, updated ${res.updated?.length || 0}, skipped ${res.skipped?.length || 0}.`
          );
        } catch (e) {
          toast(e.message);
        }
      };
    } else {
      $("csvFile").onchange = async () => {
        const file = $("csvFile").files?.[0];
        if (!file) return;
        $("csvText").value = await file.text();
      };
      $("mOk").onclick = async () => {
        const entries = parseOrgMembersCsv($("csvText").value);
        if (!entries.length) return toast("No email rows found.");
        try {
          const res = await api(`/orgs/${state.org.id}/members/bulk`, {
            method: "POST",
            body: { entries },
          });
          closeModal();
          await loadOrgsProjects();
          paint();
          toast(
            `Added ${res.added?.length || 0}, updated ${res.updated?.length || 0}, skipped ${res.skipped?.length || 0}.`
          );
        } catch (e) {
          toast(e.message);
        }
      };
    }
  };

  const wireSearch = () => {
    document.querySelectorAll("#userPicker [data-uid]").forEach((b) => {
      b.onclick = () => {
        const u = hits.find((x) => x.id === b.dataset.uid);
        if (!u) return;
        if (picked.has(u.id)) picked.delete(u.id);
        else picked.set(u.id, u);
        const panel = $("userPicker");
        if (panel) panel.innerHTML = renderHits();
        wireSearch();
        const box = $("pickedBox");
        if (box) {
          box.innerHTML = renderPicked();
          document.querySelectorAll("[data-unpick]").forEach((btn) => {
            btn.onclick = () => {
              picked.delete(btn.dataset.unpick);
              paintModal();
            };
          });
        }
      };
    });
    document.querySelectorAll("[data-unpick]").forEach((btn) => {
      btn.onclick = () => {
        picked.delete(btn.dataset.unpick);
        paintModal();
      };
    });
  };

  const runSearch = async () => {
    const myGen = ++searchGen;
    const needle = q.trim();
    if (needle.length < 2) {
      hits = [];
      const panel = $("userPicker");
      if (panel) {
        panel.innerHTML = renderHits();
        wireSearch();
      }
      return;
    }
    try {
      const res = await api(`/users/search?${new URLSearchParams({ q: needle, limit: "20", orgId: state.org.id })}`);
      if (myGen !== searchGen) return;
      hits = res.users || [];
      const panel = $("userPicker");
      if (panel) {
        panel.innerHTML = renderHits();
        wireSearch();
      }
    } catch (e) {
      if (myGen !== searchGen) return;
      const panel = $("userPicker");
      if (panel) panel.innerHTML = `<div class="picker-empty">${esc(e.message)}</div>`;
    }
  };

  paintModal();
}

function openOrgBulkManage() {
  const ids = state.selectedOrgMemberIds.filter((id) => {
    const m = (state.orgMembers || []).find((x) => x.id === id);
    return m && m.role !== "owner" && m.id !== state.user.id;
  });
  if (!ids.length) return toast("Select one or more org members (not the owner).");
  const names = ids
    .map((id) => (state.orgMembers || []).find((m) => m.id === id))
    .filter(Boolean)
    .map((m) => esc(m.name))
    .join(", ");
  modal(`<h3>Manage selected org members</h3>
    <p class="sub">${ids.length} selected: ${names}</p>
    <label>New role</label>
    <select class="field" id="bulkOrgRole"><option value="member">member</option><option value="admin">admin</option></select>
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-quiet btn-danger" type="button" id="mRemove" style="width:auto;margin:0">Remove from org</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Apply role</button>
    </div>`);
  $("mCancel").onclick = closeModal;
  $("mOk").onclick = async () => {
    try {
      const res = await api(`/orgs/${state.org.id}/members/bulk-roles`, {
        method: "POST",
        body: { userIds: ids, role: $("bulkOrgRole").value },
      });
      closeModal();
      state.selectedOrgMemberIds = [];
      await loadOrgsProjects();
      paint();
      toast(`Updated ${res.updated?.length || 0}, skipped ${res.skipped?.length || 0}.`);
    } catch (e) {
      toast(e.message);
    }
  };
  $("mRemove").onclick = async () => {
    if (!confirm(`Remove ${ids.length} member(s) from the organization?`)) return;
    try {
      const res = await api(`/orgs/${state.org.id}/members/bulk-remove`, {
        method: "POST",
        body: { userIds: ids },
      });
      closeModal();
      state.selectedOrgMemberIds = [];
      await loadOrgsProjects();
      paint();
      toast(`Removed ${res.removed?.length || 0}, skipped ${res.skipped?.length || 0}.`);
    } catch (e) {
      toast(e.message);
    }
  };
}

function openProjectBulkManage() {
  const ids = state.selectedProjectMemberIds.filter((id) => id !== state.user.id);
  if (!ids.length) return toast("Select one or more project members.");
  const names = ids
    .map((id) => (state.members || []).find((m) => m.id === id))
    .filter(Boolean)
    .map((m) => esc(m.name))
    .join(", ");
  modal(`<h3>Manage selected project members</h3>
    <p class="sub">${ids.length} selected: ${names}</p>
    <label>New project role</label>
    <select class="field" id="bulkProjRole"><option value="member">Project member</option><option value="admin">Project Owner</option></select>
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-quiet btn-danger" type="button" id="mRemove" style="width:auto;margin:0">Remove from project</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Apply role</button>
    </div>`);
  $("mCancel").onclick = closeModal;
  $("mOk").onclick = async () => {
    try {
      const res = await api(`/projects/${state.project.id}/members/bulk-roles`, {
        method: "POST",
        body: { userIds: ids, role: $("bulkProjRole").value },
      });
      closeModal();
      state.selectedProjectMemberIds = [];
      state.members = res.members || state.members;
      await openProject(state.project.id);
      toast(`Updated ${res.updated?.length || 0}, skipped ${res.skipped?.length || 0}.`);
    } catch (e) {
      toast(e.message);
    }
  };
  $("mRemove").onclick = async () => {
    if (!confirm(`Remove ${ids.length} member(s) from this project?`)) return;
    try {
      const res = await api(`/projects/${state.project.id}/members/bulk-remove`, {
        method: "POST",
        body: { userIds: ids },
      });
      closeModal();
      state.selectedProjectMemberIds = [];
      state.members = res.members || state.members;
      await openProject(state.project.id);
      toast(`Removed ${res.removed?.length || 0}, skipped ${res.skipped?.length || 0}.`);
    } catch (e) {
      toast(e.message);
    }
  };
}

/** Add org people into this project (mass). */
async function openMassProjectMembers() {
  if (state.org?.id) {
    try {
      const orgData = await api(`/orgs/${state.org.id}?sync=1`);
      state.orgMembers = orgData.members || [];
    } catch (e) {
      toast(e.message);
      return;
    }
  }
  const inProject = new Set((state.members || []).map((m) => m.id));
  const candidates = (state.orgMembers || []).filter((m) => !inProject.has(m.id));
  let picked = new Set();
  let q = "";

  const filtered = () => matchPeople(candidates, q);

  const renderHits = () => {
    const list = filtered();
    if (!candidates.length) return `<div class="picker-empty">Everyone in the org is already on this project.</div>`;
    if (!list.length) return `<div class="picker-empty">No matches.</div>`;
    return list
      .map((m) => {
        const on = picked.has(m.id);
        return `<button type="button" class="picker-hit ${on ? "picked" : ""}" data-uid="${m.id}">
          <span class="who">${on ? "✓ " : ""}${esc(m.name)}</span>
          <span class="hint">${esc(m.email)} · org ${esc(m.role)}</span>
        </button>`;
      })
      .join("");
  };

  const paintModal = () => {
    modal(
      `<h3>Mass add project members</h3>
      <p class="sub">Pick people already in this organization who are not on the project yet.</p>
      <label>Search org members</label>
      <input class="field share-search" id="massProjQ" type="search" placeholder="Name or email…" value="${esc(q)}" autocomplete="off">
      <div class="picker-panel" id="massProjPicker">${renderHits()}</div>
      <label>Project role</label>
      <select class="field" id="massProjRole"><option value="member">Project member</option><option value="admin">Project Owner</option></select>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Add selected (${picked.size})</button>
      </div>`,
      { size: "wide" }
    );
    $("mCancel").onclick = closeModal;
    const input = $("massProjQ");
    input.focus();
    input.oninput = () => {
      q = input.value;
      $("massProjPicker").innerHTML = renderHits();
      wireHits();
    };
    const wireHits = () => {
      document.querySelectorAll("#massProjPicker [data-uid]").forEach((b) => {
        b.onclick = () => {
          if (picked.has(b.dataset.uid)) picked.delete(b.dataset.uid);
          else picked.add(b.dataset.uid);
          paintModal();
        };
      });
    };
    wireHits();
    $("mOk").onclick = async () => {
      if (!picked.size) return toast("Select at least one person.");
      try {
        const res = await api(`/projects/${state.project.id}/members/bulk`, {
          method: "POST",
          body: { userIds: [...picked], role: $("massProjRole").value },
        });
        closeModal();
        await openProject(state.project.id);
        toast(`Added ${res.added?.length || 0}, updated ${res.updated?.length || 0}, skipped ${res.skipped?.length || 0}.`);
      } catch (e) {
        toast(e.message);
      }
    };
  };

  paintModal();
}

function openOffboardFolders() {
  const pool = [
    ...(state.members || []).map((m) => ({ ...m, source: "project" })),
  ];
  // Also allow org people who might only be on folder ACLs historically
  for (const m of state.orgMembers || []) {
    if (!pool.some((p) => p.id === m.id)) pool.push({ ...m, source: "org" });
  }
  let q = "";
  let selectedId = null;

  const renderHits = () => {
    const list = matchPeople(pool, q);
    if (!list.length) return `<div class="picker-empty">No matches.</div>`;
    return list
      .map((m) => {
        const on = selectedId === m.id;
        return `<button type="button" class="picker-hit ${on ? "picked" : ""}" data-uid="${m.id}">
          <span class="who">${on ? "✓ " : ""}${esc(m.name)}</span>
          <span class="hint">${esc(m.email)}</span>
        </button>`;
      })
      .join("");
  };

  const paintModal = () => {
    modal(
      `<h3>Offboard from folder shares</h3>
      <p class="sub">Strip this user from every folder ACL (and their file ACL overrides) in this project. Does not remove them from the project itself. Folder creators are skipped on their own folders.</p>
      <label>Search people</label>
      <input class="field share-search" id="offboardQ" type="search" placeholder="Name or email…" value="${esc(q)}" autocomplete="off">
      <div class="picker-panel" id="offboardPicker">${renderHits()}</div>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
        <button class="btn btn-primary btn-danger" style="width:auto;margin:0" type="button" id="mOk">Offboard from folders</button>
      </div>`,
      { size: "wide" }
    );
    $("mCancel").onclick = closeModal;
    const input = $("offboardQ");
    input.focus();
    input.oninput = () => {
      q = input.value;
      $("offboardPicker").innerHTML = renderHits();
      wireHits();
    };
    const wireHits = () => {
      document.querySelectorAll("#offboardPicker [data-uid]").forEach((b) => {
        b.onclick = () => {
          selectedId = b.dataset.uid;
          paintModal();
        };
      });
    };
    wireHits();
    $("mOk").onclick = async () => {
      if (!selectedId) return toast("Pick a person.");
      const person = pool.find((m) => m.id === selectedId);
      if (!confirm(`Remove folder/file ACL for ${person?.name || "this user"} across the project?`)) return;
      try {
        const res = await api(`/projects/${state.project.id}/offboard-folders`, {
          method: "POST",
          body: { userId: selectedId },
        });
        closeModal();
        await openProject(state.project.id);
        toast(
          `Removed ${res.folderAclRemoved || 0} folder grant(s), ${res.fileAclRemoved || 0} file override(s)${
            res.foldersSkippedCreator ? ` · skipped ${res.foldersSkippedCreator} creator folder(s)` : ""
          }.`
        );
      } catch (e) {
        toast(e.message);
      }
    };
  };

  paintModal();
}

function openCopyFolderAcl() {
  const manageable = state.folders.filter((f) => f.canManageAcl);
  if (manageable.length < 2) return toast("Need at least two folders you can manage.");
  let sourceId = manageable[0].id;
  let targets = new Set(
    state.selectedFolderIds.filter((id) => id !== sourceId && manageable.some((f) => f.id === id))
  );

  const paintModal = () => {
    const sourceOpts = manageable
      .map((f) => `<option value="${f.id}" ${f.id === sourceId ? "selected" : ""}>${esc(f.name)}</option>`)
      .join("");
    const targetRows = manageable
      .filter((f) => f.id !== sourceId)
      .map(
        (f) => `<label class="share-row" style="cursor:pointer">
        <input type="checkbox" data-ct="${f.id}" ${targets.has(f.id) ? "checked" : ""}>
        <span class="who">${esc(f.name)}</span>
      </label>`
      )
      .join("");
    modal(
      `<h3>Copy folder share</h3>
      <p class="sub">Copy the share list from one folder onto other folders you manage (replaces their current grants).</p>
      <label>Source folder</label>
      <select class="field" id="copySource">${sourceOpts}</select>
      <h4 style="margin:12px 0 8px;font-size:13px">Target folders</h4>
      <div class="share-list" style="max-height:220px">${targetRows}</div>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Copy share list</button>
      </div>`,
      { size: "wide" }
    );
    $("mCancel").onclick = closeModal;
    $("copySource").onchange = () => {
      sourceId = $("copySource").value;
      targets.delete(sourceId);
      paintModal();
    };
    document.querySelectorAll("[data-ct]").forEach((c) => {
      c.onchange = () => {
        if (c.checked) targets.add(c.dataset.ct);
        else targets.delete(c.dataset.ct);
      };
    });
    $("mOk").onclick = async () => {
      document.querySelectorAll("[data-ct]").forEach((c) => {
        if (c.checked) targets.add(c.dataset.ct);
        else targets.delete(c.dataset.ct);
      });
      if (!targets.size) return toast("Select at least one target folder.");
      try {
        const res = await api(`/projects/${state.project.id}/folders/acl/copy`, {
          method: "POST",
          body: { sourceFolderId: sourceId, targetFolderIds: [...targets] },
        });
        closeModal();
        state.selectedFolderIds = [];
        await openProject(state.project.id);
        toast(`Updated ${res.applied?.length || 0} folder(s)${res.skipped?.length ? `, skipped ${res.skipped.length}` : ""}.`);
      } catch (e) {
        toast(e.message);
      }
    };
  };

  paintModal();
}

async function resetSelectedFilesAcl() {
  if (!state.selectedFileIds.length) return toast("Select one or more files first.");
  if (!confirm(`Reset ${state.selectedFileIds.length} file(s) to inherit the folder share list?`)) return;
  try {
    const res = await api(`/folders/${state.folderId}/files/acl/reset`, {
      method: "POST",
      body: { fileIds: state.selectedFileIds },
    });
    state.selectedFileIds = [];
    await loadFiles();
    paint();
    toast(`Reset ${res.applied?.length || 0} file(s)${res.skipped?.length ? `, skipped ${res.skipped.length}` : ""}.`);
  } catch (e) {
    toast(e.message);
  }
}

async function bulkDeleteSelectedFiles() {
  if (!state.selectedFileIds.length) return toast("Select one or more files first.");
  if (!confirm(`Delete ${state.selectedFileIds.length} selected file(s)? This cannot be undone.`)) return;
  try {
    const res = await api(`/folders/${state.folderId}/files/bulk-delete`, {
      method: "POST",
      body: { fileIds: state.selectedFileIds },
    });
    state.selectedFileIds = [];
    await loadFiles();
    paint();
    toast(`Deleted ${res.deleted?.length || 0}${res.skipped?.length ? `, skipped ${res.skipped.length}` : ""}.`);
  } catch (e) {
    toast(e.message);
  }
}

/** Mass share: same grants applied to all checked folders. */
async function openBulkFolderAcl() {
  const manageable = state.folders.filter((f) => f.canManageAcl);
  let selected = new Set(
    state.selectedFolderIds.length
      ? state.selectedFolderIds.filter((id) => manageable.some((f) => f.id === id))
      : manageable.map((f) => f.id)
  );
  let folderMembers = [];
  let searchQ = "";
  let pendingAccess = "read";

  const available = () => {
    const on = new Set(folderMembers.map((m) => m.userId));
    return state.members.filter((m) => !on.has(m.id));
  };

  const renderPickerHits = () => {
    const needle = (searchQ || "").trim();
    const pool = available();
    if (needle.length < 2) {
      return `<div class="picker-empty">Type a name or email to add people to the share list (${pool.length} available).</div>`;
    }
    const hits = matchPeople(pool, needle);
    if (!hits.length) return `<div class="picker-empty">No matches.</div>`;
    return hits
      .map(
        (m) => `<button type="button" class="picker-hit" data-pick="${m.id}">
        <span class="who">${esc(m.name)}</span><span class="hint">${esc(m.email)}</span>
      </button>`
      )
      .join("");
  };

  const renderBody = () => {
    const folderChecks = manageable
      .map(
        (f) => `<label class="share-row" style="cursor:pointer">
        <input type="checkbox" data-bf="${f.id}" ${selected.has(f.id) ? "checked" : ""}>
        <span class="who">${esc(f.name)}</span>
      </label>`
      )
      .join("");
    const rows = folderMembers
      .map(
        (m) => `<div class="share-row">
        <div class="who-block"><span class="who">${esc(m.name)}</span><span class="hint">${esc(m.email)}</span></div>
        <select class="field" style="width:auto;margin:0" data-access="${m.userId}">
          <option value="read" ${m.access === "read" ? "selected" : ""}>Read only</option>
          <option value="edit" ${m.access === "edit" ? "selected" : ""}>Can edit (RW)</option>
        </select>
        <button class="btn btn-quiet btn-danger" type="button" style="width:auto;margin:0" data-drop="${m.userId}">Remove</button>
      </div>`
      )
      .join("");
    return `<h3>Mass share folders</h3>
      <p class="sub">Pick folders, build one share list, apply the same Read only / Can edit grants to every selected folder.</p>
      <h4 style="margin:8px 0;font-size:13px">Folders</h4>
      <div class="share-list" style="max-height:140px">${folderChecks || '<p class="fine" style="padding:12px">No folders you can manage.</p>'}</div>
      <div class="share-add" style="margin-top:14px">
        <div class="share-add-row">
          <input class="field share-search" id="bulkFolderSearch" type="search" placeholder="Search project members…" value="${esc(searchQ)}" style="margin:0;flex:1">
          <select class="field" id="bulkFolderAccess" style="width:auto;margin:0">
            <option value="read" ${pendingAccess === "read" ? "selected" : ""}>Read only</option>
            <option value="edit" ${pendingAccess === "edit" ? "selected" : ""}>Can edit (RW)</option>
          </select>
        </div>
        <div class="picker-panel" id="bulkFolderPicker">${renderPickerHits()}</div>
      </div>
      <div class="share-list" style="margin-top:12px">${rows || '<p class="fine" style="padding:12px">Add people above.</p>'}</div>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Apply to selected folders</button>
      </div>`;
  };

  const paintModal = () => {
    modal(renderBody(), { size: "wide" });
    $("mCancel").onclick = closeModal;
    document.querySelectorAll("[data-bf]").forEach((c) => {
      c.onchange = () => {
        if (c.checked) selected.add(c.dataset.bf);
        else selected.delete(c.dataset.bf);
      };
    });
    const search = $("bulkFolderSearch");
    search.focus();
    search.oninput = () => {
      searchQ = search.value;
      pendingAccess = $("bulkFolderAccess").value;
      $("bulkFolderPicker").innerHTML = renderPickerHits();
      wirePicker();
    };
    $("bulkFolderAccess").onchange = () => {
      pendingAccess = $("bulkFolderAccess").value;
    };
    const wirePicker = () => {
      document.querySelectorAll("#bulkFolderPicker [data-pick]").forEach((b) => {
        b.onclick = () => {
          pendingAccess = $("bulkFolderAccess").value || "read";
          const person = state.members.find((m) => m.id === b.dataset.pick);
          if (!person) return;
          if (folderMembers.some((m) => m.userId === person.id)) return toast("Already on the list.");
          folderMembers.push({
            userId: person.id,
            name: person.name,
            email: person.email,
            access: pendingAccess,
          });
          searchQ = "";
          paintModal();
        };
      });
    };
    wirePicker();
    document.querySelectorAll("[data-drop]").forEach((b) => {
      b.onclick = () => {
        folderMembers = folderMembers.filter((m) => m.userId !== b.dataset.drop);
        paintModal();
      };
    });
    document.querySelectorAll("[data-access]").forEach((s) => {
      s.onchange = () => {
        const row = folderMembers.find((m) => m.userId === s.dataset.access);
        if (row) row.access = s.value;
      };
    });
    $("mOk").onclick = async () => {
      document.querySelectorAll("[data-bf]").forEach((c) => {
        if (c.checked) selected.add(c.dataset.bf);
        else selected.delete(c.dataset.bf);
      });
      document.querySelectorAll("[data-access]").forEach((s) => {
        const row = folderMembers.find((m) => m.userId === s.dataset.access);
        if (row) row.access = s.value;
      });
      if (!selected.size) return toast("Select at least one folder.");
      if (!folderMembers.length) return toast("Add at least one person to the share list.");
      try {
        const res = await api(`/projects/${state.project.id}/folders/acl/bulk`, {
          method: "POST",
          body: {
            folderIds: [...selected],
            grants: folderMembers.map((m) => ({ userId: m.userId, access: m.access })),
          },
        });
        closeModal();
        state.selectedFolderIds = [];
        await openProject(state.project.id);
        toast(`Updated ${res.applied?.length || 0} folder(s)${res.skipped?.length ? `, skipped ${res.skipped.length}` : ""}.`);
      } catch (e) {
        toast(e.message);
      }
    };
  };

  paintModal();
}

/** Mass file ACL for checked files in the current folder. */
async function openBulkFileAcl() {
  if (!state.selectedFileIds.length) return toast("Select one or more files first.");
  const folder = state.folders.find((f) => f.id === state.folderId);
  if (!folder?.canManageAcl) return toast("You cannot manage permissions here.");

  // Seed people from folder audience via any manageable file ACL endpoint, or folder members list
  let people = [];
  try {
    const sampleId = state.selectedFileIds[0];
    const acl = await api(`/files/${sampleId}/acl`);
    people = (acl.people || []).filter((p) => !p.locked);
  } catch (e) {
    toast(e.message);
    return;
  }

  let inherit = true;
  const overrides = new Map();
  for (const p of people) {
    overrides.set(p.userId, p.folderAccess === "edit" ? "edit" : "read");
  }
  let filterQ = "";

  const renderPeople = () => {
    const list = matchPeople(people, filterQ);
    if (!people.length) {
      return `<p class="fine" style="padding:12px">Share the folder with people first.</p>`;
    }
    if (!list.length) return `<p class="fine" style="padding:12px">No matches.</p>`;
    return list
      .map((p) => {
        const cur = overrides.get(p.userId) || "read";
        return `<div class="share-row">
          <div class="who-block"><span class="who">${esc(p.name)}</span>
            <span class="hint">${esc(p.email)} · folder: ${p.folderAccess === "edit" ? "edit" : "read"}</span></div>
          <select class="field" style="width:auto;margin:0" data-file-uid="${p.userId}" ${inherit ? "disabled" : ""}>
            <option value="read" ${cur === "read" ? "selected" : ""}>This file: Read only</option>
            <option value="edit" ${cur === "edit" ? "selected" : ""}>This file: Can edit</option>
            <option value="edit_delete" ${cur === "edit_delete" ? "selected" : ""}>This file: Can edit + delete</option>
            <option value="none" ${cur === "none" ? "selected" : ""}>No access to this file</option>
          </select>
        </div>`;
      })
      .join("");
  };

  const paintModal = () => {
    modal(
      `<h3>Mass file permissions</h3>
      <p class="sub">Applies the same ACL to <strong>${state.selectedFileIds.length}</strong> selected file(s) in this folder.</p>
      <div class="switch-row"><input type="checkbox" id="inherit" ${inherit ? "checked" : ""}><label for="inherit" style="margin:0">Same as folder</label></div>
      <input class="field share-search" id="bulkFileSearch" type="search" placeholder="Filter folder members…" value="${esc(filterQ)}" ${
        people.length ? "" : "disabled"
      }>
      <div class="share-list" id="aclPeople">${renderPeople()}</div>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Apply to selected files</button>
      </div>`,
      { size: "wide" }
    );
    $("mCancel").onclick = closeModal;
    $("inherit").onchange = () => {
      inherit = $("inherit").checked;
      paintModal();
    };
    const search = $("bulkFileSearch");
    if (search && !search.disabled) {
      search.oninput = () => {
        filterQ = search.value;
        document.querySelectorAll("[data-file-uid]").forEach((s) => overrides.set(s.dataset.fileUid, s.value));
        $("aclPeople").innerHTML = renderPeople();
        wirePeople();
      };
    }
    const wirePeople = () => {
      document.querySelectorAll("[data-file-uid]").forEach((s) => {
        s.onchange = () => overrides.set(s.dataset.fileUid, s.value);
      });
    };
    wirePeople();
    $("mOk").onclick = async () => {
      document.querySelectorAll("[data-file-uid]").forEach((s) => overrides.set(s.dataset.fileUid, s.value));
      const grants = people.map((p) => ({
        userId: p.userId,
        access: overrides.get(p.userId) || "read",
      }));
      try {
        const res = await api(`/folders/${state.folderId}/files/acl/bulk`, {
          method: "POST",
          body: { fileIds: state.selectedFileIds, inherit, grants: inherit ? [] : grants },
        });
        closeModal();
        state.selectedFileIds = [];
        await loadFiles();
        paint();
        toast(`Updated ${res.applied?.length || 0} file(s)${res.skipped?.length ? `, skipped ${res.skipped.length}` : ""}.`);
      } catch (e) {
        toast(e.message);
      }
    };
  };

  paintModal();
}

async function openFolderAcl() {
  let aclData;
  try {
    aclData = await api(`/folders/${state.folderId}/acl`);
  } catch (e) {
    toast(e.message);
    return;
  }
  let folderMembers = (aclData.grants || []).map((g) => ({
    userId: g.userId,
    name: g.name,
    email: g.email,
    access: g.access,
  }));
  const creatorId = aclData.creator?.userId;
  let searchQ = "";
  let pendingAccess = "read";

  const available = () => {
    const onFolder = new Set(folderMembers.map((m) => m.userId));
    if (creatorId) onFolder.add(creatorId);
    return state.members.filter((m) => !onFolder.has(m.id));
  };

  const renderPickerHits = () => {
    const needle = (searchQ || "").trim();
    const pool = available();
    if (!pool.length) {
      return `<div class="picker-empty">Everyone eligible is already on this folder.</div>`;
    }
    if (needle.length < 2) {
      return `<div class="picker-empty">Type a name or email to find someone — results stay hidden until you search (${pool.length} project member${pool.length === 1 ? "" : "s"} not on this folder yet).</div>`;
    }
    const hits = matchPeople(pool, needle);
    if (!hits.length) {
      return `<div class="picker-empty">No matches.</div>`;
    }
    return hits
      .map(
        (m) => `<button type="button" class="picker-hit" data-pick="${m.id}">
          <span class="who">${esc(m.name)}</span>
          <span class="hint">${esc(m.email)}</span>
        </button>`
      )
      .join("");
  };

  const wirePicker = () => {
    document.querySelectorAll("#folderPicker [data-pick]").forEach((b) => {
      b.onclick = () => {
        pendingAccess = $("addFolderAccess")?.value || pendingAccess;
        const person = state.members.find((m) => m.id === b.dataset.pick);
        if (!person) return;
        if (person.id === creatorId || folderMembers.some((m) => m.userId === person.id)) {
          toast("Already on this folder.");
          return;
        }
        folderMembers.push({
          userId: person.id,
          name: person.name,
          email: person.email,
          access: pendingAccess,
        });
        searchQ = "";
        paintModal();
      };
    });
  };

  const syncPicker = () => {
    const panel = $("folderPicker");
    if (!panel) return;
    panel.innerHTML = renderPickerHits();
    wirePicker();
  };

  const renderBody = () => {
    const rows = [];
    if (aclData.creator) {
      rows.push(`<div class="share-row locked"><div class="who-block"><span class="who">${esc(aclData.creator.name)} <span class="fmeta">(creator)</span></span>
        <span class="hint">${esc(aclData.creator.email || "")}</span></div>
        <span class="fmeta">Can edit · always</span></div>`);
    }
    for (const m of folderMembers) {
      if (m.userId === creatorId) continue;
      rows.push(`<div class="share-row">
        <div class="who-block"><span class="who">${esc(m.name)}</span><span class="hint">${esc(m.email)}</span></div>
        <select class="field" style="width:auto;margin:0" data-access="${m.userId}">
          <option value="read" ${m.access === "read" ? "selected" : ""}>Read only</option>
          <option value="edit" ${m.access === "edit" ? "selected" : ""}>Can edit (RW)</option>
        </select>
        <button class="btn btn-quiet btn-danger" type="button" style="width:auto;margin:0" data-drop="${m.userId}">Remove</button>
      </div>`);
    }
    return `<h3>Share folder</h3>
      <p class="sub">Search project members, add them, then set Read only or Can edit per person. Project Owners always have access.</p>
      <div class="share-add">
        <div class="share-add-row">
          <input class="field share-search" id="folderMemberSearch" type="search" placeholder="Search by name or email…" value="${esc(searchQ)}" autocomplete="off" style="margin:0;flex:1">
          <select class="field" id="addFolderAccess" style="width:auto;margin:0">
            <option value="read" ${pendingAccess === "read" ? "selected" : ""}>Read only</option>
            <option value="edit" ${pendingAccess === "edit" ? "selected" : ""}>Can edit (RW)</option>
          </select>
        </div>
        <div class="picker-panel" id="folderPicker">${renderPickerHits()}</div>
      </div>
      <div class="share-list" style="margin-top:14px">${rows.join("") || `<p class="fine" style="padding:12px">Only the creator (and Project Owners) can open this folder.</p>`}</div>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Save</button>
      </div>`;
  };

  const paintModal = () => {
    modal(renderBody(), { size: "wide" });
    $("mCancel").onclick = closeModal;
    const search = $("folderMemberSearch");
    search.focus();
    const pos = search.value.length;
    search.setSelectionRange(pos, pos);
    search.oninput = () => {
      searchQ = search.value;
      syncPicker();
    };
    $("addFolderAccess").onchange = () => {
      pendingAccess = $("addFolderAccess").value || "read";
    };
    wirePicker();
    document.querySelectorAll("[data-drop]").forEach((b) => {
      b.onclick = () => {
        folderMembers = folderMembers.filter((m) => m.userId !== b.dataset.drop);
        paintModal();
      };
    });
    document.querySelectorAll("[data-access]").forEach((s) => {
      s.onchange = () => {
        const row = folderMembers.find((m) => m.userId === s.dataset.access);
        if (row) row.access = s.value;
      };
    });
    $("mOk").onclick = async () => {
      document.querySelectorAll("[data-access]").forEach((s) => {
        const row = folderMembers.find((m) => m.userId === s.dataset.access);
        if (row) row.access = s.value;
      });
      const grants = folderMembers
        .filter((m) => m.userId !== creatorId)
        .map((m) => ({ userId: m.userId, access: m.access }));
      try {
        await api(`/folders/${state.folderId}/acl`, { method: "POST", body: { grants } });
        closeModal();
        await openProject(state.project.id);
        toast("Folder members updated.");
      } catch (e) {
        toast(e.message);
      }
    };
  };

  paintModal();
}

async function openBackupManager() {
  let data;
  try {
    data = await api("/admin/backups");
  } catch (e) {
    toast(e.message);
    return;
  }
  const rows = (data.backups || [])
    .map(
      (b) => `<div class="share-row">
      <div class="who-block">
        <span class="who">${esc(b.id)}</span>
        <span class="hint">${b.createdAt ? esc(new Date(b.createdAt).toLocaleString()) : "—"} · ${
          b.ok ? "ok" : "incomplete"
        } · ${fmtSize(b.sizeBytes || 0)}</span>
      </div>
      <span class="row-actions">
        <button class="btn btn-quiet" type="button" data-verify-backup="${esc(b.id)}" style="width:auto;margin:0">Verify</button>
        <button class="btn btn-quiet btn-danger" type="button" data-restore-backup="${esc(b.id)}" style="width:auto;margin:0">Restore</button>
      </span>
    </div>`
    )
    .join("");
  modal(
    `<h3>Backups</h3>
    <p class="sub">Stored on the server Disk under backups/. Restore stages data then restarts the service.</p>
    <div class="share-list">${rows || `<p class="fine" style="padding:12px">No backups yet — run one first.</p>`}</div>
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="mCancel">Close</button>
      <button class="btn btn-primary" type="button" id="mRunBackup" style="width:auto;margin:0">Run backup now</button>
    </div>`,
    { size: "wide" }
  );
  $("mCancel").onclick = closeModal;
  $("mRunBackup").onclick = async () => {
    try {
      const res = await api("/admin/backup", { method: "POST" });
      toast("Backup created: " + res.path);
      closeModal();
      openBackupManager();
    } catch (e) {
      toast(e.message);
    }
  };
  document.querySelectorAll("[data-verify-backup]").forEach((b) => {
    b.onclick = async () => {
      try {
        const res = await api(`/admin/backups/${encodeURIComponent(b.dataset.verifyBackup)}/verify`, {
          method: "POST",
        });
        toast(res.ok ? `Verified ${res.id}` : `Invalid: ${(res.errors || []).join("; ")}`);
      } catch (e) {
        toast(e.message);
      }
    };
  });
  document.querySelectorAll("[data-restore-backup]").forEach((b) => {
    b.onclick = async () => {
      if (
        !confirm(
          `Restore ${b.dataset.restoreBackup}? Current data is safety-copied, then the service restarts.`
        )
      )
        return;
      try {
        await api(`/admin/backups/${encodeURIComponent(b.dataset.restoreBackup)}/restore`, {
          method: "POST",
        });
        toast("Restore staged — waiting for restart…");
        closeModal();
      } catch (e) {
        toast(e.message);
      }
    };
  });
}

async function openFileAcl(fileId) {
  let acl;
  try {
    acl = await api(`/files/${fileId}/acl`);
  } catch (e) {
    toast(e.message);
    return;
  }
  let inherit = !!acl.inherit;
  const overrides = new Map();
  for (const p of acl.people || []) {
    if (p.fileAccess) overrides.set(p.userId, p.fileAccess);
    else overrides.set(p.userId, p.folderAccess === "edit" ? "edit" : "read");
  }
  let filterQ = "";

  const renderPeople = () => {
    const people = matchPeople(acl.people || [], filterQ);
    if (!(acl.people || []).length) {
      return `<p class="fine" style="padding:12px">No other folder members to set — share the folder with people first. Your own access is not listed here.</p>`;
    }
    if (!people.length) return `<p class="fine" style="padding:12px">No matches.</p>`;
    return people
      .map((p) => {
        const cur = overrides.get(p.userId) || "read";
        if (p.locked) {
          return `<div class="share-row locked"><div class="who-block"><span class="who">${esc(p.name)} <span class="fmeta">(creator)</span></span>
            <span class="hint">${esc(p.email || "")}</span></div>
            <span class="fmeta">Full access · always</span></div>`;
        }
        return `<div class="share-row">
          <div class="who-block"><span class="who">${esc(p.name)}</span>
            <span class="hint">${esc(p.email)} · folder stays: ${p.folderAccess === "edit" ? "Can edit (uploads OK)" : "Read only"}</span></div>
          <select class="field" style="width:auto;margin:0" data-file-uid="${p.userId}" ${inherit ? "disabled" : ""}>
            <option value="read" ${cur === "read" ? "selected" : ""}>This file: Read only</option>
            <option value="edit" ${cur === "edit" ? "selected" : ""}>This file: Can edit</option>
            <option value="edit_delete" ${cur === "edit_delete" ? "selected" : ""}>This file: Can edit + delete</option>
            <option value="none" ${cur === "none" ? "selected" : ""}>No access to this file</option>
          </select>
        </div>`;
      })
      .join("");
  };

  const wirePeople = () => {
    document.querySelectorAll("[data-file-uid]").forEach((s) => {
      s.onchange = () => overrides.set(s.dataset.fileUid, s.value);
    });
  };

  const syncPeople = () => {
    const box = $("aclPeople");
    if (!box) return;
    box.innerHTML = renderPeople();
    wirePeople();
  };

  const renderBody = () => `<h3>File permissions</h3>
      <p class="sub">Applies to <strong>${esc(acl.file?.name || "this file")}</strong> only — other people on this folder. You cannot change your own access here. Project Owner / folder creator can revoke an uploader (including No access). <em>Can edit + delete</em> shows Delete for that person.</p>
      <div class="switch-row"><input type="checkbox" id="inherit" ${inherit ? "checked" : ""}><label for="inherit" style="margin:0">Same as folder</label></div>
      <input class="field share-search" id="fileAclSearch" type="search" placeholder="Filter folder members…" value="${esc(filterQ)}" autocomplete="off" ${!(acl.people || []).length ? "disabled" : ""}>
      <div class="share-list" id="aclPeople">${renderPeople()}</div>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Save</button>
      </div>`;

  const paintModal = () => {
    modal(renderBody(), { size: "wide" });
    $("mCancel").onclick = closeModal;
    $("inherit").onchange = () => {
      inherit = $("inherit").checked;
      paintModal();
    };
    const search = $("fileAclSearch");
    if (search && !search.disabled) {
      search.focus();
      const pos = search.value.length;
      search.setSelectionRange(pos, pos);
      search.oninput = () => {
        filterQ = search.value;
        syncPeople();
      };
    }
    wirePeople();
    $("mOk").onclick = async () => {
      document.querySelectorAll("[data-file-uid]").forEach((s) => {
        overrides.set(s.dataset.fileUid, s.value);
      });
      const grants = (acl.people || [])
        .filter((p) => !p.locked)
        .map((p) => ({ userId: p.userId, access: overrides.get(p.userId) || "read" }));
      try {
        await api(`/files/${fileId}/acl`, {
          method: "POST",
          body: { inherit, grants: inherit ? [] : grants },
        });
        closeModal();
        // Reload folders so folder access badge cannot drift; file ACL must not demote it.
        if (state.project?.id) {
          const proj = await api(`/projects/${state.project.id}?sync=1`);
          state.folders = proj.folders;
        }
        await loadFiles();
        paint();
        toast("File permissions saved (folder upload rights unchanged).");
      } catch (e) {
        toast(e.message);
      }
    };
  };

  paintModal();
}

async function confirmRestoreVersion(fileId, version, { fileName = "", onDone } = {}) {
  modal(`<h3>Restore version ${version}?</h3>
    <p class="sub">This copies <strong>v${version}</strong>${
      fileName ? ` of <strong>${esc(fileName)}</strong>` : ""
    } forward as a <strong>new</strong> current version. Full history is kept.</p>
    <label>Note (optional, saved in audit)</label>
    <input class="field" id="restoreNote" maxlength="500" placeholder="e.g. rolled back bad config change">
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="mCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mOk">Restore as new version</button>
    </div>`);
  $("mCancel").onclick = closeModal;
  $("mOk").onclick = async () => {
    try {
      const res = await api(`/files/${fileId}/versions/restore`, {
        method: "POST",
        body: { version, note: $("restoreNote")?.value || "" },
      });
      closeModal();
      await loadFiles();
      paint();
      toast(`Restored v${res.restoredFrom} → new v${res.newVersion}.`);
      if (onDone) await onDone(res);
    } catch (e) {
      toast(e.message);
    }
  };
}

async function openVersions(fileId) {
  const res = await api(`/files/${fileId}/versions`);
  const canRestore = !!res.canRestore;
  modal(
    `<h3>Versions${res.name ? ` — ${esc(res.name)}` : ""}</h3>
    <p class="sub">Current: v${res.currentVersion}. Restore copies an older version forward as a new tip.</p>
    ${res.versions
      .map(
        (v) => `<div class="file-row">
      <span class="fname">v${v.version}${v.isCurrent ? ' <span class="lang-tag">current</span>' : ""}</span>
      <span class="fmeta">${fmtSize(v.size)} · ${esc(v.created_by_name)} · ${new Date(v.created_at).toLocaleString()}</span>
      <span class="row-actions">
        <button class="btn btn-quiet" type="button" data-ov="${v.version}">Open</button>
        ${
          canRestore && !v.isCurrent
            ? `<button class="btn btn-quiet" type="button" data-restore="${v.version}">Restore</button>`
            : ""
        }
      </span>
    </div>`
      )
      .join("")}
    <div class="modal-actions"><button class="btn btn-primary" style="width:auto;margin:0" type="button" id="mDone">Close</button></div>`
  );
  $("mDone").onclick = closeModal;
  document.querySelectorAll("[data-ov]").forEach((b) => {
    b.onclick = () => openFile(fileId, false, Number(b.dataset.ov));
  });
  document.querySelectorAll("[data-restore]").forEach((b) => {
    b.onclick = () =>
      confirmRestoreVersion(fileId, Number(b.dataset.restore), {
        fileName: res.name || "",
        onDone: async () => openVersions(fileId),
      });
  });
}

async function openFile(fileId, wantEdit, version = null) {
  const q = version ? `?version=${version}` : "";
  const data = await api(`/files/${fileId}/content${q}`);
  const langLabel = fileLanguageLabel({ language: data.language, name: data.name });
  const monacoLang = data.monacoLanguage || detectLanguage(data.name, data.text || "").id || "plaintext";
  const useIde = data.text != null && (data.isCode || monacoLang !== "plaintext" || !!wantEdit);
  const editing = wantEdit && data.access === "edit" && data.text != null;
  const storedDiags = Array.isArray(data.diagnostics) ? data.diagnostics : [];
  let diags = storedDiags;
  // Always re-lint current text on open (stored meta can be stale / too weak)
  if (data.text != null && (data.isCode || monacoLang !== "plaintext")) {
    try {
      const live = await api(`/files/${fileId}/diagnostics`, {
        method: "POST",
        body: { text: data.text, filename: data.name },
      });
      diags = live.diagnostics || storedDiags;
    } catch {
      /* keep stored */
    }
  }
  const errN = diags.filter((d) => d.severity === "error").length;
  const warnN = diags.filter((d) => d.severity === "warning").length;

  modal(
    `<div class="viewer-head">
      <div>
        <h3 class="viewer-title">${esc(data.name)} <span class="lang-tag">${esc(langLabel)}</span>${
          data.isCode ? ' <span class="code-badge">code</span>' : ""
        }</h3>
        <p class="sub">Version ${data.version}${
          data.currentVersion != null && data.version !== data.currentVersion
            ? ` (current is v${data.currentVersion})`
            : ""
        } · ${fmtSize(data.size)} · ${esc(data.access)}${
          editing ? " · IDE editing" : useIde ? " · code preview" : " · preview"
        }${data.formatStatus ? ` · format: ${esc(data.formatStatus)}` : ""}</p>
      </div>
    </div>
    ${
      useIde
        ? `<div class="monaco-host file-viewer-body" id="monacoHost"></div>
           <div class="diag-bar" id="diagBar">${
             errN || warnN
               ? `<span class="diag-err">${errN} error(s)</span> · <span class="diag-warn">${warnN} warning(s)</span>`
               : `<span class="diag-ok">No syntax issues</span>`
           }</div>`
        : `<pre class="file-viewer-body hljs"><code id="filePreview"></code></pre>`
    }
    <div class="modal-actions">
      ${editing ? `<button class="btn btn-primary" style="width:auto;margin:0" type="button" id="pvSave">Save new version</button>` : ""}
      ${
        !editing && data.access === "edit" && data.text != null
          ? `<button class="btn btn-quiet" style="width:auto;margin:0" type="button" id="pvEdit">Edit in IDE</button>`
          : ""
      }
      ${
        data.access === "edit" && data.version !== data.currentVersion
          ? `<button class="btn btn-quiet" style="width:auto;margin:0" type="button" id="pvRestore">Restore this version</button>`
          : ""
      }
      ${
        data.canDelete
          ? `<button class="btn btn-quiet btn-danger" style="width:auto;margin:0" type="button" id="pvDelete">Delete file</button>`
          : ""
      }
      <button class="btn btn-quiet" type="button" id="mDone">Close</button>
    </div>`,
    { size: "modal-viewer" }
  );

  let ide = null;
  const updateDiagBar = (list) => {
    const bar = $("diagBar");
    if (!bar) return;
    const e = (list || []).filter((d) => d.severity === "error").length;
    const w = (list || []).filter((d) => d.severity === "warning").length;
    bar.innerHTML =
      e || w
        ? `<span class="diag-err">${e} error(s)</span> · <span class="diag-warn">${w} warning(s)</span>`
        : `<span class="diag-ok">No syntax issues</span>`;
  };

  const runLiveDiagnostics = () => {
    if (!ide) return;
    if (state.diagTimer) clearTimeout(state.diagTimer);
    state.diagTimer = setTimeout(async () => {
      try {
        const res = await api(`/files/${fileId}/diagnostics`, {
          method: "POST",
          body: { text: ide.getValue(), filename: data.name },
        });
        applyDiagnostics(ide.monaco, ide.editor, "config-rooms", res.diagnostics || []);
        updateDiagBar(res.diagnostics || []);
      } catch {
        /* ignore live diag failures */
      }
    }, 450);
  };

  if (useIde && $("monacoHost")) {
    try {
      ide = await createCodeEditor($("monacoHost"), {
        value: data.text || "",
        language: monacoLang,
        readOnly: !editing,
      });
      state.activeEditorDispose = () => ide.dispose();
      applyDiagnostics(ide.monaco, ide.editor, "config-rooms", diags);
      updateDiagBar(diags);
      if (editing) {
        ide.editor.onDidChangeModelContent(() => runLiveDiagnostics());
      } else {
        // One more pass with editor buffer (normalized newlines etc.)
        runLiveDiagnostics();
      }
    } catch (e) {
      // Fallback textarea if Monaco CDN blocked
      $("monacoHost").outerHTML = `<textarea class="file-viewer-body file-editor" id="fileEditor" spellcheck="false"></textarea>`;
      if ($("fileEditor")) {
        $("fileEditor").value = data.text || "";
        $("fileEditor").readOnly = !editing;
      }
      toast("Monaco unavailable — using plain editor. " + (e.message || ""));
    }
  } else if ($("filePreview")) {
    const raw = data.text ?? "(binary file — preview not available)";
    highlightCode($("filePreview"), raw, monacoLang);
  }

  if (editing) {
    $("pvSave").onclick = async () => {
      try {
        const text = ide ? ide.getValue() : $("fileEditor")?.value ?? "";
        const res = await api(`/files/${fileId}/content`, {
          method: "PUT",
          body: { text, format: true, baseVersion: data.currentVersion ?? data.version },
        });
        closeModal();
        await loadFiles();
        paint();
        const e = (res.diagnostics || []).filter((d) => d.severity === "error").length;
        const w = (res.diagnostics || []).filter((d) => d.severity === "warning").length;
        toast(
          e || w
            ? `Saved (format: ${res.formatStatus || "ok"}) · ${e} err / ${w} warn`
            : `Saved new version (format: ${res.formatStatus || "ok"}).`
        );
      } catch (err) {
        toast(err.message);
      }
    };
  }
  $("pvEdit")?.addEventListener("click", () => openFile(fileId, true, version));
  $("pvRestore")?.addEventListener("click", () => {
    confirmRestoreVersion(fileId, data.version, {
      fileName: data.name,
      onDone: async () => openFile(fileId, false),
    });
  });
  $("pvDelete")?.addEventListener("click", async () => {
    if (!confirm("Delete this file?")) return;
    try {
      await api(`/files/${fileId}`, { method: "DELETE" });
      closeModal();
      await loadFiles();
      paint();
      toast("File deleted.");
    } catch (e) {
      toast(e.message);
    }
  });
  $("mDone").onclick = closeModal;
}

async function syncSilent() {
  if (!state.user) return;
  try {
    // Always refresh org/project lists so newly added members see orgs without a full reload.
    const beforeOrgs = state.orgs.map((o) => `${o.id}:${o.my_role || ""}`).join("|");
    const beforeProjects = state.projects.map((p) => `${p.id}:${p.my_role || ""}`).join("|");
    await loadOrgsProjects();
    const afterOrgs = state.orgs.map((o) => `${o.id}:${o.my_role || ""}`).join("|");
    const afterProjects = state.projects.map((p) => `${p.id}:${p.my_role || ""}`).join("|");
    if (beforeOrgs !== afterOrgs || beforeProjects !== afterProjects) {
      if (state.view === "home" || !state.project) {
        state.view = "home";
        paint();
        if (afterOrgs && afterOrgs !== beforeOrgs) toast("Organizations updated.");
        else if (afterProjects !== beforeProjects) toast("Projects updated.");
        return;
      }
      // Still on a project view — refresh shell lists at least
      renderOrgList();
      renderProjectList();
      if (afterOrgs !== beforeOrgs) toast("Organizations updated.");
    }

    if (!state.project) return;

    const beforeFiles = state.files
      .map((f) => `${f.id}:${f.access}:${f.current_version}:${f.canDelete ? 1 : 0}`)
      .join("|");
    const beforeMembers = state.members.map((m) => m.id + ":" + m.role).join("|");
    const beforeFolders = state.folders.map((f) => f.id + ":" + f.access + ":" + (f.canManageAcl ? 1 : 0)).join("|");
    const data = await api(`/projects/${state.project.id}?sync=1`);
    state.folders = data.folders;
    state.members = data.members;
    if (data.myRole) state.project = { ...state.project, my_role: data.myRole };
    if (state.folderId) await loadFiles();
    const afterFiles = state.files
      .map((f) => `${f.id}:${f.access}:${f.current_version}:${f.canDelete ? 1 : 0}`)
      .join("|");
    const afterMembers = state.members.map((m) => m.id + ":" + m.role).join("|");
    const afterFolders = state.folders.map((f) => f.id + ":" + f.access + ":" + (f.canManageAcl ? 1 : 0)).join("|");
    if (beforeMembers !== afterMembers) {
      paint();
      toast("Members updated.");
      return;
    }
    if (beforeFiles !== afterFiles || beforeFolders !== afterFolders) {
      paint();
      toast("Project updated.");
    }
  } catch {
    /* ignore */
  }
}

async function boot() {
  try {
    await refreshSession();
    if (!state.user) {
      const meta = await api("/auth/meta");
      state.oidcEnabled = meta.oidcEnabled;
      paint();
      return;
    }
    await loadOrgsProjects();
    state.view = "home";
    paint();
    clearInterval(state.poll);
    state.poll = setInterval(liveTick, 2000);
  } catch {
    state.user = null;
    try {
      const meta = await api("/auth/meta");
      state.oidcEnabled = meta.oidcEnabled;
    } catch {
      /* */
    }
    paint();
  }
}

boot();
