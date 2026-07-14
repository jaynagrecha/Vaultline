import { createApiStore } from "./api.js";
import {
  deriveKey,
  roomIdFromCode,
  encBytes,
  decBytes,
  encJSON,
  decJSON,
  makeCode,
  uid,
  makePasswordVerifier,
  verifyPassword,
} from "./crypto.js";

const store = createApiStore();
const CHUNK = 3 * 1024 * 1024;
const MAX_RAW = 50 * 1024 * 1024;
const PREVIEW_MAX = 2 * 1024 * 1024;
const roomKey = (id) => `cr:${id}`;
const chunkKey = (rid, fid, i) => `crf:${rid}:${fid}:${i}`;

const TEXT_EXT =
  /\.(txt|md|markdown|json|ya?ml|toml|ini|cfg|conf|config|env|xml|html?|css|scss|js|mjs|cjs|jsx|ts|tsx|py|rb|go|rs|java|kt|c|h|hpp|cpp|cs|sh|bash|zsh|bat|ps1|sql|csv|tsv|log|properties|gradle|tf|proto|graphql|svg|lock|gitignore|dockerignore|editorconfig)$/i;
const isTexty = (n) =>
  TEXT_EXT.test(n) || /^(dockerfile|makefile|license|readme|\.env.*)$/i.test(n) || !n.includes(".");

let S = {
  code: null,
  key: null,
  roomId: null,
  room: null,
  roomEtag: null,
  me: null,
  folderId: null,
  pollTimer: null,
};

let mutating = Promise.resolve();
let toastTimer;

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
const fmtSize = (n) =>
  n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(2) + " MB";

function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) {
    t = document.createElement("div");
    t.className = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 3500);
}

function modal(html, wide) {
  $("modalRoot").innerHTML = `<div class="overlay" id="overlay"><div class="modal${wide ? " wide" : ""}" role="dialog" aria-modal="true">${html}</div></div>`;
  $("overlay").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeModal();
  });
}
function closeModal() {
  $("modalRoot").innerHTML = "";
}

function gateErr(m) {
  $("gateErr").textContent = m || "";
}

function needCrypto() {
  if (!window.crypto || !crypto.subtle) {
    gateErr("This browser needs a secure context (HTTPS) for encryption.");
    return true;
  }
  return false;
}

async function loadRoomRow() {
  const row = await store.get(roomKey(S.roomId));
  return row;
}

async function saveRoom(ifMatch) {
  S.room.updatedAt = Date.now();
  const cipher = await encJSON(S.key, S.room);
  const result = await store.set(roomKey(S.roomId), cipher, { ifMatch });
  S.roomEtag = result.etag;
}

function setTab(t) {
  $("tabCreate").setAttribute("aria-selected", t === "create");
  $("tabJoin").setAttribute("aria-selected", t === "join");
  $("paneCreate").classList.toggle("hidden", t !== "create");
  $("paneJoin").classList.toggle("hidden", t !== "join");
  gateErr("");
}

async function createRoom() {
  if (needCrypto()) return;
  const name = $("cRoom").value.trim();
  const display = $("cName").value.trim();
  const pass = $("cPass").value;
  const pass2 = $("cPass2").value;
  if (!name || !display) return gateErr("Give the room a name and tell us yours.");
  if (pass.length < 8) return gateErr("Password must be at least 8 characters.");
  if (pass !== pass2) return gateErr("Passwords don't match.");
  const code = makeCode();
  try {
    const memberId = uid();
    const verifier = await makePasswordVerifier(pass);
    S.code = code;
    S.key = await deriveKey(code);
    S.roomId = await roomIdFromCode(code);
    S.me = { id: memberId, name: display };
    S.room = {
      name,
      owner: memberId,
      members: [{ id: memberId, name: display, verifier }],
      folders: [],
      activity: [],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    logAct(S.room, "created the room");
    await saveRoom(null);
    $("cPass").value = "";
    $("cPass2").value = "";
    enterApp();
    showInvite(true);
  } catch (e) {
    gateErr("Couldn't create the room: " + e.message);
  }
}

async function joinRoom() {
  if (needCrypto()) return;
  const joinFail = "Couldn't unlock. Check the room code, name, and password.";
  const code = $("jCode").value.trim();
  const display = $("jName").value.trim();
  const pass = $("jPass").value;
  if (!code || !display) return gateErr("Enter the key code, your name, and password.");
  if (pass.length < 8) return gateErr("Enter your password (at least 8 characters).");
  try {
    const key = await deriveKey(code);
    const rid = await roomIdFromCode(code);
    const row = await store.get(roomKey(rid));
    if (!row) return gateErr(joinFail);
    let room;
    try {
      room = await decJSON(key, row.value);
    } catch {
      return gateErr(joinFail);
    }
    normalizeRoom(room);

    const existing = findMemberByName(room, display);
    let me = null;

    if (existing) {
      if (existing.verifier) {
        const ok = await verifyPassword(pass, existing.verifier);
        if (!ok) return gateErr(joinFail);
        me = { id: existing.id, name: existing.name };
      } else {
        // Legacy name-only member: claim with password (one-time upgrade)
        const verifier = await makePasswordVerifier(pass);
        S.code = code.toUpperCase();
        S.key = key;
        S.roomId = rid;
        S.room = room;
        S.roomEtag = row.etag;
        S.me = { id: existing.id || uid(), name: existing.name };
        await mutateRoom((r) => {
          const m = findMemberByName(r, display);
          if (!m) return;
          if (!m.id) m.id = S.me.id;
          m.verifier = verifier;
          remapLegacyNameToId(r, display, m.id);
        });
        me = { id: findMemberByName(S.room, display).id, name: display };
        toast("Identity secured with your password. Don't share it.");
      }
    } else {
      const memberId = uid();
      const verifier = await makePasswordVerifier(pass);
      S.code = code.toUpperCase();
      S.key = key;
      S.roomId = rid;
      S.room = room;
      S.roomEtag = row.etag;
      S.me = { id: memberId, name: display };
      await mutateRoom((r) => {
        if (findMemberByName(r, display)) return;
        r.members.push({ id: memberId, name: display, verifier });
        logAct(r, "joined the room");
      });
      const registered = findMemberByName(S.room, display);
      if (!registered) {
        S = {
          code: null,
          key: null,
          roomId: null,
          room: null,
          roomEtag: null,
          me: null,
          folderId: null,
          pollTimer: null,
        };
        return gateErr(joinFail);
      }
      if (registered.id !== memberId) {
        const ok = registered.verifier && (await verifyPassword(pass, registered.verifier));
        if (!ok) {
          S = {
            code: null,
            key: null,
            roomId: null,
            room: null,
            roomEtag: null,
            me: null,
            folderId: null,
            pollTimer: null,
          };
          return gateErr(joinFail);
        }
      }
      me = { id: registered.id, name: registered.name };
    }

    S.code = code.toUpperCase();
    S.key = key;
    S.roomId = rid;
    S.roomEtag = row.etag;
    const latest = await store.get(roomKey(rid));
    if (latest) {
      try {
        S.room = await decJSON(key, latest.value);
        normalizeRoom(S.room);
        S.roomEtag = latest.etag;
      } catch {
        S.room = room;
        normalizeRoom(S.room);
      }
    } else {
      S.room = room;
      normalizeRoom(S.room);
    }
    S.me = me;
    $("jPass").value = "";
    enterApp();
  } catch (e) {
    gateErr(joinFail);
  }
}

function enterApp() {
  $("landing").classList.add("hidden");
  $("app").classList.remove("hidden");
  S.folderId = null;
  S.accessKey = accessSnapshot(S.room).key;
  render();
  clearInterval(S.pollTimer);
  S.pollTimer = setInterval(() => syncRoom(false), 4000);
  syncRoom(false);
}

function leaveRoom() {
  clearInterval(S.pollTimer);
  S = {
    code: null,
    key: null,
    roomId: null,
    room: null,
    roomEtag: null,
    me: null,
    folderId: null,
    pollTimer: null,
    accessKey: null,
  };
  $("app").classList.add("hidden");
  $("landing").classList.remove("hidden");
  ["cRoom", "cName", "cPass", "cPass2", "jCode", "jName", "jPass"].forEach((id) => {
    const el = $(id);
    if (el) el.value = "";
  });
  gateErr("");
}

const normName = (n) => String(n || "").trim().toLowerCase();
const meId = () => (S.me && S.me.id) || null;
const meName = () => (S.me && S.me.name) || "";

function findMemberByName(room, name) {
  const n = normName(name);
  return (room.members || []).find((m) => normName(m.name) === n) || null;
}

function findMemberById(room, id) {
  if (!id) return null;
  return (room.members || []).find((m) => m.id === id) || null;
}

function displayName(idOrName) {
  if (!idOrName || !S.room) return String(idOrName || "");
  const byId = findMemberById(S.room, idOrName);
  if (byId) return byId.name;
  const byName = findMemberByName(S.room, idOrName);
  if (byName) return byName.name;
  return String(idOrName);
}

function resolveMemberId(ref) {
  if (!ref || !S.room) return ref;
  if (findMemberById(S.room, ref)) return ref;
  const byName = findMemberByName(S.room, ref);
  return byName ? byName.id : ref;
}

/** Upgrade legacy name-keyed room data to member ids. */
function normalizeRoom(room) {
  if (!room.members) room.members = [];
  for (const m of room.members) {
    if (!m.id) m.id = uid();
  }
  if (room.owner && !findMemberById(room, room.owner)) {
    const m = findMemberByName(room, room.owner);
    if (m) room.owner = m.id;
  }
  for (const f of room.folders || []) {
    if (f.owner && !findMemberById(room, f.owner)) {
      const m = findMemberByName(room, f.owner);
      if (m) f.owner = m.id;
    }
    if (Array.isArray(f.sharedWith) && f.sharedWith.length && typeof f.sharedWith[0] === "object") {
      for (const g of f.sharedWith) {
        if (g.name && !g.id) {
          const m = findMemberByName(room, g.name);
          if (m) g.id = m.id;
        }
        if (g.id && !g.name) {
          const m = findMemberById(room, g.id);
          if (m) g.name = m.name;
        }
      }
    } else if (Array.isArray(f.sharedWith) && typeof f.sharedWith[0] === "string") {
      f.sharedWith = f.sharedWith
        .map((name) => {
          const m = findMemberByName(room, name);
          return m ? { id: m.id, name: m.name, access: "edit" } : null;
        })
        .filter(Boolean);
    }
    if (Array.isArray(f.visibility) && f.visibility !== "all") {
      /* leave; getFolderAcl handles legacy */
    }
    for (const fl of f.files || []) {
      if (fl.by && !findMemberById(room, fl.by)) {
        const m = findMemberByName(room, fl.by);
        if (m) fl.by = m.id;
      }
      if (Array.isArray(fl.sharedWith) && fl.sharedWith.length && typeof fl.sharedWith[0] === "object") {
        for (const g of fl.sharedWith) {
          if (g.name && !g.id) {
            const m = findMemberByName(room, g.name);
            if (m) g.id = m.id;
          }
        }
      } else if (Array.isArray(fl.sharedWith) && typeof fl.sharedWith[0] === "string") {
        fl.sharedWith = fl.sharedWith
          .map((name) => {
            const m = findMemberByName(room, name);
            return m ? { id: m.id, name: m.name, access: "read" } : null;
          })
          .filter(Boolean);
      }
    }
  }
  for (const a of room.activity || []) {
    if (a.byId) continue;
    const m = findMemberByName(room, a.by);
    if (m) a.byId = m.id;
  }
}

function remapLegacyNameToId(room, name, id) {
  if (room.owner === name) room.owner = id;
  for (const f of room.folders || []) {
    if (f.owner === name) f.owner = id;
    if (Array.isArray(f.write)) f.write = f.write.map((n) => (n === name ? id : n));
    if (Array.isArray(f.visibility)) f.visibility = f.visibility.map((n) => (n === name ? id : n));
    if (Array.isArray(f.sharedWith)) {
      for (const g of f.sharedWith) {
        if (typeof g === "string" && g === name) {
          /* converted elsewhere */
        } else if (g && g.name === name) g.id = id;
      }
    }
    for (const fl of f.files || []) {
      if (fl.by === name) fl.by = id;
      if (Array.isArray(fl.sharedWith)) {
        for (const g of fl.sharedWith) {
          if (g && g.name === name) g.id = id;
        }
      }
    }
  }
}

function logAct(r, action) {
  r.activity = r.activity || [];
  r.activity.unshift({ by: meName(), byId: meId(), action, ts: Date.now() });
  if (r.activity.length > 150) r.activity.length = 150;
}

function accessSnapshot(room) {
  const id = meId();
  const folders = [];
  const files = [];
  if (!room || !id) return { folders, files, key: "" };
  for (const f of room.folders || []) {
    const fa = memberAccess(f, id);
    if (!fa) continue;
    folders.push({ id: f.id, name: f.name, access: fa });
    for (const fl of f.files || []) {
      const a = fileAccess(f, fl, id);
      if (!a) continue;
      files.push({ id: fl.id, name: fl.name, folderId: f.id, access: a });
    }
  }
  const key =
    folders
      .map((x) => x.id + ":" + x.access)
      .sort()
      .join("|") +
    "#" +
    files
      .map((x) => x.id + ":" + x.access)
      .sort()
      .join("|");
  return { folders, files, key };
}

function notifyAccessChanges(before, after) {
  if (!before || !after || before.key === after.key) return;
  const beforeFiles = new Map(before.files.map((f) => [f.id, f]));
  const afterFiles = new Map(after.files.map((f) => [f.id, f]));
  const beforeFolders = new Map(before.folders.map((f) => [f.id, f]));
  const afterFolders = new Map(after.folders.map((f) => [f.id, f]));

  const gainedFiles = after.files.filter((f) => !beforeFiles.has(f.id));
  const lostFiles = before.files.filter((f) => !afterFiles.has(f.id));
  const changedFiles = after.files.filter((f) => {
    const prev = beforeFiles.get(f.id);
    return prev && prev.access !== f.access;
  });
  const gainedFolders = after.folders.filter((f) => !beforeFolders.has(f.id));
  const lostFolders = before.folders.filter((f) => !afterFolders.has(f.id));

  if (gainedFiles.length === 1) {
    toast(`You can now see “${gainedFiles[0].name}”.`);
  } else if (gainedFiles.length > 1) {
    toast(`You gained access to ${gainedFiles.length} files.`);
  } else if (gainedFolders.length) {
    toast(
      gainedFolders.length === 1
        ? `You can now see folder “${gainedFolders[0].name}”.`
        : `You gained access to ${gainedFolders.length} folders.`
    );
  } else if (changedFiles.length === 1) {
    const f = changedFiles[0];
    toast(
      f.access === "edit"
        ? `You can now edit “${f.name}”.`
        : `“${f.name}” is now read-only for you.`
    );
  } else if (changedFiles.length > 1) {
    toast("Your file permissions were updated.");
  } else if (lostFiles.length === 1) {
    toast(`You no longer have access to “${lostFiles[0].name}”.`);
  } else if (lostFiles.length > 1) {
    toast(`Access removed for ${lostFiles.length} files.`);
  } else if (lostFolders.length) {
    toast(
      lostFolders.length === 1
        ? `You no longer have access to folder “${lostFolders[0].name}”.`
        : `Access removed for ${lostFolders.length} folders.`
    );
  }
}

async function syncRoom(manual) {
  if (!S.roomId || !S.key) return;
  const before = accessSnapshot(S.room);
  const row = await loadRoomRow();
  if (!row) return;
  try {
    if (S.roomEtag && row.etag === S.roomEtag) {
      if (manual) toast("Room is up to date.");
      return;
    }
    const fresh = await decJSON(S.key, row.value);
    normalizeRoom(fresh);
    S.room = fresh;
    S.roomEtag = row.etag;
    const after = accessSnapshot(S.room);
    render();
    if (!manual) notifyAccessChanges(before, after);
    S.accessKey = after.key;
    if (manual) toast("Room is up to date.");
  } catch {
    /* ignore decrypt glitches during sync */
  }
}

function mutateRoom(fn) {
  mutating = mutating
    .then(async () => {
      for (let attempt = 0; attempt < 5; attempt++) {
        const row = await loadRoomRow();
        if (row) {
          try {
            S.room = await decJSON(S.key, row.value);
            normalizeRoom(S.room);
            S.roomEtag = row.etag;
          } catch {
            /* keep local */
          }
        }
        await fn(S.room);
        try {
          await saveRoom(S.roomEtag || undefined);
          render();
          return;
        } catch (err) {
          if (err.code === "CONFLICT") {
            await new Promise((r) => setTimeout(r, 40 + attempt * 60));
            continue;
          }
          throw err;
        }
      }
      throw new Error("could not save after conflicts");
    })
    .catch((e) => toast("Couldn't save — try Sync now. (" + e.message + ")"));
  return mutating;
}

const isOwner = (id) => S.room && S.room.owner === id;
const canManageFolder = (f, id) => isOwner(id) || resolveMemberId(f.owner) === id;
const canDeleteFolder = (f, id) => !!f && resolveMemberId(f.owner) === id;

/**
 * Normalized folder ACL:
 * { mode: "all"|"people", everyoneAccess: "read"|"edit", people: { [memberId]: "read"|"edit" } }
 */
function getFolderAcl(f) {
  const everyoneAccess = f.everyoneAccess === "read" ? "read" : "edit";
  const ownerId = resolveMemberId(f.owner);

  if (Array.isArray(f.sharedWith) && f.sharedWith.length && typeof f.sharedWith[0] === "object") {
    const people = {};
    for (const g of f.sharedWith) {
      const id = g.id || resolveMemberId(g.name);
      if (!id || id === ownerId) continue;
      people[id] = g.access === "edit" ? "edit" : "read";
    }
    return { mode: "people", everyoneAccess, people };
  }

  if (f.sharedWith === "all" || f.visibility === "all") {
    let access = f.everyoneAccess;
    if (!access) {
      if (f.visibility === "all" && Array.isArray(f.write) && f.write.length === 0) access = "read";
      else access = "edit";
    }
    return { mode: "all", everyoneAccess: access === "read" ? "read" : "edit", people: {} };
  }

  const names = Array.isArray(f.sharedWith)
    ? f.sharedWith.filter((n) => typeof n === "string")
    : Array.isArray(f.visibility)
      ? f.visibility
      : [];
  const people = {};
  const writers = new Set((f.write || []).map((w) => resolveMemberId(w)));
  for (const n of names) {
    const id = resolveMemberId(n);
    if (!id || id === ownerId) continue;
    if (f.write !== undefined) people[id] = writers.has(id) ? "edit" : "read";
    else people[id] = "edit";
  }
  return { mode: names.length ? "people" : "all", everyoneAccess, people };
}

function memberNames() {
  return (S.room.members || []).map((m) => ({ id: m.id, name: m.name }));
}

function memberAccess(f, id) {
  if (!f || !id) return null;
  const ownerId = resolveMemberId(f.owner);
  if (isOwner(id) || ownerId === id) return "edit";
  const acl = getFolderAcl(f);
  if (acl.mode === "all") return acl.everyoneAccess;
  return acl.people[id] || null;
}

function canSee(f, id) {
  return memberAccess(f, id) !== null;
}

function canWrite(f, id) {
  return memberAccess(f, id) === "edit";
}

function folderMembers(f) {
  const acl = getFolderAcl(f);
  const all = S.room.members || [];
  if (acl.mode === "all") return all.map((m) => m.id);
  const ownerId = resolveMemberId(f.owner);
  return Array.from(new Set([ownerId, S.room.owner, ...Object.keys(acl.people)].filter(Boolean)));
}

function canSeeFile(folder, file, id) {
  return fileAccess(folder, file, id) !== null;
}

function canEditFile(folder, file, id) {
  return fileAccess(folder, file, id) === "edit";
}

function canManageFilePerms(folder, file, id) {
  return isOwner(id) || resolveMemberId(folder.owner) === id || resolveMemberId(file.by) === id;
}

function canDeleteFile(folder, file, id) {
  return !!file && resolveMemberId(file.by) === id;
}

function getFileAcl(file) {
  if (!file.sharedWith || file.sharedWith === "folder" || file.sharedWith === "all") {
    return { mode: "folder", people: {} };
  }
  if (Array.isArray(file.sharedWith) && file.sharedWith.length && typeof file.sharedWith[0] === "object") {
    const people = {};
    for (const g of file.sharedWith) {
      const id = g.id || resolveMemberId(g.name);
      if (!id) continue;
      people[id] = g.access === "edit" ? "edit" : "read";
    }
    return { mode: "people", people };
  }
  if (Array.isArray(file.sharedWith)) {
    const people = {};
    for (const n of file.sharedWith) {
      if (typeof n === "string") {
        const id = resolveMemberId(n);
        if (id) people[id] = "read";
      }
    }
    return { mode: "people", people };
  }
  return { mode: "folder", people: {} };
}

function fileAccess(folder, file, id) {
  if (!folder || !file || !id) return null;
  if (!canSee(folder, id)) return null;
  if (isOwner(id) || resolveMemberId(folder.owner) === id || resolveMemberId(file.by) === id) return "edit";
  const facl = getFileAcl(file);
  if (facl.mode === "folder") return memberAccess(folder, id);
  return facl.people[id] || null;
}

function describeFileShare(folder, file) {
  const facl = getFileAcl(file);
  if (facl.mode === "folder") return "";
  const entries = Object.entries(facl.people);
  if (!entries.length) return "custom access";
  const edits = entries.filter(([, a]) => a === "edit").length;
  const reads = entries.filter(([, a]) => a === "read").length;
  const bits = [];
  if (edits) bits.push(edits === 1 ? "1 can edit" : `${edits} can edit`);
  if (reads) bits.push(reads === 1 ? "1 read-only" : `${reads} read-only`);
  return bits.join(", ") || "custom access";
}

function describeFolderShare(f) {
  const acl = getFolderAcl(f);
  if (acl.mode === "all") {
    return acl.everyoneAccess === "edit"
      ? "everyone can edit"
      : "everyone can read (owner can edit)";
  }
  const entries = Object.entries(acl.people);
  if (!entries.length) return "only you (not shared yet)";
  const bits = [];
  const edits = entries.filter(([, a]) => a === "edit").length;
  const reads = entries.filter(([, a]) => a === "read").length;
  if (edits) bits.push(`${edits} can edit`);
  if (reads) bits.push(`${reads} read-only`);
  return bits.join(" · ");
}


/** Simple checkbox share picker (used for per-file visibility). */
function renderSharePickerRows(opts) {
  const q = (($(opts.searchId) && $(opts.searchId).value) || "").trim().toLowerCase();
  const list = $(opts.listId);
  if (!list) return;
  const rows = opts.candidates
    .filter((n) => !q || n.toLowerCase().includes(q))
    .map((n) => {
      const locked = opts.locked.has(n);
      const checked = locked || opts.selected.has(n);
      return `<label class="share-row${locked ? " locked" : ""}">
        <input type="checkbox" data-share-name="${esc(n)}" ${checked ? "checked" : ""} ${locked ? "disabled" : ""}>
        <span class="avatar">${esc(n.slice(0, 2).toUpperCase())}</span>
        <span class="who">${esc(n)}</span>
        ${locked ? '<span class="hint">always</span>' : ""}
      </label>`;
    })
    .join("");
  list.innerHTML =
    rows ||
    `<p class="sub" style="padding:14px;margin:0">${
      opts.candidates.length ? "No matches." : "No other members in the room yet."
    }</p>`;
  list.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach((el) => {
    el.onchange = () => {
      if (el.checked) opts.selected.add(el.dataset.shareName);
      else opts.selected.delete(el.dataset.shareName);
      updateShareCount(opts);
    };
  });
  updateShareCount(opts);
}

function updateShareCount(opts) {
  const el = $(opts.countId);
  if (!el) return;
  const n = new Set([...opts.selected, ...opts.locked]).size;
  el.textContent = `${n} selected`;
}

function wireSharePicker(opts) {
  renderSharePickerRows(opts);
  if ($(opts.searchId)) $(opts.searchId).oninput = () => renderSharePickerRows(opts);
  if ($(opts.selectAllId)) {
    $(opts.selectAllId).onclick = (e) => {
      e.preventDefault();
      opts.candidates.forEach((n) => {
        if (!opts.locked.has(n)) opts.selected.add(n);
      });
      renderSharePickerRows(opts);
    };
  }
  if ($(opts.clearId)) {
    $(opts.clearId).onclick = (e) => {
      e.preventDefault();
      opts.selected.clear();
      renderSharePickerRows(opts);
    };
  }
}

/** Folder/file share UI: candidates = [{id,name}], grants Map id -> "off"|"read"|"edit" */
function renderAccessRows(state) {
  const q = (($("shareSearch") && $("shareSearch").value) || "").trim().toLowerCase();
  const list = $("shareList");
  if (!list) return;
  const rows = state.candidates
    .filter((m) => !q || m.name.toLowerCase().includes(q))
    .map((m) => {
      const access = state.grants.get(m.id) || "off";
      return `<div class="share-row" data-person="${esc(m.id)}">
        <span class="avatar">${esc(m.name.slice(0, 2).toUpperCase())}</span>
        <div class="who-block"><span class="who">${esc(m.name)}</span></div>
        <div class="access-seg" role="group" aria-label="Access for ${esc(m.name)}">
          <button type="button" class="off" data-access="off" aria-pressed="${access === "off"}">Off</button>
          <button type="button" class="read" data-access="read" aria-pressed="${access === "read"}">Read only</button>
          <button type="button" class="edit" data-access="edit" aria-pressed="${access === "edit"}">Can edit</button>
        </div>
      </div>`;
    })
    .join("");
  list.innerHTML =
    rows ||
    `<p class="sub" style="padding:14px;margin:0">${
      state.candidates.length ? "No matches." : "No other members yet — they'll appear when they join."
    }</p>`;

  list.querySelectorAll(".share-row").forEach((row) => {
    const id = row.dataset.person;
    row.querySelectorAll("button[data-access]").forEach((btn) => {
      btn.onclick = () => {
        state.grants.set(id, btn.dataset.access);
        renderAccessRows(state);
      };
    });
  });

  const active = [...state.grants.entries()].filter(([, a]) => a !== "off");
  const edits = active.filter(([, a]) => a === "edit").length;
  const reads = active.filter(([, a]) => a === "read").length;
  if ($("shareCount")) {
    $("shareCount").textContent = active.length
      ? `${active.length} shared · ${edits} edit · ${reads} read-only`
      : "Nobody selected yet";
  }
}

function render() {
  if (!S.room) return;
  normalizeRoom(S.room);
  $("sbRoom").textContent = S.room.name;
  $("sbYou").textContent = meName();
  const visible = S.room.folders.filter((f) => canSee(f, meId()));
  $("folderList").innerHTML =
    visible
      .map((f, idx) => {
        const access = memberAccess(f, meId());
        return `
    <button class="folder-item" type="button" data-folder="${f.id}" aria-current="${f.id === S.folderId}">
      <span class="item-num">${idx + 1}.</span> ${esc(f.name)}
      <span class="badge ${access === "edit" ? "edit" : "read"}">${access === "edit" ? "edit" : "read"}</span>
    </button>`;
      })
      .join("") ||
    `<p style="font-size:13px;color:var(--ink-soft);padding:4px 2px">No folders yet — create the first one.</p>`;

  $("memberList").innerHTML = S.room.members
    .map(
      (m) => `
    <div class="member"><span class="avatar">${esc(m.name.slice(0, 2).toUpperCase())}</span>${esc(m.name)}${
        m.id === S.room.owner ? '<span class="tag">owner</span>' : ""
      }${m.id === meId() ? '<span class="tag" style="color:var(--ink-soft)">you</span>' : ""}${
        m.verifier ? "" : '<span class="tag" style="color:var(--danger)">unprotected</span>'
      }</div>`
    )
    .join("");

  const f = S.room.folders.find((x) => x.id === S.folderId);
  if (!f || !canSee(f, meId())) S.folderId = null;
  $("folderHome").classList.toggle("hidden", !!S.folderId);
  $("folderView").classList.toggle("hidden", !S.folderId);
  if (S.folderId) renderFolder(S.room.folders.find((x) => x.id === S.folderId));
}

function renderFolder(f) {
  const w = canWrite(f, meId());
  const manage = canManageFolder(f, meId());
  const canRemoveFolder = canDeleteFolder(f, meId());
  const visibleFiles = f.files.filter((fl) => canSeeFile(f, fl, meId()));
  const folderNum = S.room.folders.filter((x) => canSee(x, meId())).findIndex((x) => x.id === f.id) + 1;
  $("fvName").textContent = `${folderNum}. ${f.name}`;
  $("fvMeta").textContent = `${visibleFiles.length} file${visibleFiles.length === 1 ? "" : "s"} · ${describeFolderShare(
    f
  )} · created by ${displayName(f.owner)}${w ? "" : " · read-only for you"}`;
  $("fvSettings").classList.toggle("hidden", !manage);
  $("fvDelete").classList.toggle("hidden", !canRemoveFolder);
  $("fvDownloadAll").classList.toggle("hidden", visibleFiles.length === 0);
  $("dropzone").classList.toggle("hidden", !w);

  const groups = {};
  visibleFiles.forEach((fl) => {
    (groups[fl.dir || ""] = groups[fl.dir || ""] || []).push(fl);
  });
  const dirs = Object.keys(groups).sort();
  let fileNum = 0;
  $("fileList").innerHTML =
    visibleFiles.length === 0
      ? `<div class="empty"><h3>Folder is empty</h3><p>${
          w ? "Drop a file, a folder, or a zip above to fill it." : "Nothing has been shared with you here yet."
        }</p></div>`
      : dirs
          .map((d) => {
            const block = groups[d]
              .map((fl) => {
                fileNum += 1;
                const n = fileNum;
                const texty = isTexty(fl.name) && fl.size <= PREVIEW_MAX;
                const lim = describeFileShare(f, fl);
                const canDel = canDeleteFile(f, fl, meId());
                const canEd = canEditFile(f, fl, meId());
                const canPerm = canManageFilePerms(f, fl, meId());
                const openAction = canEd && texty ? "data-edit" : texty ? "data-preview" : null;
                const nameEl = openAction
                  ? `<button class="fname" type="button" ${openAction}="${fl.id}" title="${
                      canEd ? "Edit" : "Preview"
                    } ${esc(fl.name)}">${esc(fl.name)}</button>`
                  : `<span class="fname">${esc(fl.name)}</span>`;
                return `<div class="file-row">
            <span class="item-num">${n}.</span>
            ${nameEl}${
                  lim
                    ? `<span class="file-share-tag" title="Who this file is shared with">${esc(lim)}</span>`
                    : ""
                }
            <span class="fmeta">${fmtSize(fl.size)} · ${esc(displayName(fl.by))}${canEd ? "" : " · read-only"}</span>
            <span class="row-actions">
              ${
                canEd && texty
                  ? `<button class="icon-btn" type="button" title="Edit" data-edit="${fl.id}" aria-label="Edit">✎</button>`
                  : texty
                    ? `<button class="icon-btn" type="button" title="Preview" data-preview="${fl.id}" aria-label="Preview">◉</button>`
                    : ""
              }
              ${
                canPerm
                  ? `<button class="icon-btn" type="button" title="Permissions" data-perms="${fl.id}" aria-label="Permissions">⚙</button>`
                  : ""
              }
              <button class="icon-btn" type="button" title="Download" data-download="${fl.id}" aria-label="Download">⬇</button>
              ${
                canDel
                  ? `<button class="icon-btn danger" type="button" title="Delete" data-delete="${fl.id}" aria-label="Delete">✕</button>`
                  : ""
              }
            </span>
          </div>`;
              })
              .join("");
            return `<div class="dir-group">${d ? `<div class="dir-label">${esc(d)}/</div>` : ""}${block}</div>`;
          })
          .join("");
}

function openFolder(id) {
  S.folderId = id;
  render();
}

function openNewFolder() {
  modal(`
    <h3>New shared folder</h3>
    <p class="sub">Next you'll choose who can <strong>read</strong> or <strong>edit</strong> it.</p>
    <label for="nfName">Folder name</label>
    <input class="field" id="nfName" maxlength="48" placeholder="e.g. deploy-configs">
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="nfCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="nfCreate">Create &amp; share</button>
    </div>`);
  $("nfCancel").onclick = closeModal;
  $("nfCreate").onclick = createFolder;
  $("nfName").focus();
  $("nfName").addEventListener("keydown", (e) => {
    if (e.key === "Enter") createFolder();
  });
}

async function createFolder() {
  const name = $("nfName").value.trim();
  if (!name) return;
  const id = uid();
  closeModal();
  await mutateRoom((r) => {
    r.folders.push({
      id,
      name,
      owner: meId(),
      sharedWith: "all",
      everyoneAccess: "edit",
      files: [],
    });
    logAct(r, `created folder “${name}”`);
  });
  S.folderId = id;
  render();
  openFolderShare(id, true);
}

function openFolderShare(folderId, firstTime) {
  const f = S.room.folders.find((x) => x.id === (folderId || S.folderId));
  if (!f || !canManageFolder(f, meId())) return;
  const acl = getFolderAcl(f);
  const ownerId = resolveMemberId(f.owner);
  const candidates = memberNames().filter((m) => m.id !== ownerId);
  const grants = new Map();
  for (const m of candidates) {
    if (acl.mode === "all") grants.set(m.id, acl.everyoneAccess);
    else grants.set(m.id, acl.people[m.id] || "off");
  }
  let everyoneAccess = acl.everyoneAccess;
  const state = { candidates, grants };

  modal(
    `
    <h3>${firstTime ? "Share this folder" : "Share & permissions"}</h3>
    <p class="sub">“${esc(f.name)}” — set <strong>Read only</strong> or <strong>Can edit</strong> per person. Editors can upload; readers can only view and download. You always have full access.</p>
    <div class="switch-row">
      <input type="checkbox" id="shareEveryone" ${acl.mode === "all" ? "checked" : ""}>
      <label for="shareEveryone" style="margin:0;font-weight:500;color:var(--ink)">Share with everyone in the room</label>
    </div>
    <div id="everyoneAccessWrap" class="${acl.mode === "all" ? "" : "hidden"}">
      <div class="everyone-access">
        <button type="button" class="choice" id="everyoneEdit" aria-pressed="${everyoneAccess === "edit"}">
          <strong>Everyone can edit</strong>
          <span>View, download, and upload files</span>
        </button>
        <button type="button" class="choice" id="everyoneRead" aria-pressed="${everyoneAccess === "read"}">
          <strong>Everyone read only</strong>
          <span>View and download — only you upload</span>
        </button>
      </div>
    </div>
    <div id="sharePickWrap" class="${acl.mode === "all" ? "hidden" : ""}">
      <label for="shareSearch">Search members</label>
      <input class="field share-search" id="shareSearch" placeholder="Type a name…" autocomplete="off">
      <div class="share-toolbar">
        <span class="share-count" id="shareCount"></span>
        <span>
          <button type="button" class="linkish" id="shareAllEdit">All can edit</button>
          ·
          <button type="button" class="linkish" id="shareAllRead">All read only</button>
          ·
          <button type="button" class="linkish" id="shareNone">Clear</button>
        </span>
      </div>
      <div class="share-list" id="shareList"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="psCancel">${firstTime ? "Skip for now" : "Cancel"}</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="psSave">Save</button>
    </div>`,
    true
  );

  const syncWrap = () => {
    const all = $("shareEveryone").checked;
    $("sharePickWrap").classList.toggle("hidden", all);
    $("everyoneAccessWrap").classList.toggle("hidden", !all);
  };
  const setEveryone = (access) => {
    everyoneAccess = access;
    $("everyoneEdit").setAttribute("aria-pressed", access === "edit");
    $("everyoneRead").setAttribute("aria-pressed", access === "read");
  };
  $("shareEveryone").onchange = syncWrap;
  $("everyoneEdit").onclick = () => setEveryone("edit");
  $("everyoneRead").onclick = () => setEveryone("read");
  $("shareSearch").oninput = () => renderAccessRows(state);
  $("shareAllEdit").onclick = (e) => {
    e.preventDefault();
    candidates.forEach((m) => state.grants.set(m.id, "edit"));
    renderAccessRows(state);
  };
  $("shareAllRead").onclick = (e) => {
    e.preventDefault();
    candidates.forEach((m) => state.grants.set(m.id, "read"));
    renderAccessRows(state);
  };
  $("shareNone").onclick = (e) => {
    e.preventDefault();
    candidates.forEach((m) => state.grants.set(m.id, "off"));
    renderAccessRows(state);
  };
  renderAccessRows(state);

  $("psCancel").onclick = closeModal;
  $("psSave").onclick = async () => {
    const everyone = $("shareEveryone").checked;
    const fid = f.id;
    closeModal();
    await mutateRoom((r) => {
      const fo = r.folders.find((x) => x.id === fid);
      if (!fo) return;
      delete fo.visibility;
      delete fo.write;
      if (everyone) {
        fo.sharedWith = "all";
        fo.everyoneAccess = everyoneAccess;
      } else {
        fo.sharedWith = [...state.grants.entries()]
          .filter(([, a]) => a === "read" || a === "edit")
          .map(([id, access]) => ({ id, name: displayName(id), access }));
        fo.everyoneAccess = "edit";
      }
      logAct(r, `updated sharing on “${fo.name}”`);
    });
    toast("Sharing & permissions saved.");
  };
}

function openFolderSettings() {
  openFolderShare(S.folderId, false);
}

async function deleteFolder() {
  const f = S.room.folders.find((x) => x.id === S.folderId);
  if (!f || !canDeleteFolder(f, meId())) return toast("You can only delete folders you created.");
  if (!confirm(`Delete “${f.name}” and its ${f.files.length} file(s) for everyone?`)) return;
  const metas = f.files.slice();
  const fid = f.id;
  const fname = f.name;
  await mutateRoom((r) => {
    r.folders = r.folders.filter((x) => x.id !== fid);
    logAct(r, `deleted folder “${fname}”`);
  });
  S.folderId = null;
  render();
  for (const m of metas) {
    for (let i = 0; i < (m.chunks || 1); i++) await store.del(chunkKey(S.roomId, m.id, i));
  }
  toast("Folder deleted.");
}

function walkEntry(entry, dir, out) {
  return new Promise((res) => {
    if (entry.isFile) {
      entry.file(
        (f) => {
          out.push({ file: f, dir });
          res();
        },
        () => res()
      );
    } else if (entry.isDirectory) {
      const rd = entry.createReader();
      const all = [];
      const readMore = () =>
        rd.readEntries(async (batch) => {
          if (!batch.length) {
            await Promise.all(all.map((en) => walkEntry(en, dir ? dir + "/" + entry.name : entry.name, out)));
            res();
          } else {
            all.push(...batch);
            readMore();
          }
        }, () => res());
      readMore();
    } else res();
  });
}

function pickFileShareTargets(folder, fileCount) {
  const poolIds = folderMembers(folder).filter((id) => id !== meId() && canSee(folder, id));
  const candidates = poolIds.map((id) => ({ id, name: displayName(id) }));
  if (!candidates.length) return Promise.resolve("folder");

  return new Promise((resolve) => {
    const grants = new Map();
    for (const m of candidates) {
      const a = memberAccess(folder, m.id);
      grants.set(m.id, a === "edit" ? "edit" : a === "read" ? "read" : "off");
    }
    const state = { candidates, grants };

    modal(
      `
      <h3>Permissions for ${fileCount === 1 ? "this file" : "these files"}</h3>
      <p class="sub">People must already have access to “${esc(
        folder.name
      )}”. Choose <strong>Read only</strong> or <strong>Can edit</strong> (edit text contents). You always keep full access.</p>
      <div class="switch-row">
        <input type="checkbox" id="fileShareFolder" checked>
        <label for="fileShareFolder" style="margin:0;font-weight:500;color:var(--ink)">Same as folder permissions</label>
      </div>
      <div id="fileShareWrap" class="hidden">
        <label for="shareSearch">Search</label>
        <input class="field share-search" id="shareSearch" placeholder="Type a name…" autocomplete="off">
        <div class="share-toolbar">
          <span class="share-count" id="shareCount"></span>
          <span>
            <button type="button" class="linkish" id="shareAllEdit">All can edit</button>
            ·
            <button type="button" class="linkish" id="shareAllRead">All read only</button>
            ·
            <button type="button" class="linkish" id="shareNone">Clear</button>
          </span>
        </div>
        <div class="share-list" id="shareList"></div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="fileShareCancel">Cancel upload</button>
        <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="fileShareGo">Upload</button>
      </div>`,
      true
    );

    const sync = () => {
      const all = $("fileShareFolder").checked;
      $("fileShareWrap").classList.toggle("hidden", all);
    };
    $("fileShareFolder").onchange = sync;
    $("shareSearch").oninput = () => renderAccessRows(state);
    $("shareAllEdit").onclick = (e) => {
      e.preventDefault();
      candidates.forEach((m) => state.grants.set(m.id, "edit"));
      renderAccessRows(state);
    };
    $("shareAllRead").onclick = (e) => {
      e.preventDefault();
      candidates.forEach((m) => state.grants.set(m.id, "read"));
      renderAccessRows(state);
    };
    $("shareNone").onclick = (e) => {
      e.preventDefault();
      candidates.forEach((m) => state.grants.set(m.id, "off"));
      renderAccessRows(state);
    };
    renderAccessRows(state);

    $("fileShareCancel").onclick = () => {
      closeModal();
      resolve(null);
    };
    $("fileShareGo").onclick = () => {
      if ($("fileShareFolder").checked) {
        closeModal();
        resolve("folder");
        return;
      }
      const list = [...state.grants.entries()]
        .filter(([, a]) => a === "read" || a === "edit")
        .map(([id, access]) => ({ id, name: displayName(id), access }));
      if (!list.length) {
        toast("Pick at least one person, or use folder permissions.");
        return;
      }
      closeModal();
      resolve(list);
    };
  });
}

function openFilePermissions(fileId) {
  const folder = S.room.folders.find((x) => x.id === S.folderId);
  const file = folder && folder.files.find((x) => x.id === fileId);
  if (!folder || !file || !canManageFilePerms(folder, file, meId())) return;

  const byId = resolveMemberId(file.by);
  const candidates = memberNames().filter((m) => m.id !== byId && canSee(folder, m.id));
  const facl = getFileAcl(file);
  const grants = new Map();
  for (const m of candidates) {
    if (facl.mode === "folder") {
      const a = memberAccess(folder, m.id);
      grants.set(m.id, a === "edit" ? "edit" : a === "read" ? "read" : "off");
    } else {
      grants.set(m.id, facl.people[m.id] || "off");
    }
  }
  const state = { candidates, grants };
  const inherit = facl.mode === "folder";

  modal(
    `
    <h3>File permissions</h3>
    <p class="sub">“${esc(file.name)}” — set who can <strong>read</strong> or <strong>edit</strong> this file. Editors can change its contents. You / folder owner / uploader always have full access.</p>
    <div class="switch-row">
      <input type="checkbox" id="filePermInherit" ${inherit ? "checked" : ""}>
      <label for="filePermInherit" style="margin:0;font-weight:500;color:var(--ink)">Same as folder permissions</label>
    </div>
    <div id="filePermWrap" class="${inherit ? "hidden" : ""}">
      <label for="shareSearch">Search members</label>
      <input class="field share-search" id="shareSearch" placeholder="Type a name…" autocomplete="off">
      <div class="share-toolbar">
        <span class="share-count" id="shareCount"></span>
        <span>
          <button type="button" class="linkish" id="shareAllEdit">All can edit</button>
          ·
          <button type="button" class="linkish" id="shareAllRead">All read only</button>
          ·
          <button type="button" class="linkish" id="shareNone">Clear</button>
        </span>
      </div>
      <div class="share-list" id="shareList"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="fpCancel">Cancel</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="fpSave">Save</button>
    </div>`,
    true
  );

  $("filePermInherit").onchange = () => {
    $("filePermWrap").classList.toggle("hidden", $("filePermInherit").checked);
  };
  $("shareSearch").oninput = () => renderAccessRows(state);
  $("shareAllEdit").onclick = (e) => {
    e.preventDefault();
    candidates.forEach((m) => state.grants.set(m.id, "edit"));
    renderAccessRows(state);
  };
  $("shareAllRead").onclick = (e) => {
    e.preventDefault();
    candidates.forEach((m) => state.grants.set(m.id, "read"));
    renderAccessRows(state);
  };
  $("shareNone").onclick = (e) => {
    e.preventDefault();
    candidates.forEach((m) => state.grants.set(m.id, "off"));
    renderAccessRows(state);
  };
  renderAccessRows(state);

  $("fpCancel").onclick = closeModal;
  $("fpSave").onclick = async () => {
    const useFolder = $("filePermInherit").checked;
    const fid = folder.id;
    const fileIdLocal = file.id;
    closeModal();
    await mutateRoom((r) => {
      const fo = r.folders.find((x) => x.id === fid);
      if (!fo) return;
      const fl = fo.files.find((x) => x.id === fileIdLocal);
      if (!fl) return;
      if (useFolder) fl.sharedWith = "folder";
      else {
        fl.sharedWith = [...state.grants.entries()]
          .filter(([, a]) => a === "read" || a === "edit")
          .map(([id, access]) => ({ id, name: displayName(id), access }));
      }
      logAct(r, `changed permissions on “${fl.name}”`);
    });
    toast("File permissions saved.");
  };
}

async function ingest(entries) {
  const f = S.room.folders.find((x) => x.id === S.folderId);
  if (!f || !canWrite(f, meId())) return toast("You don't have upload access to this folder.");
  const plan = [];
  for (const { file, dir } of entries) {
    if (/\.zip$/i.test(file.name)) {
      try {
        if (typeof JSZip === "undefined") {
          toast("Zip support is still loading — try again in a second.");
          continue;
        }
        const zip = await JSZip.loadAsync(await file.arrayBuffer());
        for (const n of Object.keys(zip.files)) {
          const zf = zip.files[n];
          if (zf.dir) continue;
          const u8 = await zf.async("uint8array");
          const parts = n.split("/").filter(Boolean);
          const nm = parts.pop();
          plan.push({ name: nm, dir: [dir, ...parts].filter(Boolean).join("/"), u8 });
        }
      } catch {
        toast(`Couldn't unpack ${file.name} — is it a valid zip?`);
      }
    } else {
      plan.push({ name: file.name, dir, u8: new Uint8Array(await file.arrayBuffer()) });
    }
  }
  if (!plan.length) return;

  const shareTargets = await pickFileShareTargets(f, plan.length);
  if (shareTargets === null) return;

  const totalChunks = plan.reduce((a, p) => a + Math.max(1, Math.ceil(p.u8.length / CHUNK)), 0);
  const prog = $("upProg");
  const status = $("upStatus");
  prog.classList.remove("hidden");
  status.classList.remove("hidden");
  prog.max = totalChunks;
  prog.value = 0;
  let doneChunks = 0;
  let skipped = 0;
  const added = [];

  for (const p of plan) {
    const n = Math.max(1, Math.ceil(p.u8.length / CHUNK));
    if (p.u8.length > MAX_RAW) {
      skipped++;
      doneChunks += n;
      prog.value = doneChunks;
      continue;
    }
    status.textContent = `Encrypting & uploading ${p.name}…`;
    const id = uid();
    let ok = true;
    for (let i = 0; i < n; i++) {
      try {
        await store.set(chunkKey(S.roomId, id, i), await encBytes(S.key, p.u8.subarray(i * CHUNK, (i + 1) * CHUNK)));
      } catch {
        ok = false;
        for (let j = 0; j <= i; j++) await store.del(chunkKey(S.roomId, id, j));
        break;
      }
      doneChunks++;
      prog.value = doneChunks;
    }
    if (ok) {
      added.push({
        id,
        name: p.name,
        dir: p.dir,
        size: p.u8.length,
        chunks: n,
        by: meId(),
        ts: Date.now(),
        sharedWith: shareTargets,
      });
    } else skipped++;
  }

  const fid = S.folderId;
  if (added.length) {
    await mutateRoom((r) => {
      const fo = r.folders.find((x) => x.id === fid);
      if (!fo) return;
      fo.files.push(...added);
      logAct(
        r,
        added.length === 1 ? `shared “${added[0].name}” in “${fo.name}”` : `shared ${added.length} files in “${fo.name}”`
      );
    });
  }
  prog.classList.add("hidden");
  status.classList.add("hidden");
  toast(
    `${added.length} file${added.length === 1 ? "" : "s"} shared${
      skipped ? ` · ${skipped} skipped (over 50 MB or storage full)` : ""
    }.`
  );
}

async function getFileBytes(meta) {
  const parts = [];
  let total = 0;
  for (let i = 0; i < (meta.chunks || 1); i++) {
    const row = await store.get(chunkKey(S.roomId, meta.id, i));
    if (!row) throw new Error("missing chunk " + i);
    const u8 = await decBytes(S.key, row.value);
    parts.push(u8);
    total += u8.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function findMeta(id) {
  const f = S.room.folders.find((x) => x.id === S.folderId);
  if (!f) return null;
  const meta = f.files.find((x) => x.id === id);
  if (!meta || !canSeeFile(f, meta, meId())) return null;
  return meta;
}

async function refreshRoomFromServer() {
  const row = await loadRoomRow();
  if (!row) return false;
  try {
    S.room = await decJSON(S.key, row.value);
    normalizeRoom(S.room);
    S.roomEtag = row.etag;
    return true;
  } catch {
    return false;
  }
}

async function previewFile(id) {
  return openFileViewer(id, false);
}

async function editFile(id) {
  return openFileViewer(id, true);
}

async function openFileViewer(id, wantEdit) {
  await refreshRoomFromServer();
  render();
  const folder = S.room.folders.find((x) => x.id === S.folderId);
  if (!folder) return toast("Open a folder first.");
  const meta = folder.files.find((x) => x.id === id);
  if (!meta || !canSeeFile(folder, meta, meId())) {
    return toast("You don't have access to that file anymore — try Sync now.");
  }
  const editable = canEditFile(folder, meta, meId());
  const editing = wantEdit && editable;
  if (wantEdit && !editable) {
    toast("You only have read access — opening preview.");
  } else {
    toast(editing ? "Opening editor…" : "Opening preview…");
  }
  try {
    const u8 = await getFileBytes(meta);
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(u8);
    } catch {
      return modal(`
        <h3>Can't open as text</h3>
        <p class="sub">“${esc(meta.name)}” doesn't look like a text file. You can still download it.</p>
        <div class="modal-actions"><button class="btn btn-primary" style="width:auto;margin:0" type="button" id="pvOk">OK</button></div>`);
    }
    window.__previewText = text;
    window.__editingFileId = editing ? meta.id : null;
    const access = fileAccess(folder, meta, meId());
    modal(
      `
      <h3 class="mono" style="font-size:15px">${esc(meta.name)}</h3>
      <p class="sub">${fmtSize(meta.size)} · shared by ${esc(displayName(meta.by))}${
        meta.dir ? ` · in ${esc(meta.dir)}/` : ""
      } · ${access === "edit" ? "you can edit" : "read only for you"}</p>
      ${
        editing
          ? `<textarea class="preview-pre file-editor" id="fileEditor" spellcheck="false"></textarea>`
          : `<pre class="preview-pre" id="filePreview"></pre>`
      }
      <div class="modal-actions">
        <button class="btn btn-quiet" type="button" id="pvCopy">Copy contents</button>
        <button class="btn btn-quiet" type="button" id="pvDl">Download</button>
        ${
          editable && !editing
            ? `<button class="btn btn-quiet" type="button" id="pvEdit">Edit</button>`
            : ""
        }
        ${
          editing
            ? `<button class="btn btn-primary" style="width:auto;margin:0" type="button" id="pvSave">Save changes</button>`
            : `<button class="btn btn-primary" style="width:auto;margin:0" type="button" id="pvClose">Close</button>`
        }
        ${editing ? `<button class="btn btn-quiet" type="button" id="pvClose">Cancel</button>` : ""}
      </div>`,
      true
    );
    $("pvCopy").onclick = () => {
      const val = editing && $("fileEditor") ? $("fileEditor").value : window.__previewText;
      navigator.clipboard.writeText(val).then(() => toast("Copied."));
    };
    $("pvDl").onclick = () => downloadFile(meta.id);
    if ($("fileEditor")) {
      $("fileEditor").value = text;
      $("fileEditor").focus();
    } else if ($("filePreview")) {
      $("filePreview").textContent = text;
    }
    if ($("pvEdit")) $("pvEdit").onclick = () => editFile(meta.id);
    if ($("pvSave")) {
      $("pvSave").onclick = async () => {
        const next = $("fileEditor").value;
        $("pvSave").disabled = true;
        $("pvSave").textContent = "Saving…";
        try {
          await saveFileContent(meta.id, next);
          window.__editingFileId = null;
          closeModal();
          toast("Saved.");
        } catch (e) {
          toast(e.message || "Couldn't save.");
          $("pvSave").disabled = false;
          $("pvSave").textContent = "Save changes";
          if (/permission|access/i.test(e.message || "")) {
            const ed = $("fileEditor");
            if (ed) {
              ed.readOnly = true;
              ed.title = "Your edit access was removed";
            }
          }
        }
      };
    }
    if ($("pvClose")) {
      $("pvClose").onclick = () => {
        window.__editingFileId = null;
        closeModal();
      };
    }
  } catch (e) {
    toast("Couldn't open that file — try Sync now. (" + (e.message || "error") + ")");
  }
  const ok = $("pvOk");
  if (ok) ok.onclick = closeModal;
}

async function saveFileContent(id, text) {
  await refreshRoomFromServer();
  let folder = S.room.folders.find((x) => x.id === S.folderId);
  let meta = folder && folder.files.find((x) => x.id === id);
  if (!folder || !meta) throw new Error("File not found — try Sync now.");
  if (!canEditFile(folder, meta, meId())) {
    render();
    throw new Error("You no longer have permission to edit this file.");
  }
  const u8 = new TextEncoder().encode(text);
  if (u8.length > MAX_RAW) throw new Error("File too large (50 MB max).");
  const oldChunks = meta.chunks || 1;
  const n = Math.max(1, Math.ceil(u8.length / CHUNK) || 1);

  for (let i = 0; i < n; i++) {
    await store.set(chunkKey(S.roomId, id, i), await encBytes(S.key, u8.subarray(i * CHUNK, (i + 1) * CHUNK)));
  }
  for (let i = n; i < oldChunks; i++) {
    await store.del(chunkKey(S.roomId, id, i));
  }

  // Re-check after upload in case permissions changed mid-save
  await refreshRoomFromServer();
  folder = S.room.folders.find((x) => x.id === S.folderId);
  meta = folder && folder.files.find((x) => x.id === id);
  if (!folder || !meta || !canEditFile(folder, meta, meId())) {
    render();
    throw new Error("You no longer have permission to edit this file.");
  }

  const fid = folder.id;
  await mutateRoom((r) => {
    const fo = r.folders.find((x) => x.id === fid);
    if (!fo) return;
    const fl = fo.files.find((x) => x.id === id);
    if (!fl) return;
    fl.size = u8.length;
    fl.chunks = n;
    fl.ts = Date.now();
    logAct(r, `edited “${fl.name}” in “${fo.name}”`);
  });
  render();
}

function triggerDownload(blob, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

async function downloadFile(id) {
  const meta = findMeta(id);
  if (!meta) return;
  try {
    triggerDownload(new Blob([await getFileBytes(meta)]), meta.name);
  } catch {
    toast("Couldn't fetch that file — try Sync now.");
  }
}

async function downloadFolderZip() {
  const f = S.room.folders.find((x) => x.id === S.folderId);
  if (!f) return;
  const files = f.files.filter((meta) => canSeeFile(f, meta, meId()));
  if (!files.length) return;
  if (typeof JSZip === "undefined") return toast("Zip support is still loading.");
  toast("Packing zip…");
  const zip = new JSZip();
  for (const meta of files) {
    try {
      zip.file((meta.dir ? meta.dir + "/" : "") + meta.name, await getFileBytes(meta));
    } catch {
      /* skip missing */
    }
  }
  triggerDownload(await zip.generateAsync({ type: "blob" }), f.name.replace(/\s+/g, "-") + ".zip");
}

async function deleteFile(id) {
  const f = S.room.folders.find((x) => x.id === S.folderId);
  const meta = findMeta(id);
  if (!f || !meta) return;
  if (!canDeleteFile(f, meta, meId())) return toast("You can only delete files you uploaded.");
  if (!confirm(`Delete “${meta.name}” for everyone in this room?`)) return;
  const fid = S.folderId;
  await mutateRoom((r) => {
    const fo = r.folders.find((x) => x.id === fid);
    if (!fo) return;
    fo.files = fo.files.filter((x) => x.id !== id);
    logAct(r, `deleted “${meta.name}” from “${fo.name}”`);
  });
  for (let i = 0; i < (meta.chunks || 1); i++) await store.del(chunkKey(S.roomId, id, i));
  toast("File deleted.");
}

function relTime(ts) {
  const d = Date.now() - ts;
  if (d < 60e3) return "just now";
  if (d < 3600e3) return Math.floor(d / 60e3) + " min ago";
  if (d < 86400e3) return Math.floor(d / 3600e3) + " h ago";
  return (
    new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
    " " +
    new Date(ts).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
  );
}

function showActivity() {
  const acts = S.room.activity || [];
  modal(
    `
    <h3>Activity</h3>
    <p class="sub">Everything that's happened in “${esc(S.room.name)}”, newest first.</p>
    ${
      acts.length
        ? acts
            .map(
              (a) => `
      <div class="act-row">
        <span class="avatar">${esc(a.by.slice(0, 2).toUpperCase())}</span>
        <span><strong>${esc(a.by)}</strong> ${esc(a.action)}</span>
        <span class="when">${relTime(a.ts)}</span>
      </div>`
            )
            .join("")
        : '<div class="empty" style="padding:24px"><h3>Quiet so far</h3><p>Uploads, folder changes, and joins will show up here.</p></div>'
    }
    <div class="modal-actions"><button class="btn btn-primary" style="width:auto;margin:0" type="button" id="actClose">Close</button></div>`,
    true
  );
  $("actClose").onclick = closeModal;
}

function showInvite(first) {
  modal(`
    <h3>${first ? "Your room is ready" : "Room key code"}</h3>
    <p class="sub">Anyone with this code can unlock the room, so share it privately. It's never shown in a link.</p>
    <div class="key-tag"><div><span class="lbl">Key code</span><span class="code">${esc(S.code)}</span></div></div>
    <div class="modal-actions">
      <button class="btn btn-quiet" type="button" id="invCopy">Copy code</button>
      <button class="btn btn-primary" style="width:auto;margin:0" type="button" id="invDone">Done</button>
    </div>`);
  $("invCopy").onclick = () =>
    navigator.clipboard.writeText(S.code).then(() => toast("Code copied.")).catch(() => toast("Copy failed — select it manually."));
  $("invDone").onclick = closeModal;
}

function wireUi() {
  $("tabCreate").onclick = () => setTab("create");
  $("tabJoin").onclick = () => setTab("join");
  $("btnCreate").onclick = createRoom;
  $("btnJoin").onclick = joinRoom;
  $("btnNewFolder").onclick = openNewFolder;
  $("btnActivity").onclick = showActivity;
  $("btnInvite").onclick = () => showInvite(false);
  $("btnSync").onclick = () => syncRoom(true);
  $("btnLeave").onclick = leaveRoom;
  $("fvDownloadAll").onclick = downloadFolderZip;
  $("fvSettings").onclick = openFolderSettings;
  $("fvDelete").onclick = deleteFolder;
  $("btnBrowse").onclick = () => $("filePick").click();
  $("filePick").onchange = (e) => {
    ingest(Array.from(e.target.files).map((f) => ({ file: f, dir: "" })));
    e.target.value = "";
  };

  $("folderList").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-folder]");
    if (btn) openFolder(btn.dataset.folder);
  });

  $("fileList").addEventListener("click", (e) => {
    const edit = e.target.closest("[data-edit]");
    if (edit) return editFile(edit.dataset.edit);
    const preview = e.target.closest("[data-preview]");
    if (preview) return previewFile(preview.dataset.preview);
    const perms = e.target.closest("[data-perms]");
    if (perms) return openFilePermissions(perms.dataset.perms);
    const dl = e.target.closest("[data-download]");
    if (dl) return downloadFile(dl.dataset.download);
    const del = e.target.closest("[data-delete]");
    if (del) return deleteFile(del.dataset.delete);
  });

  const dz = $("dropzone");
  dz.addEventListener("dragover", (e) => {
    e.preventDefault();
    dz.classList.add("armed");
  });
  dz.addEventListener("dragleave", () => dz.classList.remove("armed"));
  dz.addEventListener("drop", async (e) => {
    e.preventDefault();
    dz.classList.remove("armed");
    const entries = [];
    if (e.dataTransfer.items) {
      const jobs = [];
      for (const item of e.dataTransfer.items) {
        const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
        if (entry) jobs.push(walkEntry(entry, "", entries));
        else {
          const fl = item.getAsFile();
          if (fl) entries.push({ file: fl, dir: "" });
        }
      }
      await Promise.all(jobs);
    } else {
      for (const fl of e.dataTransfer.files) entries.push({ file: fl, dir: "" });
    }
    await ingest(entries);
  });

  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && S.roomId) syncRoom(false);
  });
  window.addEventListener("focus", () => {
    if (S.roomId) syncRoom(false);
  });

  ["cRoom", "cName", "cPass", "cPass2"].forEach((id) => {
    $(id).addEventListener("keydown", (e) => {
      if (e.key === "Enter") createRoom();
    });
  });
  ["jCode", "jName", "jPass"].forEach((id) => {
    $(id).addEventListener("keydown", (e) => {
      if (e.key === "Enter") joinRoom();
    });
  });
}

wireUi();
