import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { categorizeAction, explainAuditEvent, listActionCatalog, AUDIT_CATEGORIES, AUDIT_OUTCOMES, resolveAuditOutcome } from "./auditExplain.js";

const folderLookup = db.prepare(`SELECT id, name, parent_id FROM folders WHERE id = ?`);

/** Build "Parent / Child" path for a folder id. */
export function resolveFolderPath(folderId) {
  if (!folderId) return null;
  const parts = [];
  let id = folderId;
  const seen = new Set();
  while (id && !seen.has(id)) {
    seen.add(id);
    const row = folderLookup.get(id);
    if (!row) break;
    parts.unshift(row.name);
    id = row.parent_id || null;
  }
  return parts.length ? parts.join(" / ") : null;
}

export function audit({
  orgId = null,
  projectId = null,
  actorId = null,
  action,
  targetType = null,
  targetId = null,
  meta = null,
  ip = null,
  userAgent = null,
  outcome = null,
}) {
  const resolved =
    outcome === "failure" || outcome === "success"
      ? outcome
      : /_failed$|_denied$/.test(String(action || ""))
        ? "failure"
        : "success";
  db.prepare(
    `INSERT INTO audit_events (id, ts, org_id, project_id, actor_id, action, target_type, target_id, meta_json, ip, user_agent, outcome)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    uuid(),
    now(),
    orgId,
    projectId,
    actorId,
    action,
    targetType,
    targetId,
    meta ? JSON.stringify(meta) : null,
    ip || null,
    userAgent ? String(userAgent).slice(0, 300) : null,
    resolved
  );
}

/** Attach IP / UA from Express req onto audit calls. */
export function auditFromReq(req, fields) {
  return audit({
    ...fields,
    ip: req.ip || req.socket?.remoteAddress || null,
    userAgent: req.get?.("user-agent") || null,
  });
}

function enrich(row) {
  const meta = row.meta_json ? JSON.parse(row.meta_json) : null;
  const folderId =
    row.resolved_folder_id ||
    meta?.folderId ||
    (row.target_type === "folder" ? row.target_id : null) ||
    null;
  const folderPath =
    meta?.folderPath ||
    resolveFolderPath(folderId) ||
    row.folder_name ||
    null;
  const targetName =
    row.target_name ||
    meta?.name ||
    meta?.orgName ||
    meta?.projectName ||
    meta?.email ||
    meta?.memberName ||
    null;
  const event = {
    ...row,
    meta,
    meta_json: undefined,
    target_name: targetName || null,
    folder_id: folderId || null,
    folder_name: row.folder_name || (folderPath ? folderPath.split(" / ").pop() : null),
    folder_path: folderPath,
    outcome: resolveAuditOutcome({ ...row, meta }),
  };
  const explained = explainAuditEvent(event);
  return {
    ...event,
    ...explained,
  };
}

export function listAudit({
  orgId = null,
  projectId = null,
  actorId = null,
  action = null,
  targetType = null,
  category = null,
  outcome = null,
  q = null,
  limit = 200,
  since = null,
  until = null,
} = {}) {
  let sql = `SELECT a.*, u.email AS actor_email, u.name AS actor_name,
      o.name AS org_name, p.name AS project_name,
      CASE
        WHEN a.target_type = 'file' THEN f.name
        WHEN a.target_type = 'folder' THEN fo.name
        WHEN a.target_type = 'org' THEN o2.name
        WHEN a.target_type = 'project' THEN p2.name
        WHEN a.target_type = 'user' THEN COALESCE(tu.name, tu.email)
        ELSE NULL
      END AS target_name,
      CASE
        WHEN a.target_type = 'file' THEN f.folder_id
        WHEN a.target_type = 'folder' THEN a.target_id
        ELSE NULL
      END AS resolved_folder_id,
      CASE
        WHEN a.target_type = 'file' THEN ff.name
        WHEN a.target_type = 'folder' THEN fo.name
        ELSE NULL
      END AS folder_name,
      tu.email AS target_user_email,
      tu.name AS target_user_name
    FROM audit_events a
    LEFT JOIN users u ON u.id = a.actor_id
    LEFT JOIN orgs o ON o.id = a.org_id
    LEFT JOIN projects p ON p.id = a.project_id
    LEFT JOIN files f ON a.target_type = 'file' AND f.id = a.target_id
    LEFT JOIN folders ff ON a.target_type = 'file' AND ff.id = f.folder_id
    LEFT JOIN folders fo ON a.target_type = 'folder' AND fo.id = a.target_id
    LEFT JOIN orgs o2 ON a.target_type = 'org' AND o2.id = a.target_id
    LEFT JOIN projects p2 ON a.target_type = 'project' AND p2.id = a.target_id
    LEFT JOIN users tu ON a.target_type = 'user' AND tu.id = a.target_id
    WHERE 1=1`;
  const params = [];
  if (orgId) {
    sql += ` AND a.org_id = ?`;
    params.push(orgId);
  }
  if (projectId) {
    sql += ` AND a.project_id = ?`;
    params.push(projectId);
  }
  if (actorId) {
    sql += ` AND a.actor_id = ?`;
    params.push(actorId);
  }
  if (action) {
    sql += ` AND a.action = ?`;
    params.push(action);
  }
  if (targetType) {
    sql += ` AND a.target_type = ?`;
    params.push(targetType);
  }
  if (since) {
    sql += ` AND a.ts >= ?`;
    params.push(Number(since));
  }
  if (until) {
    sql += ` AND a.ts <= ?`;
    params.push(Number(until));
  }
  if (q) {
    const like = `%${String(q).trim()}%`;
    sql += ` AND (
      a.action LIKE ? OR a.target_type LIKE ? OR a.target_id LIKE ? OR a.meta_json LIKE ?
      OR u.email LIKE ? OR u.name LIKE ? OR o.name LIKE ? OR p.name LIKE ?
      OR a.ip LIKE ?
      OR f.name LIKE ? OR fo.name LIKE ? OR ff.name LIKE ? OR o2.name LIKE ? OR p2.name LIKE ?
      OR tu.email LIKE ? OR tu.name LIKE ?
    )`;
    params.push(like, like, like, like, like, like, like, like, like, like, like, like, like, like, like, like);
  }

  const want = Math.min(Number(limit) || 200, 10000);
  const needsOverfetch =
    (category && AUDIT_CATEGORIES[category]) || outcome === "success" || outcome === "failure";
  const fetchLimit = needsOverfetch ? Math.min(want * 8, 10000) : want;
  sql += ` ORDER BY a.ts DESC LIMIT ?`;
  params.push(fetchLimit);

  let rows = db.prepare(sql).all(...params).map(enrich);
  if (category && AUDIT_CATEGORIES[category]) {
    rows = rows.filter((e) => e.category === category);
  }
  if (outcome === "success" || outcome === "failure") {
    rows = rows.filter((e) => e.outcome === outcome);
  }
  return rows.slice(0, want);
}

export function exportAuditJson(opts) {
  const rows = listAudit({ ...opts, limit: opts.limit || 10000 });
  return {
    exportedAt: new Date().toISOString(),
    count: rows.length,
    filters: {
      orgId: opts.orgId || null,
      projectId: opts.projectId || null,
      actorId: opts.actorId || null,
      action: opts.action || null,
      targetType: opts.targetType || null,
      category: opts.category || null,
      outcome: opts.outcome || null,
      q: opts.q || null,
      since: opts.since || null,
      until: opts.until || null,
    },
    events: rows,
  };
}

/** Distinct values for admin filter dropdowns. */
export function listAuditFilterOptions() {
  const orgs = db
    .prepare(
      `SELECT DISTINCT o.id, o.name FROM audit_events a
       JOIN orgs o ON o.id = a.org_id
       WHERE a.org_id IS NOT NULL
       ORDER BY o.name COLLATE NOCASE`
    )
    .all();
  const projects = db
    .prepare(
      `SELECT DISTINCT p.id, p.name, p.org_id FROM audit_events a
       JOIN projects p ON p.id = a.project_id
       WHERE a.project_id IS NOT NULL
       ORDER BY p.name COLLATE NOCASE`
    )
    .all();
  const actors = db
    .prepare(
      `SELECT DISTINCT u.id, u.name, u.email FROM audit_events a
       JOIN users u ON u.id = a.actor_id
       WHERE a.actor_id IS NOT NULL
       ORDER BY u.name COLLATE NOCASE`
    )
    .all();
  const targetTypes = db
    .prepare(
      `SELECT DISTINCT target_type AS id FROM audit_events
       WHERE target_type IS NOT NULL AND target_type != ''
       ORDER BY target_type`
    )
    .all()
    .map((r) => ({ id: r.id, label: r.id }));
  const actionsSeen = db
    .prepare(`SELECT DISTINCT action FROM audit_events ORDER BY action`)
    .all()
    .map((r) => r.action);
  const catalog = listActionCatalog();
  const byAction = new Map(catalog.map((a) => [a.action, a]));
  const actions = [...new Set([...actionsSeen, ...catalog.map((a) => a.action)])]
    .sort()
    .map((action) => {
      const c = byAction.get(action);
      return {
        action,
        label: c?.label || action,
        category: c?.category || categorizeAction(action),
      };
    });

  return {
    categories: Object.values(AUDIT_CATEGORIES),
    outcomes: Object.values(AUDIT_OUTCOMES),
    actions,
    orgs,
    projects,
    actors,
    targetTypes,
  };
}
