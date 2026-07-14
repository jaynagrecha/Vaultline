import crypto from "node:crypto";
import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { audit } from "./audit.js";
import { requireOrgRole } from "./orgs.js";

export const WEBHOOK_EVENT_TYPES = [
  "file.uploaded",
  "file.version_saved",
  "file.deleted",
  "folder.created",
  "folder.acl_updated",
  "folder.deleted",
  "project.member_added",
  "project.joined",
];

function signBody(secret, body) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

export function createWebhook({ orgId, url, events, actorId }) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  const target = String(url || "").trim();
  if (!/^https:\/\//i.test(target)) {
    throw Object.assign(new Error("Webhook URL must be https://"), { code: "VALIDATION" });
  }
  const ev = (events || []).filter((e) => WEBHOOK_EVENT_TYPES.includes(e));
  if (!ev.length) {
    throw Object.assign(new Error("Select at least one event"), { code: "VALIDATION" });
  }
  const id = uuid();
  const secret = `whsec_${crypto.randomBytes(24).toString("base64url")}`;
  const ts = now();
  db.prepare(
    `INSERT INTO webhooks (id, org_id, url, secret, events_json, created_by, created_at, active)
     VALUES (?, ?, ?, ?, ?, ?, ?, 1)`
  ).run(id, orgId, target, secret, JSON.stringify(ev), actorId, ts);
  audit({
    orgId,
    actorId,
    action: "webhook.created",
    targetType: "webhook",
    targetId: id,
    meta: { url: target, events: ev },
  });
  return { id, orgId, url: target, events: ev, secret, createdAt: ts, active: true };
}

export function listWebhooks(orgId, actorId) {
  requireOrgRole(orgId, actorId, ["owner", "admin", "member"]);
  return db
    .prepare(
      `SELECT id, org_id AS orgId, url, events_json AS eventsJson, created_at AS createdAt, active, last_status AS lastStatus, last_delivery_at AS lastDeliveryAt
       FROM webhooks WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(orgId)
    .map((r) => ({
      id: r.id,
      orgId: r.orgId,
      url: r.url,
      events: JSON.parse(r.eventsJson || "[]"),
      createdAt: r.createdAt,
      active: !!r.active,
      lastStatus: r.lastStatus,
      lastDeliveryAt: r.lastDeliveryAt,
    }));
}

export function deleteWebhook({ orgId, webhookId, actorId }) {
  requireOrgRole(orgId, actorId, ["owner", "admin"]);
  const row = db.prepare(`SELECT * FROM webhooks WHERE id = ? AND org_id = ?`).get(webhookId, orgId);
  if (!row) throw Object.assign(new Error("Webhook not found"), { code: "NOT_FOUND" });
  db.prepare(`DELETE FROM webhooks WHERE id = ?`).run(webhookId);
  audit({
    orgId,
    actorId,
    action: "webhook.deleted",
    targetType: "webhook",
    targetId: webhookId,
    meta: { url: row.url },
  });
  return { ok: true };
}

/**
 * Fire-and-forget delivery for matching org webhooks.
 * Never throws to callers.
 */
export function dispatchWebhooks(orgId, action, payload = {}) {
  if (!orgId || !WEBHOOK_EVENT_TYPES.includes(action)) return;
  let hooks = [];
  try {
    hooks = db
      .prepare(`SELECT * FROM webhooks WHERE org_id = ? AND active = 1`)
      .all(orgId)
      .filter((h) => {
        try {
          return JSON.parse(h.events_json || "[]").includes(action);
        } catch {
          return false;
        }
      });
  } catch {
    return;
  }
  if (!hooks.length) return;

  const bodyObj = {
    id: uuid(),
    type: action,
    createdAt: new Date().toISOString(),
    data: payload,
  };
  const body = JSON.stringify(bodyObj);

  for (const hook of hooks) {
    const sig = signBody(hook.secret, body);
    setImmediate(() => {
      deliver(hook, body, sig).catch(() => {});
    });
  }
}

async function deliver(hook, body, signature) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch(hook.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "Vaultline-Webhook/1.0",
        "x-vaultline-signature": `sha256=${signature}`,
        "x-vaultline-event": JSON.parse(body).type,
      },
      body,
      signal: ctrl.signal,
    });
    db.prepare(`UPDATE webhooks SET last_status = ?, last_delivery_at = ? WHERE id = ?`).run(
      String(res.status),
      now(),
      hook.id
    );
  } catch (e) {
    db.prepare(`UPDATE webhooks SET last_status = ?, last_delivery_at = ? WHERE id = ?`).run(
      `error:${String(e.message || e).slice(0, 80)}`,
      now(),
      hook.id
    );
  } finally {
    clearTimeout(t);
  }
}
