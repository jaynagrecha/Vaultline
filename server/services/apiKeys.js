import crypto from "node:crypto";
import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { audit } from "./audit.js";
import { findUserById, publicUser } from "./auth.js";

function hashKey(raw) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function makeSecret() {
  return `vl_${crypto.randomBytes(24).toString("base64url")}`;
}

/** Create a personal API key. Raw secret returned once. */
export function createApiKey({ userId, name, scopes = ["*"] }) {
  const label = String(name || "API key").trim().slice(0, 80) || "API key";
  const raw = makeSecret();
  const id = uuid();
  const prefix = raw.slice(0, 10);
  const ts = now();
  db.prepare(
    `INSERT INTO api_keys (id, user_id, name, prefix, key_hash, scopes_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, userId, label, prefix, hashKey(raw), JSON.stringify(scopes), ts);
  audit({
    actorId: userId,
    action: "api_key.created",
    targetType: "api_key",
    targetId: id,
    meta: { name: label, prefix },
  });
  return { id, name: label, prefix, scopes, createdAt: ts, secret: raw };
}

export function listApiKeys(userId) {
  return db
    .prepare(
      `SELECT id, name, prefix, scopes_json AS scopesJson, created_at AS createdAt, last_used_at AS lastUsedAt, revoked_at AS revokedAt
       FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`
    )
    .all(userId)
    .map((r) => ({
      id: r.id,
      name: r.name,
      prefix: r.prefix,
      scopes: JSON.parse(r.scopesJson || '["*"]'),
      createdAt: r.createdAt,
      lastUsedAt: r.lastUsedAt,
      revokedAt: r.revokedAt,
      active: !r.revokedAt,
    }));
}

export function revokeApiKey({ keyId, userId }) {
  const row = db.prepare(`SELECT * FROM api_keys WHERE id = ? AND user_id = ?`).get(keyId, userId);
  if (!row) throw Object.assign(new Error("API key not found"), { code: "NOT_FOUND" });
  if (row.revoked_at) return { id: keyId, alreadyRevoked: true };
  db.prepare(`UPDATE api_keys SET revoked_at = ? WHERE id = ?`).run(now(), keyId);
  audit({
    actorId: userId,
    action: "api_key.revoked",
    targetType: "api_key",
    targetId: keyId,
    meta: { name: row.name, prefix: row.prefix },
  });
  return { id: keyId, revoked: true };
}

/** Resolve Bearer token to public user, or null. */
export function resolveApiKeyUser(rawToken) {
  if (!rawToken || !String(rawToken).startsWith("vl_")) return null;
  const row = db.prepare(`SELECT * FROM api_keys WHERE key_hash = ?`).get(hashKey(rawToken));
  if (!row || row.revoked_at) return null;
  const user = findUserById(row.user_id);
  if (!user || user.status !== "active") return null;
  db.prepare(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`).run(now(), row.id);
  return { user: publicUser(user), apiKeyId: row.id, scopes: JSON.parse(row.scopes_json || '["*"]') };
}
