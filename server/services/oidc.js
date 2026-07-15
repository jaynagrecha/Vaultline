import { Issuer, generators } from "openid-client";
import { v4 as uuid } from "uuid";
import { config } from "../config.js";
import { db, now } from "../db.js";
import { findUserByEmail, findUserById, shouldGrantPlatformAdminOnSignup } from "./auth.js";

let cachedClient = null;

export function oidcEnabled() {
  return config.oidc.enabled;
}

async function getClient() {
  if (!oidcEnabled()) throw new Error("OIDC disabled");
  if (cachedClient) return cachedClient;
  const issuer = await Issuer.discover(config.oidc.issuer);
  cachedClient = new issuer.Client({
    client_id: config.oidc.clientId,
    client_secret: config.oidc.clientSecret,
    redirect_uris: [`${config.publicUrl || "http://127.0.0.1:" + config.port}/api/auth/oidc/callback`],
    response_types: ["code"],
  });
  return cachedClient;
}

export async function beginOidcLogin() {
  const client = await getClient();
  const state = generators.state();
  const nonce = generators.nonce();
  db.prepare(`INSERT INTO oidc_states (state, nonce, expires_at) VALUES (?, ?, ?)`).run(
    state,
    nonce,
    now() + 10 * 60 * 1000
  );
  return client.authorizationUrl({
    scope: "openid email profile",
    state,
    nonce,
  });
}

export async function finishOidcLogin(query) {
  const client = await getClient();
  const stateRow = db.prepare(`SELECT * FROM oidc_states WHERE state = ?`).get(query.state);
  if (!stateRow || stateRow.expires_at < now()) throw new Error("Invalid OIDC state");
  db.prepare(`DELETE FROM oidc_states WHERE state = ?`).run(query.state);

  const params = client.callbackParams(`?${new URLSearchParams(query).toString()}`);
  const tokenSet = await client.callback(
    `${config.publicUrl || "http://127.0.0.1:" + config.port}/api/auth/oidc/callback`,
    params,
    { state: query.state, nonce: stateRow.nonce }
  );
  const claims = tokenSet.claims();
  const email = claims.email;
  const name = claims.name || claims.preferred_username || email;
  if (!email) throw new Error("OIDC provider did not return email");

  let user = findUserByEmail(email);
  if (!user) {
    const id = uuid();
    const asAdmin = shouldGrantPlatformAdminOnSignup(email) ? 1 : 0;
    db.prepare(
      `INSERT INTO users (id, email, name, password_hash, status, is_platform_admin, oidc_sub, created_at, email_verified_at)
       VALUES (?, ?, ?, NULL, 'active', ?, ?, ?, ?)`
    ).run(id, email.toLowerCase(), name, asAdmin, claims.sub || null, now(), now());
    user = findUserById(id);
  } else if (user.status !== "active") {
    throw new Error("Account disabled");
  } else {
    if (claims.sub) {
      db.prepare(`UPDATE users SET oidc_sub = ? WHERE id = ?`).run(claims.sub, user.id);
    }
    if (!user.email_verified_at) {
      db.prepare(`UPDATE users SET email_verified_at = ? WHERE id = ?`).run(now(), user.id);
    }
    if (shouldGrantPlatformAdminOnSignup(email) && !user.is_platform_admin) {
      db.prepare(`UPDATE users SET is_platform_admin = 1 WHERE id = ?`).run(user.id);
      user = findUserById(user.id);
    }
  }
  return user;
}
