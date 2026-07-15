import crypto from "node:crypto";
import { v4 as uuid } from "uuid";
import { db, now } from "../db.js";
import { config } from "../config.js";
import { sha256 } from "../crypto/vault.js";
import { audit } from "./audit.js";
import { findUserByEmail, findUserById } from "./auth.js";
import { sendActivationEmail, sendPasswordResetEmail } from "./mail.js";

const TTL_MS = 30 * 60 * 1000;

function sixDigitCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

function publicBase() {
  return (config.publicUrl || "").replace(/\/$/, "") || "http://localhost:3847";
}

function issueChallenge(userId, purpose) {
  db.prepare(`DELETE FROM email_challenges WHERE user_id = ? AND purpose = ? AND used_at IS NULL`).run(
    userId,
    purpose
  );
  const code = sixDigitCode();
  const token = crypto.randomBytes(24).toString("base64url");
  const id = uuid();
  const ts = now();
  db.prepare(
    `INSERT INTO email_challenges (id, user_id, purpose, code_hash, token_hash, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, userId, purpose, sha256(code), sha256(token), ts + TTL_MS, ts);
  return { code, token, expiresAt: ts + TTL_MS };
}

function consumeChallenge({ userId, purpose, code, token }) {
  const rows = db
    .prepare(
      `SELECT * FROM email_challenges
       WHERE user_id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
       ORDER BY created_at DESC`
    )
    .all(userId, purpose, now());
  if (!rows.length) {
    throw Object.assign(new Error("Code expired or invalid — request a new one"), { code: "VALIDATION" });
  }
  let match = null;
  if (token) {
    const th = sha256(String(token).trim());
    match = rows.find((r) => r.token_hash === th) || null;
  } else if (code) {
    const ch = sha256(String(code).trim());
    match = rows.find((r) => r.code_hash === ch) || null;
  }
  if (!match) {
    throw Object.assign(new Error("Code expired or invalid — request a new one"), { code: "VALIDATION" });
  }
  db.prepare(`UPDATE email_challenges SET used_at = ? WHERE id = ?`).run(now(), match.id);
  db.prepare(
    `UPDATE email_challenges SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL`
  ).run(now(), userId, purpose);
  return match;
}

export async function sendActivationForUser(user) {
  const { code, token } = issueChallenge(user.id, "activate");
  const link = `${publicBase()}/?activate=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`;
  await sendActivationEmail({ to: user.email, name: user.name, code, link });
  return { emailed: true };
}

export async function resendActivation(email) {
  const user = findUserByEmail(email);
  // Don't leak whether the account exists
  if (!user || user.status === "disabled") return { ok: true };
  if (user.email_verified_at && user.status === "active") return { ok: true };
  await sendActivationForUser(user);
  audit({
    actorId: user.id,
    action: "user.activation_resent",
    targetType: "user",
    targetId: user.id,
    meta: { email: user.email },
  });
  return { ok: true };
}

export function activateAccount({ email, code, token }) {
  const user = findUserByEmail(email);
  if (!user) throw Object.assign(new Error("Invalid activation"), { code: "VALIDATION" });
  if (user.status === "disabled") {
    throw Object.assign(new Error("Account is disabled"), { code: "FORBIDDEN" });
  }
  if (user.email_verified_at && user.status === "active") {
    return { user, alreadyActive: true };
  }
  consumeChallenge({ userId: user.id, purpose: "activate", code, token });
  const ts = now();
  db.prepare(`UPDATE users SET status = 'active', email_verified_at = ? WHERE id = ?`).run(ts, user.id);
  audit({
    actorId: user.id,
    action: "user.activated",
    targetType: "user",
    targetId: user.id,
    meta: { email: user.email },
  });
  return { user: findUserById(user.id), alreadyActive: false };
}

export async function requestPasswordReset(email) {
  const user = findUserByEmail(email);
  if (!user || user.status === "disabled") return { ok: true };
  if (!user.email_verified_at || user.status !== "active") {
    // Still ok response; optionally nudge activation
    return { ok: true, needsActivation: true };
  }
  const { code, token } = issueChallenge(user.id, "reset");
  const link = `${publicBase()}/?reset=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`;
  await sendPasswordResetEmail({ to: user.email, name: user.name, code, link });
  audit({
    actorId: user.id,
    action: "user.password_reset_requested",
    targetType: "user",
    targetId: user.id,
  });
  return { ok: true };
}

export async function resetPassword({ email, code, token, password }) {
  if (!password || password.length < 10) {
    throw Object.assign(new Error("Password must be at least 10 characters"), { code: "VALIDATION" });
  }
  const user = findUserByEmail(email);
  if (!user || user.status === "disabled") {
    throw Object.assign(new Error("Invalid reset request"), { code: "VALIDATION" });
  }
  consumeChallenge({ userId: user.id, purpose: "reset", code, token });
  const bcrypt = (await import("bcryptjs")).default;
  const password_hash = await bcrypt.hash(password, 12);
  db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(password_hash, user.id);
  const { destroyAllUserSessions } = await import("./auth.js");
  destroyAllUserSessions(user.id);
  audit({
    actorId: user.id,
    action: "user.password_reset",
    targetType: "user",
    targetId: user.id,
  });
  return { ok: true };
}
