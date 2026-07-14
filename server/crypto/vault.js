import crypto from "node:crypto";
import { config } from "../config.js";

const te = new TextEncoder();

export function b64(buf) {
  return Buffer.from(buf).toString("base64");
}

export function unb64(s) {
  return Buffer.from(s, "base64");
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function generateProjectDek() {
  return crypto.randomBytes(32);
}

/** Wrap project DEK with master key (AES-256-GCM). */
export function wrapDek(dek) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", config.masterKey, iv);
  const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
  const tag = cipher.getAuthTag();
  return b64(Buffer.concat([iv, tag, ct]));
}

export function unwrapDek(wrapped) {
  const buf = unb64(wrapped);
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", config.masterKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function encryptBuffer(dek, plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

export function decryptBuffer(dek, blob) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", dek, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function hashInviteCode(code) {
  return sha256(`invite:${String(code).trim().toUpperCase()}`);
}

export function makeInviteCode() {
  const A = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const r = crypto.randomBytes(12);
  let c = "";
  for (let i = 0; i < 12; i++) {
    c += A[r[i] % A.length];
    if (i === 3 || i === 7) c += "-";
  }
  return c;
}
