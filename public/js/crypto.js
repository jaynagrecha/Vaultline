const te = new TextEncoder();
const td = new TextDecoder();

export function b64(u8) {
  let s = "";
  const CH = 0x8000;
  for (let i = 0; i < u8.length; i += CH) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
  }
  return btoa(s);
}

export function unb64(s) {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export async function deriveKey(code) {
  const mat = await crypto.subtle.importKey(
    "raw",
    te.encode(code.trim().toUpperCase()),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: te.encode("config-rooms-v1"),
      iterations: 150000,
      hash: "SHA-256",
    },
    mat,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function roomIdFromCode(code) {
  const h = await crypto.subtle.digest(
    "SHA-256",
    te.encode("config-rooms-id:" + code.trim().toUpperCase())
  );
  return Array.from(new Uint8Array(h).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function encBytes(key, u8) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, u8));
  return JSON.stringify({ iv: b64(iv), ct: b64(ct) });
}

export async function decBytes(key, str) {
  const { iv, ct } = JSON.parse(str);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(ct))
  );
}

export const encJSON = async (k, o) => encBytes(k, te.encode(JSON.stringify(o)));
export const decJSON = async (k, s) => JSON.parse(td.decode(await decBytes(k, s)));

export function makeCode() {
  const A = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const r = crypto.getRandomValues(new Uint8Array(12));
  let c = "";
  for (let i = 0; i < 12; i++) {
    c += A[r[i] % A.length];
    if (i === 3 || i === 7) c += "-";
  }
  return c;
}

export const uid = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

/** PBKDF2 password verifier (stored inside the encrypted room blob). */
export async function makePasswordVerifier(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const mat = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    mat,
    256
  );
  return { salt: b64(salt), hash: b64(new Uint8Array(bits)) };
}

export async function verifyPassword(password, verifier) {
  if (!verifier || !verifier.salt || !verifier.hash) return false;
  const salt = unb64(verifier.salt);
  const mat = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    mat,
    256
  );
  const got = b64(new Uint8Array(bits));
  return timingSafeEqual(got, verifier.hash);
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
