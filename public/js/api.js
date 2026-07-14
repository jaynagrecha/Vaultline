/** Opaque ciphertext blob store over the Config Rooms API. */

function encodeKey(key) {
  return encodeURIComponent(key);
}

export function createApiStore() {
  return {
    mode: "server",
    async get(key) {
      const res = await fetch(`/api/blob/${encodeKey(key)}`, { cache: "no-store" });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`read failed (${res.status})`);
      const etag = (res.headers.get("ETag") || "").replace(/^"|"$/g, "");
      const value = await res.text();
      return { value, etag };
    },
    async set(key, value, { ifMatch } = {}) {
      const headers = { "Content-Type": "text/plain; charset=utf-8" };
      if (ifMatch === null) headers["If-None-Match"] = "*";
      else if (ifMatch) headers["If-Match"] = `"${ifMatch}"`;
      const res = await fetch(`/api/blob/${encodeKey(key)}`, {
        method: "PUT",
        headers,
        body: value,
      });
      if (res.status === 409) {
        const err = new Error("conflict");
        err.code = "CONFLICT";
        err.etag = (res.headers.get("ETag") || "").replace(/^"|"$/g, "") || null;
        throw err;
      }
      if (!res.ok) throw new Error(`write failed (${res.status})`);
      return { etag: (res.headers.get("ETag") || "").replace(/^"|"$/g, "") };
    },
    async del(key) {
      const res = await fetch(`/api/blob/${encodeKey(key)}`, { method: "DELETE" });
      if (!res.ok && res.status !== 404) throw new Error(`delete failed (${res.status})`);
    },
  };
}
