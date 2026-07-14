import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const KEY_RE = /^[a-zA-Z0-9:_-]{1,180}$/;

function safeSegment(seg) {
  if (!KEY_RE.test(seg)) throw new Error("invalid key");
  return seg;
}

/** Map logical key → path under dataDir (nested to avoid huge flat dirs). */
export function keyToPath(dataDir, key) {
  const k = safeSegment(key);
  const hash = crypto.createHash("sha256").update(k).digest("hex");
  return path.join(dataDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.bin`);
}

export function etagOf(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

export function createStore(dataDir) {
  async function ensureParent(filePath) {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
  }

  return {
    async get(key) {
      const filePath = keyToPath(dataDir, key);
      try {
        const buf = await fs.readFile(filePath);
        return { value: buf.toString("utf8"), etag: etagOf(buf) };
      } catch (err) {
        if (err && err.code === "ENOENT") return null;
        throw err;
      }
    },

    /**
     * Atomic write. If ifMatch is set, reject with conflict when etag differs.
     * Pass ifMatch === null to require the key does not exist (create-only).
     */
    async put(key, value, ifMatch) {
      const filePath = keyToPath(dataDir, key);
      const body = Buffer.from(String(value), "utf8");
      const nextEtag = etagOf(body);

      await ensureParent(filePath);

      let existing = null;
      try {
        const cur = await fs.readFile(filePath);
        existing = { etag: etagOf(cur) };
      } catch (err) {
        if (!err || err.code !== "ENOENT") throw err;
      }

      if (ifMatch === null) {
        if (existing) {
          const e = new Error("already exists");
          e.code = "CONFLICT";
          e.etag = existing.etag;
          throw e;
        }
      } else if (ifMatch !== undefined) {
        if (!existing) {
          const e = new Error("not found");
          e.code = "NOT_FOUND";
          throw e;
        }
        if (existing.etag !== ifMatch) {
          const e = new Error("etag mismatch");
          e.code = "CONFLICT";
          e.etag = existing.etag;
          throw e;
        }
      }

      const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
      await fs.writeFile(tmp, body, { flag: "w" });
      await fs.rename(tmp, filePath);
      return { etag: nextEtag };
    },

    async del(key) {
      const filePath = keyToPath(dataDir, key);
      try {
        await fs.unlink(filePath);
        return true;
      } catch (err) {
        if (err && err.code === "ENOENT") return false;
        throw err;
      }
    },

    async stats() {
      // light walk for health — count files under dataDir
      let files = 0;
      async function walk(dir) {
        let entries;
        try {
          entries = await fs.readdir(dir, { withFileTypes: true });
        } catch {
          return;
        }
        for (const ent of entries) {
          const p = path.join(dir, ent.name);
          if (ent.isDirectory()) await walk(p);
          else if (ent.isFile() && ent.name.endsWith(".bin")) files += 1;
        }
      }
      await walk(dataDir);
      return { files };
    },
  };
}
