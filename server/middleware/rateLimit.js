import rateLimit from "express-rate-limit";

/** Prefer authenticated user id so local multi-tab / shared NAT IPs don't collide. */
function clientKey(req) {
  if (req.user?.id) return `u:${req.user.id}`;
  return `ip:${req.ip || "unknown"}`;
}

/** Live polls (?sync=1) and session probes must not burn the write budget. */
function skipPollTraffic(req) {
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  if (req.query?.sync === "1") return true;
  const p = req.path || "";
  return (
    p === "/auth/me" ||
    p === "/auth/meta" ||
    p === "/health" ||
    p.startsWith("/auth/admin/audit") ||
    p.startsWith("/auth/admin/catalog") ||
    p.startsWith("/auth/admin/users")
  );
}

const limiterBase = {
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
};

export const authLimiter = rateLimit({
  ...limiterBase,
  windowMs: 15 * 60 * 1000,
  max: 40,
  message: { error: "Too many attempts — try again later" },
});

/**
 * Global API budget — keyed per user when logged in.
 * Polling GETs are skipped so interactive uploads / ACL edits are not starved.
 */
export const apiLimiter = rateLimit({
  ...limiterBase,
  windowMs: 60 * 1000,
  max: 600,
  keyGenerator: clientKey,
  skip: skipPollTraffic,
  message: { error: "Rate limit exceeded — wait a moment and try again" },
});

export const uploadLimiter = rateLimit({
  ...limiterBase,
  windowMs: 60 * 1000,
  max: 60,
  keyGenerator: clientKey,
  message: { error: "Upload rate limit exceeded — wait a moment and try again" },
});
