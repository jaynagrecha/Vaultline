import { db } from "../db.js";

const cols = db.prepare("PRAGMA table_info(users)").all().map((c) => c.name);
console.log("email_verified_at", cols.includes("email_verified_at"));
console.log(
  "email_challenges",
  !!db.prepare("SELECT 1 AS x FROM sqlite_master WHERE type='table' AND name='email_challenges'").get()
);
const n = db
  .prepare("SELECT COUNT(*) AS c FROM users WHERE status = 'active' AND email_verified_at IS NOT NULL")
  .get();
console.log("active_verified", n.c);
