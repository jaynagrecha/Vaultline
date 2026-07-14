import fs from "node:fs";
import path from "node:path";
import { config } from "../config.js";
import { runBackup } from "../services/backup.js";
import { runRetentionPurge } from "../services/retention.js";

const STATE_FILE = () => path.join(config.dataDir, "jobs-state.json");

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE(), "utf8"));
  } catch {
    return {};
  }
}

function writeState(state) {
  fs.writeFileSync(STATE_FILE(), JSON.stringify(state, null, 2));
}

function dayKey(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

/**
 * In-process jobs (Render Disk is not shared with separate Cron services).
 * Runs a light tick every hour; daily backup + retention at most once per UTC day.
 */
export function startBackgroundJobs() {
  const enabled = process.env.ENABLE_JOBS !== "0";
  if (!enabled) {
    console.log("Background jobs disabled (ENABLE_JOBS=0)");
    return;
  }

  const tick = () => {
    try {
      const state = readState();
      const today = dayKey();
      if (state.lastRetentionDay !== today) {
        const result = runRetentionPurge({ dryRun: false });
        state.lastRetentionDay = today;
        state.lastRetention = { at: new Date().toISOString(), ...result };
        writeState(state);
        console.log(`Retention purge: deleted ${result.deleted} / scanned ${result.scanned}`);
      }
      if (process.env.AUTO_BACKUP !== "0" && state.lastBackupDay !== today) {
        const dest = runBackup();
        state.lastBackupDay = today;
        state.lastBackup = { at: new Date().toISOString(), path: dest };
        writeState(state);
        console.log(`Auto backup: ${dest}`);
      }
    } catch (e) {
      console.error("Background job error:", e.message);
    }
  };

  // First tick shortly after boot, then hourly
  setTimeout(tick, 15_000);
  setInterval(tick, 60 * 60 * 1000);
  console.log("Background jobs scheduled (retention + daily backup on Disk)");
}
