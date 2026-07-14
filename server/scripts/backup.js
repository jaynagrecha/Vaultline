import { runBackup } from "../services/backup.js";

const dest = runBackup();
console.log("Backup written to", dest);
