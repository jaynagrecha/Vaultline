# Deploy Vaultline on Render (Disk + SQLite)

## Architecture (locked)

```
Browser → Render Web Service (Node)
              └─ Persistent Disk @ /var/data
                    ├─ enterprise.db   (SQLite)
                    ├─ files/          (encrypted blobs)
                    └─ backups/
```

- **Auth:** local register/login for everyone (including non-org users). Optional OIDC later.
- **One instance only** while using Disk (do not scale to multiple instances).
## Disk size

In Render → **Disk**, set size to **5 GB** (or more). `render.yaml` requests 5 GB for new Blueprint deploys; existing Disks must be increased in the UI (you can grow, not shrink).

## One-time setup

1. Create a **Web Service** from this repo (or Blueprint with `render.yaml`).
2. Confirm **Disk**:
   - Mount path: `/var/data`
   - Size: **5 GB** (or more)
3. **Environment** (Render → Environment):

| Key | Value |
|-----|--------|
| `NODE_ENV` | `production` |
| `DATA_DIR` | `/var/data` |
| `MASTER_KEY` | Generate once and **never rotate** casually (wraps project keys) |
| `PUBLIC_URL` | `https://YOUR-SERVICE.onrender.com` |
| `BOOTSTRAP_ADMIN_EMAIL` | Email of the first platform admin (register that user after deploy) |

4. Deploy. Open `https://YOUR-SERVICE.onrender.com/api/health` — expect `"ok": true`, `writable: true`, `dbOk: true`.
5. Register the bootstrap email (or login), then use Admin console.

## Email (activation + forgot password)

Set these on Render → **Environment** (SMTP):

| Key | Example |
|-----|---------|
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |
| `SMTP_SECURE` | `false` (use `true` for port 465) |
| `SMTP_USER` | your SMTP username |
| `SMTP_PASS` | app password / SMTP password |
| `SMTP_FROM` | `Vaultline <you@yourdomain.com>` |
| `PUBLIC_URL` | `https://vaultline-h15c.onrender.com` (used in email links) |

**Flow:** Register → email with **6-digit code** + **activation link** → Activate tab / link → then Sign in.  
**Forgot password:** Sign in → Forgot password → email code/link → set new password.

Existing accounts already on the Disk stay active (no re-activation).

## Do not

- Rotate `MASTER_KEY` after real data exists (files become undecryptable).
- Remove the Disk or change mount path without migrating `/var/data`.
- Enable horizontal scaling with this Disk layout.

## Next (Phases B → C)

Phase **B** (in this build):
- Backup **list / verify / restore** (Admin → Manage backups)
- **Retention purge** (daily in-process job + `POST /api/admin/retention/run`)
- **Edit conflict** via `baseVersion` on save (409 if stale)
- Jobs run **inside the web service** (Render Disk is not shared with separate Cron services)

Phase **C** (in progress / partial):
- Nested folders
- **API keys** (sidebar → API keys; `Authorization: Bearer vl_…`)
- **Webhooks** (select an org → Webhooks; HTTPS + HMAC `X-Vaultline-Signature`)
- Still open: optional OIDC polish, SAML, SCIM

### Job env (optional)

| Key | Default | Meaning |
|-----|---------|---------|
| `ENABLE_JOBS` | on | Set `0` to disable background retention/backup |
| `AUTO_BACKUP` | on | Set `0` to skip daily auto backup (manual still works) |
