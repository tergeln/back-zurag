# Backups and restore

## What must be backed up

| Data | Where | Replaceable? |
|---|---|---|
| Orders, payments, ledger, payouts, users, events, photo records | Supabase Postgres | **No.** Financial records must be kept. |
| Original photos | R2 `originals/` | **No.** Customers paid for these. |
| Previews, thumbnails | R2 `previews/`, `thumbs/` | Yes: re-run the worker (set `status = 'processing'`). |
| Face embeddings | Postgres `face_embeddings` | Yes: set `faces_indexed_at = null`, then run the worker. |
| Secrets (`.env` files) | Your PC | Keep a copy in a password manager. Keys can be re-issued if lost. |

**Supabase free plan has no downloadable automatic backups** (Pro, about $25/month, has daily backups).
Until then, make your own database dumps.

## Weekly database backup (free)

You need the database connection string from Supabase: **Project Settings → Database → Connection string → URI**,
including the database password. Never commit it or paste it into chat.

```bash
# from back-zurag, in PowerShell; the connection string is read from your clipboard/vault, not stored
$env:DB_URL = "postgresql://postgres:[PASSWORD]@db.zzkxavgpwxknsqtlgiqf.supabase.co:5432/postgres"
npx supabase@3 db dump --db-url $env:DB_URL -f backups\schema-$(Get-Date -Format yyyyMMdd).sql
npx supabase@3 db dump --db-url $env:DB_URL --data-only -f backups\data-$(Get-Date -Format yyyyMMdd).sql
Remove-Item Env:DB_URL
```

`backups/` is git-ignored. Copy the files to a second place (an external drive or a private cloud folder).
**The data file contains personal data, so store it encrypted** (for example a 7-Zip archive with AES-256 and a strong password).

## Original photos backup

R2 has no version history. Copy `originals/` to a second location regularly, for example with
[rclone](https://rclone.org) (free), using a **read-only** R2 token:

```bash
rclone sync r2:zurag-photos/originals D:\zurag-backup\originals --progress
```

## Restore test (do this once before launch, then every few months)

1. Create a second, empty free Supabase project, for example "zurag-restore-test".
2. In its SQL editor, run `schema-YYYYMMDD.sql`, then `data-YYYYMMDD.sql`
   (or `psql "<restore-project-uri>" -f ...`).
3. Check counts match the live project: `select count(*) from orders;`, `... from photos;`, `... from commissions;`.
4. Delete the restore project afterwards.

## If something goes wrong

- **Wrong data change:** restore only the affected table from the latest dump into a scratch project and copy rows back.
- **Lost photos:** restore `originals/` with rclone from the backup copy, then reprocess previews.
- **Leaked key:** re-issue it (Supabase secret key / R2 token / QPay), update `.env` and the Cloudflare secrets, then redeploy.
