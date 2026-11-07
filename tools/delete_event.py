"""Permanently delete one event: its files in R2 and all its database rows.

    .venv\\Scripts\\python.exe tools\\delete_event.py <event-id>            # dry run: shows what would go
    .venv\\Scripts\\python.exe tools\\delete_event.py <event-id> --confirm  # really deletes

Meant for test events. Deleting an event removes its photos (originals,
previews, thumbnails), face embeddings, cart entries, search log and consent
records. It cannot be undone. Events with paid orders must never be deleted
this way (orders arrive in Phase 8; this tool will refuse them then).
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

from app.config import load_settings  # noqa: E402
from app.storage import Storage  # noqa: E402


def main(event_id: str, confirm: bool) -> None:
    if not re.fullmatch(r"[0-9a-f-]{36}", event_id):
        raise SystemExit("not an event id")
    s = load_settings()
    rest = httpx.Client(base_url=f"{s.supabase_url}/rest/v1", headers={"apikey": s.supabase_secret_key}, timeout=60)
    event = rest.get("/events", params={"id": f"eq.{event_id}", "select": "id,name_mn,status"}).json()
    if not event:
        raise SystemExit("event not found")
    photos = rest.get("/photos", params={"event_id": f"eq.{event_id}", "select": "id,original_key,preview_key,thumb_key"}).json()
    keys = [k for p in photos for k in (p["original_key"], p["preview_key"], p["thumb_key"]) if k]
    print(f"event: {event[0]['name_mn']} ({event[0]['status']})")
    print(f"photos: {len(photos)}, stored files: {len(keys)}")
    if not confirm:
        print("dry run: nothing deleted (add --confirm to delete)")
        return

    storage = Storage(s)
    for i in range(0, len(keys), 1000):  # S3 delete_objects takes up to 1000 keys
        batch = [{"Key": k} for k in keys[i:i + 1000]]
        storage.client.delete_objects(Bucket=storage.bucket, Delete={"Objects": batch, "Quiet": True})
    rest.delete("/photos", params={"event_id": f"eq.{event_id}"}).raise_for_status()
    rest.delete("/events", params={"id": f"eq.{event_id}"}).raise_for_status()
    left = rest.get("/photos", params={"event_id": f"eq.{event_id}", "select": "id"}).json()
    print(f"deleted: {len(keys)} files, {len(photos)} photos, the event. Remaining photo rows: {len(left)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("event_id")
    ap.add_argument("--confirm", action="store_true")
    a = ap.parse_args()
    main(a.event_id, a.confirm)
