"""Housekeeping, run by the worker once an hour (or: python -m app.worker --maintenance).

1. Uploads that never finished (24 h) or failed (7 days) are marked deleted.
2. Face data of events older than the retention setting is deleted and face
   search for those events is switched off.
3. Files of deleted photos are removed from R2, except photos a customer still
   has a download right for (the database never lists those).
"""

import logging

from .db import Db
from .storage import Storage

log = logging.getLogger("maintenance")


def run_maintenance(storage: Storage, db: Db) -> dict:
    abandoned = db.mark_abandoned_uploads()
    faces = db.expire_face_data()
    files = photos = 0
    while True:
        rows = db.deletable_photo_files(200)
        if not rows:
            break
        keys = [k for r in rows for k in (r["original_key"], r["preview_key"], r["thumb_key"]) if k]
        storage.delete_many(keys)
        photos += db.mark_photo_files_deleted([r["id"] for r in rows])
        files += len(keys)
        if len(rows) < 200:
            break
    result = {"abandoned_uploads": abandoned, "expired_faces": faces, "deleted_photos": photos, "deleted_files": files}
    log.info("maintenance: %s", result)
    return result
