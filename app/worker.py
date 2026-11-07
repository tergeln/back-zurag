"""Photo processing worker.

    python -m app.worker          # run forever, polling for new photos
    python -m app.worker --once   # process everything waiting, then exit

Two queues, both in the photos table:
  1. 'processing' photos: download the original from R2, make a 400px thumbnail
     and a 1600px preview (both watermarked, EXIF stripped, WebP), store them
     under thumbs/ and previews/, find every face and store its embedding,
     then mark the photo 'ready'.
  2. 'ready'/'published' photos that were never face-indexed (older photos,
     or after a model change): find faces only.
Failures are retried up to 3 times (rendering) or recorded (faces).
"""

import argparse
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from .config import load_settings
from .db import Db
from .faces import MODEL_NAME, FaceEngine, load_bgr, to_pgvector
from .imaging import InvalidImage, render
from .maintenance import run_maintenance
from .storage import Storage

log = logging.getLogger("worker")

BATCH = 20
THREADS = 4
IDLE_SLEEP = 5


def keys_for(event_id: str, photo_id: str) -> tuple[str, str]:
    return f"previews/{event_id}/{photo_id}.webp", f"thumbs/{event_id}/{photo_id}.webp"


def index_faces(photo_id: str, original: bytes, db: Db) -> int:
    try:
        faces = FaceEngine.for_thread().faces(load_bgr(original))
        payload = [{"embedding": to_pgvector(f.embedding), "bbox": f.bbox, "score": f.score} for f in faces]
        return db.save_faces(photo_id, MODEL_NAME, payload)
    except Exception as e:
        log.exception("face indexing failed %s", photo_id)
        db.fail_faces(photo_id, f"{type(e).__name__}: {e}")
        return -1


def process_one(job: dict, storage: Storage, db: Db) -> bool:
    photo_id, event_id = job["id"], job["event_id"]
    try:
        original = storage.get(job["original_key"])
        out = render(original)
        preview_key, thumb_key = keys_for(event_id, photo_id)
        storage.put(preview_key, out.preview, "image/webp")
        storage.put(thumb_key, out.thumb, "image/webp")
        db.complete(photo_id, preview_key, thumb_key, out.width, out.height)
    except InvalidImage as e:
        log.warning("invalid image %s: %s", photo_id, e)
        db.fail(photo_id, f"invalid image: {e}")
        return False
    except Exception as e:  # network, storage, etc.: retried on a later claim
        log.exception("failed %s", photo_id)
        db.fail(photo_id, f"{type(e).__name__}: {e}")
        return False
    index_faces(photo_id, original, db)  # the photo is usable even if this fails
    return True


def faces_one(job: dict, storage: Storage, db: Db) -> int:
    try:
        original = storage.get(job["original_key"])
    except Exception as e:
        db.fail_faces(job["id"], f"{type(e).__name__}: {e}")
        return -1
    return index_faces(job["id"], original, db)


MAINTENANCE_EVERY = 3600  # seconds


def run(once: bool) -> None:
    settings = load_settings()
    storage, db = Storage(settings), Db(settings)
    done = failed = indexed = faces_found = 0
    started = time.monotonic()
    last_maintenance = 0.0
    with ThreadPoolExecutor(THREADS) as pool:
        while True:
            if not once and time.monotonic() - last_maintenance > MAINTENANCE_EVERY:
                try:
                    run_maintenance(storage, db)
                except Exception:
                    log.exception("maintenance failed")
                last_maintenance = time.monotonic()

            jobs = db.claim(BATCH)
            if jobs:
                for ok in pool.map(lambda j: process_one(j, storage, db), jobs):
                    done += ok
                    failed += not ok
                log.info("processed %d, failed %d (%.0fs)", done, failed, time.monotonic() - started)
                continue

            face_jobs = db.claim_faces(BATCH)
            if face_jobs:
                for n in pool.map(lambda j: faces_one(j, storage, db), face_jobs):
                    indexed += 1
                    faces_found += max(n, 0)
                log.info("face-indexed %d photos, %d faces (%.0fs)", indexed, faces_found, time.monotonic() - started)
                continue

            if once:
                break
            time.sleep(IDLE_SLEEP)
    log.info("finished: %d processed, %d failed, %d face-indexed (%d faces) in %.0fs",
             done, failed, indexed, faces_found, time.monotonic() - started)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per request is too noisy
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="process the queues once and exit")
    parser.add_argument("--maintenance", action="store_true", help="run the cleanup jobs once and exit")
    args = parser.parse_args()
    if args.maintenance:
        s = load_settings()
        run_maintenance(Storage(s), Db(s))
    else:
        run(args.once)
