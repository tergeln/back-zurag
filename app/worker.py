"""Photo processing worker.

    python -m app.worker          # run forever, polling for new photos
    python -m app.worker --once   # process everything waiting, then exit

For each photo in 'processing': download the original from R2, make a 400px
thumbnail and a 1600px preview (both watermarked, EXIF stripped, WebP), store
them next to the original under previews/ and thumbs/, and mark the photo
'ready'. Failures are retried up to 3 times, then the photo is marked 'failed'.
"""

import argparse
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from .config import load_settings
from .db import Db
from .imaging import InvalidImage, render
from .storage import Storage

log = logging.getLogger("worker")

BATCH = 20
THREADS = 4
IDLE_SLEEP = 5


def keys_for(event_id: str, photo_id: str) -> tuple[str, str]:
    return f"previews/{event_id}/{photo_id}.webp", f"thumbs/{event_id}/{photo_id}.webp"


def process_one(job: dict, storage: Storage, db: Db) -> bool:
    photo_id, event_id = job["id"], job["event_id"]
    try:
        out = render(storage.get(job["original_key"]))
        preview_key, thumb_key = keys_for(event_id, photo_id)
        storage.put(preview_key, out.preview, "image/webp")
        storage.put(thumb_key, out.thumb, "image/webp")
        db.complete(photo_id, preview_key, thumb_key, out.width, out.height)
        return True
    except InvalidImage as e:
        log.warning("invalid image %s: %s", photo_id, e)
        db.fail(photo_id, f"invalid image: {e}")
    except Exception as e:  # network, storage, etc.: retried on a later claim
        log.exception("failed %s", photo_id)
        db.fail(photo_id, f"{type(e).__name__}: {e}")
    return False


def run(once: bool) -> None:
    settings = load_settings()
    storage, db = Storage(settings), Db(settings)
    done = failed = 0
    started = time.monotonic()
    with ThreadPoolExecutor(THREADS) as pool:
        while True:
            jobs = db.claim(BATCH)
            if not jobs:
                if once:
                    break
                time.sleep(IDLE_SLEEP)
                continue
            for ok in pool.map(lambda j: process_one(j, storage, db), jobs):
                done += ok
                failed += not ok
            log.info("processed %d, failed %d (%.0fs)", done, failed, time.monotonic() - started)
    log.info("finished: %d processed, %d failed in %.0fs", done, failed, time.monotonic() - started)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per request is too noisy
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="process the queue once and exit")
    run(parser.parse_args().once)
