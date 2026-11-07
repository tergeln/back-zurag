"""Internal AI service: selfie search.

    .venv\\Scripts\\python.exe -m uvicorn app.api:app --port 8001

Only the Next.js server calls this (with the shared AI_SERVICE_TOKEN), after it
has checked the customer's login, consent and rate limit. Browsers never reach
it directly. The selfie is processed in memory and never written anywhere.
"""

import hmac
import logging
import os

import httpx
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile

from .config import load_settings
from .db import Db
from .faces import DEFAULT_MATCH_THRESHOLD, FaceEngine, load_bgr, to_pgvector

log = logging.getLogger("api")
settings = load_settings()
db = Db(settings)
TOKEN = os.environ.get("AI_SERVICE_TOKEN", "")
if len(TOKEN) < 32:
    raise SystemExit("AI_SERVICE_TOKEN must be set in back-zurag/.env (at least 32 characters).")

MAX_SELFIE_BYTES = 10 * 1024 * 1024
MIN_SELFIE_FACE_PX = 60  # a selfie face this small gives a weak search

app = FastAPI(title="Zurag AI service", docs_url=None, redoc_url=None, openapi_url=None)


def check_token(token: str | None) -> None:
    if not token or not hmac.compare_digest(token, TOKEN):
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/search")
async def search(
    event_id: str = Form(..., pattern=r"^[0-9a-f-]{36}$"),
    image: UploadFile = File(...),
    limit: int = Form(200, ge=1, le=500),
    x_internal_token: str | None = Header(default=None),
) -> dict:
    check_token(x_internal_token)
    data = await image.read(MAX_SELFIE_BYTES + 1)
    if len(data) > MAX_SELFIE_BYTES:
        raise HTTPException(status_code=413, detail="too_large")

    try:
        bgr = load_bgr(data, long_side=1280)
    except Exception:
        raise HTTPException(status_code=422, detail="invalid_image")
    faces = FaceEngine.for_thread().faces(bgr)
    del data, bgr  # nothing about the selfie is kept

    if not faces:
        raise HTTPException(status_code=422, detail="no_face")
    face = max(faces, key=lambda f: f.width_px)  # the selfie-taker is the largest face
    if face.width_px < MIN_SELFIE_FACE_PX:
        raise HTTPException(status_code=422, detail="face_too_small")

    try:
        rows = db.search(event_id, to_pgvector(face.embedding), DEFAULT_MATCH_THRESHOLD, limit)
    except httpx.HTTPStatusError as e:
        if "search_disabled" in e.response.text:
            raise HTTPException(status_code=403, detail="search_disabled")
        log.error("search failed: %s", e.response.status_code)
        raise HTTPException(status_code=502, detail="search_failed")

    log.info("search event=%s faces_in_selfie=%d matches=%d", event_id, len(faces), len(rows))
    return {"matches": [{"photo_id": r["photo_id"], "similarity": round(r["similarity"], 4)} for r in rows]}
