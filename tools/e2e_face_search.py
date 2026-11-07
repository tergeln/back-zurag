"""End-to-end check of selfie search through the running AI service.

    .venv\\Scripts\\python.exe -I tools\\e2e_face_search.py <folder of Name_0001.jpg files>

Creates three TEST events directly in the database (service role):
  A: published, face search on   - 6 people's photos + 40 distractors
  B: published, face search on   - 2 of the same people (isolation check)
  C: published, face search OFF
Indexes their faces with the real models (no files are uploaded to R2), calls
POST /search on the AI service, checks the answers, then deletes everything.
"""

import os
import re
import sys
import uuid
from collections import defaultdict
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.config import load_settings  # noqa: E402
from app.db import Db  # noqa: E402
from app.faces import MODEL_NAME, FaceEngine, load_bgr, to_pgvector  # noqa: E402

API = "http://127.0.0.1:8001"
NAME = re.compile(r"^(.+)_(\d{4})\.jpe?g$", re.I)
results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


def main(folder: Path) -> None:
    s = load_settings()
    db, engine = Db(s), FaceEngine()
    rest = httpx.Client(base_url=f"{s.supabase_url}/rest/v1", timeout=30,
                        headers={"apikey": s.supabase_secret_key, "Content-Type": "application/json", "Prefer": "return=representation"})
    api = httpx.Client(base_url=API, timeout=60)
    token = os.environ["AI_SERVICE_TOKEN"]

    admin = rest.get("/users", params={"role": "eq.admin", "select": "id", "limit": 1}).json()[0]["id"]
    people: dict[str, list[Path]] = defaultdict(list)
    for p in sorted(folder.glob("*.jpg")):
        if m := NAME.match(p.name):
            people[m.group(1)].append(p)
    multi = [n for n, ps in people.items() if len(ps) >= 4][:6]
    singles = [ps[0] for n, ps in people.items() if len(ps) == 1][:40]

    def make_event(name: str, search_on: bool) -> str:
        row = rest.post("/events", json={"name_mn": name, "event_date": "2026-11-07", "created_by": admin,
                                         "status": "published", "face_search_enabled": search_on}).json()[0]
        return row["id"]

    def add_photo(event_id: str, path: Path) -> str:
        pid = str(uuid.uuid4())
        rest.post("/photos", json={"id": pid, "event_id": event_id, "owner_type": "platform", "uploaded_by": admin,
                                   "original_key": f"test/{pid}", "sha256": uuid.uuid4().hex * 2, "bytes": 1,
                                   "mime": "image/jpeg", "price_mnt": 0, "status": "ready"}).raise_for_status()
        faces = engine.faces(load_bgr(path.read_bytes()))
        db.save_faces(pid, MODEL_NAME, [{"embedding": to_pgvector(f.embedding), "bbox": f.bbox, "score": f.score} for f in faces])
        return pid

    ev = {}
    try:
        ev["A"], ev["B"], ev["C"] = make_event("TEST face A", True), make_event("TEST face B", True), make_event("TEST face C", False)
        owner: dict[str, str] = {}      # photo_id -> person
        in_event: dict[str, str] = {}   # photo_id -> event label
        for n in multi:
            for p in people[n][1:]:
                pid = add_photo(ev["A"], p); owner[pid] = n; in_event[pid] = "A"
        for p in singles:
            pid = add_photo(ev["A"], p); owner[pid] = p.stem; in_event[pid] = "A"
        for n in multi[:2]:
            for p in people[n][1:3]:
                pid = add_photo(ev["B"], p); owner[pid] = n; in_event[pid] = "B"
        for p in people[multi[0]][1:3]:
            pid = add_photo(ev["C"], p); owner[pid] = multi[0]; in_event[pid] = "C"

        def search(event: str, selfie: Path, tok: str | None = token):
            headers = {"x-internal-token": tok} if tok else {}
            return api.post("/search", headers=headers, data={"event_id": ev[event]},
                            files={"image": (selfie.name, selfie.read_bytes(), "image/jpeg")})

        for n in multi:
            r = search("A", people[n][0])
            matches = r.json().get("matches", []) if r.status_code == 200 else []
            ids = [m["photo_id"] for m in matches]
            own_total = len(people[n]) - 1
            own_found = sum(owner.get(i) == n for i in ids)
            check(f"search A for {n}: top result is them", r.status_code == 200 and bool(ids) and owner.get(ids[0]) == n,
                  f"{own_found}/{own_total} own photos, {len(ids) - own_found} others")
            check(f"search A for {n}: only event A photos", all(in_event.get(i) == "A" for i in ids))

        r = search("B", people[multi[2]][0])  # person 3 has no photos in B
        check("search B for someone not in B returns nothing from A", r.status_code == 200 and not r.json()["matches"], str(r.json()))
        r = search("B", people[multi[0]][0])
        ids = [m["photo_id"] for m in r.json().get("matches", [])]
        check("search B for someone in B returns only B photos", bool(ids) and all(in_event.get(i) == "B" for i in ids), f"{len(ids)} matches")

        check("search C (face search off) is refused", search("C", people[multi[0]][0]).status_code == 403)
        check("no token is refused", search("A", people[multi[0]][0], tok=None).status_code == 401)
        check("wrong token is refused", search("A", people[multi[0]][0], tok="x" * 64).status_code == 401)
        r = api.post("/search", headers={"x-internal-token": token}, data={"event_id": ev["A"]},
                      files={"image": ("blank.jpg", blank_jpeg(), "image/jpeg")})
        check("selfie with no face is rejected", r.status_code == 422 and r.json().get("detail") == "no_face", r.text[:80])
    finally:
        for label in ("A", "B", "C"):
            if label in ev:
                rest.delete("/photos", params={"event_id": f"eq.{ev[label]}"})
                rest.delete("/events", params={"id": f"eq.{ev[label]}"})

    width = max(len(r[0]) for r in results)
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label.ljust(width)}  {detail}")
    print(f"\n{sum(ok for _, ok, _ in results)}/{len(results)} passed; test events deleted")


def blank_jpeg() -> bytes:
    import io
    from PIL import Image
    out = io.BytesIO()
    Image.new("RGB", (640, 480), (200, 200, 200)).save(out, "JPEG")
    return out.getvalue()


if __name__ == "__main__":
    main(Path(sys.argv[1]))
