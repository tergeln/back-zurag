"""Measure selfie-search accuracy on a labelled face set (e.g. LFW).

    .venv\\Scripts\\python.exe -I tools\\eval_faces.py <folder of Name_0001.jpg files>

Setup, per person with at least 3 photos: their first photo is the "selfie",
the rest go into one big "event" together with every other photo (distractors).
For each selfie we rank all event photos by their best-matching face, exactly
like search_event_faces does, and report:
  * hit@1 / hit@20: is one of the person's own photos ranked first / in the top 20?
  * recall@T: share of the person's own photos at or above threshold T
  * false/query@T: other people's photos at or above T, per search
Runs entirely locally; nothing is uploaded.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # import app.* even with python -I
from app.faces import DEFAULT_MATCH_THRESHOLD, FaceEngine, load_bgr  # noqa: E402

NAME = re.compile(r"^(.+)_(\d{4})\.jpe?g$", re.I)


def main(folder: Path) -> None:
    engine = FaceEngine()
    people: dict[str, list[Path]] = defaultdict(list)
    for p in sorted(folder.glob("*.jpg")):
        m = NAME.match(p.name)
        if m:
            people[m.group(1)].append(p)

    faces: dict[Path, list[np.ndarray]] = {}
    for paths in people.values():
        for p in paths:
            found = engine.faces(load_bgr(p.read_bytes()))
            faces[p] = [f.embedding for f in sorted(found, key=lambda f: -f.width_px)]

    no_face = [p for p, f in faces.items() if not f]
    queries = {name: paths for name, paths in people.items() if len(paths) >= 3 and faces[paths[0]]}
    gallery = [p for paths in people.values() for p in paths if faces[p]]
    gallery_vecs = [np.stack(faces[p]) for p in gallery]
    owner = [next(n for n, ps in people.items() if p in ps) for p in gallery]

    print(f"images: {len(faces)}, people: {len(people)}, no face found: {len(no_face)}")
    print(f"searches (people with 3+ photos): {len(queries)}, event photos: {len(gallery)}")

    thresholds = [0.30, 0.33, 0.363, 0.40, 0.45]
    hit1 = hit20 = 0
    recall = {t: [] for t in thresholds}
    false = {t: [] for t in thresholds}
    for name, paths in queries.items():
        q = faces[paths[0]][0]  # largest face in the selfie
        scores = np.array([float(np.max(v @ q)) for v in gallery_vecs])
        mine = np.array([o == name and g != paths[0] for o, g in zip(owner, gallery)])
        others = np.array([o != name for o in owner])
        order = [i for i in np.argsort(-scores) if gallery[i] != paths[0]]  # don't match the selfie itself
        hit1 += bool(mine[order[0]])
        hit20 += bool(mine[order[:20]].any())
        for t in thresholds:
            if mine.sum():
                recall[t].append(float((scores[mine] >= t).mean()))
            false[t].append(int((scores[others] >= t).sum()))

    n = len(queries)
    print(f"\nhit@1:  {hit1}/{n} = {hit1 / n:.1%}")
    print(f"hit@20: {hit20}/{n} = {hit20 / n:.1%}")
    print("\nthreshold  recall(own photos found)  false matches per search")
    for t in thresholds:
        mark = "  <- default" if abs(t - DEFAULT_MATCH_THRESHOLD) < 1e-9 else ""
        print(f"  {t:.3f}      {np.mean(recall[t]):6.1%}                 {np.mean(false[t]):.2f}{mark}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
