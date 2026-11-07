# back-zurag

Python side of Zurag, plus the database migrations.

- `supabase/migrations/`: database schema, access rules and functions. Run them in order in the Supabase SQL editor.
- `app/worker.py`: photo processing worker (thumbnails, watermarked previews, face indexing).
- `app/api.py`: internal AI service for selfie search. Only the Next.js server calls it.

## Setup (Windows)

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Download the face models into `models/` (not in git):

```bash
curl -L -o models/face_detection_yunet_2023mar.onnx https://huggingface.co/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar.onnx
curl -L -o models/face_recognition_sface_2021dec.onnx https://huggingface.co/opencv/face_recognition_sface/resolve/main/face_recognition_sface_2021dec.onnx
```

YuNet is MIT-licensed and SFace is Apache-2.0, so both are free for commercial use.

Copy `.env.example` to `.env` and fill it in. `SUPABASE_SECRET_KEY` and the R2 keys are secrets.

## Run

```bash
.venv\Scripts\python.exe -m app.worker                 # keep processing new uploads
.venv\Scripts\python.exe -m app.worker --once          # empty the queue, then exit
.venv\Scripts\python.exe -m uvicorn app.api:app --port 8001   # selfie search service
.venv\Scripts\python.exe -m pytest -q                  # tests
```

## Face search accuracy

`tools/eval_faces.py <folder>` measures accuracy on a labelled set (files named `Name_0001.jpg`).
On a 981-image LFW subset: the right person was in the top 20 for 98.6% of searches. At the
0.40 threshold, 98% of a person's photos were found, with 0.17 wrong photos per search.
LFW is easier than real event photos, so re-check with real events before launch.

`tools/e2e_face_search.py <folder>` runs the full search path against the running AI service.
It checks results come from one event only, and that disabled search, bad tokens and faceless
selfies are refused. It cleans up after itself.
