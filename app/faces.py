"""Face detection (YuNet) and face embeddings (SFace), both from OpenCV Zoo.

Licences: YuNet is MIT, SFace is Apache-2.0, so both may be used commercially.
Model files live in back-zurag/models/ (not in git). Swapping in another model
(e.g. a licensed ArcFace) means a new FaceEngine with the same methods and a
re-index of all photos (set photos.faces_indexed_at = null).
"""

import io
import threading
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageOps

MODELS = Path(__file__).resolve().parent.parent / "models"
YUNET = MODELS / "face_detection_yunet_2023mar.onnx"
SFACE = MODELS / "face_recognition_sface_2021dec.onnx"

MODEL_NAME = "yunet-2023mar+sface-2021dec"
DETECT_LONG_SIDE = 2048   # large enough for faces in crowd shots, small enough to be fast
MIN_FACE_PX = 24          # smaller faces give unreliable embeddings
SCORE_THRESHOLD = 0.8
# OpenCV publishes 0.363 as SFace's "same person" cosine threshold. On LFW
# (tools/eval_faces.py) 0.40 kept the same 98% recall while cutting wrong
# matches from 0.85 to 0.17 per search, so we use 0.40. Re-check on real events.
DEFAULT_MATCH_THRESHOLD = 0.40


@dataclass(frozen=True)
class Face:
    embedding: np.ndarray          # 128 floats, L2-normalised
    bbox: dict                     # x, y, w, h as fractions of the image (0..1)
    score: float
    width_px: int                  # face width in the analysed image


def load_bgr(data: bytes, long_side: int = DETECT_LONG_SIDE) -> np.ndarray:
    img = ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("RGB")
    img.thumbnail((long_side, long_side), Image.Resampling.LANCZOS)
    return cv2.cvtColor(np.asarray(img), cv2.COLOR_RGB2BGR)


class FaceEngine:
    """Not thread-safe: OpenCV DNN objects keep state. Use one per thread (see for_thread)."""

    _local = threading.local()

    def __init__(self):
        if not YUNET.exists() or not SFACE.exists():
            raise SystemExit(f"Face models missing in {MODELS}. See back-zurag/README.md.")
        self.detector = cv2.FaceDetectorYN.create(str(YUNET), "", (320, 320), SCORE_THRESHOLD, 0.3, 5000)
        self.recognizer = cv2.FaceRecognizerSF.create(str(SFACE), "")

    @classmethod
    def for_thread(cls) -> "FaceEngine":
        engine = getattr(cls._local, "engine", None)
        if engine is None:
            engine = cls._local.engine = cls()
        return engine

    def faces(self, bgr: np.ndarray) -> list[Face]:
        h, w = bgr.shape[:2]
        self.detector.setInputSize((w, h))
        _, rows = self.detector.detect(bgr)
        out: list[Face] = []
        for row in rows if rows is not None else []:
            x, y, fw, fh, score = float(row[0]), float(row[1]), float(row[2]), float(row[3]), float(row[14])
            if fw < MIN_FACE_PX:
                continue
            aligned = self.recognizer.alignCrop(bgr, row)
            vec = self.recognizer.feature(aligned).flatten().astype(np.float32)
            vec /= np.linalg.norm(vec) or 1.0
            bbox = {
                "x": round(max(x, 0) / w, 4), "y": round(max(y, 0) / h, 4),
                "w": round(min(fw, w) / w, 4), "h": round(min(fh, h) / h, 4),
            }
            out.append(Face(embedding=vec, bbox=bbox, score=round(score, 4), width_px=int(fw)))
        return out


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b))  # vectors are already normalised


def to_pgvector(vec: np.ndarray) -> str:
    return "[" + ",".join(f"{v:.6f}" for v in vec.tolist()) + "]"
