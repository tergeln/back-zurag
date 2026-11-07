import io

import numpy as np
import pytest
from PIL import Image

from app.faces import SFACE, YUNET, FaceEngine, cosine, load_bgr, to_pgvector

models_present = YUNET.exists() and SFACE.exists()


def jpeg(w: int, h: int, color=(120, 140, 160)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (w, h), color).save(out, "JPEG")
    return out.getvalue()


def test_to_pgvector_format():
    s = to_pgvector(np.array([0.5, -0.25, 1.0], dtype=np.float32))
    assert s == "[0.500000,-0.250000,1.000000]"


def test_cosine_of_normalised_vectors():
    a = np.array([1.0, 0.0], dtype=np.float32)
    b = np.array([0.0, 1.0], dtype=np.float32)
    assert cosine(a, a) == pytest.approx(1.0)
    assert cosine(a, b) == pytest.approx(0.0)


def test_load_bgr_downscales_large_images():
    bgr = load_bgr(jpeg(6000, 4000))
    assert bgr.shape == (1365, 2048, 3)


@pytest.mark.skipif(not models_present, reason="face models not downloaded")
def test_no_faces_in_a_plain_image():
    assert FaceEngine().faces(load_bgr(jpeg(1600, 1000))) == []
