import io

import pytest
from PIL import Image

from app.imaging import PREVIEW_LONG_SIDE, THUMB_LONG_SIDE, InvalidImage, add_watermark, render


def make_jpeg(w: int, h: int, exif_orientation: int | None = None, gps: bool = False) -> bytes:
    img = Image.new("RGB", (w, h), (40, 90, 140))
    exif = Image.Exif()
    if exif_orientation:
        exif[0x0112] = exif_orientation
    if gps:
        exif[0x8825] = {1: "N", 2: (47.0, 55.0, 0.0)}  # GPS info: Ulaanbaatar-ish
    out = io.BytesIO()
    img.save(out, "JPEG", quality=90, exif=exif.tobytes())
    return out.getvalue()


def decode(data: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(data))
    img.load()
    return img


def test_sizes_and_format():
    out = render(make_jpeg(6000, 4000))
    thumb, preview = decode(out.thumb), decode(out.preview)
    assert (out.width, out.height) == (6000, 4000)
    assert thumb.format == preview.format == "WEBP"
    assert max(thumb.size) == THUMB_LONG_SIDE
    assert max(preview.size) == PREVIEW_LONG_SIDE
    assert preview.size == (1600, 1067)  # aspect ratio kept


def test_small_images_are_not_upscaled():
    out = render(make_jpeg(800, 600))
    assert decode(out.preview).size == (800, 600)


def test_exif_rotation_applied():
    # Orientation 6 = camera held sideways: stored 4000x3000, displayed 3000x4000.
    out = render(make_jpeg(4000, 3000, exif_orientation=6))
    assert (out.width, out.height) == (3000, 4000)
    assert decode(out.preview).size == (1200, 1600)


def test_previews_carry_no_exif_or_gps():
    out = render(make_jpeg(2000, 1500, gps=True))
    for data in (out.thumb, out.preview):
        assert len(decode(data).getexif()) == 0


def test_watermark_changes_pixels_across_the_image():
    plain = Image.new("RGB", (1600, 1000), (40, 90, 140))
    marked = add_watermark(plain)
    # Compare a grid of 4x4 regions: the repeated mark must reach every quarter.
    changed = 0
    for gx in range(4):
        for gy in range(4):
            box = (gx * 400, gy * 250, gx * 400 + 400, gy * 250 + 250)
            if plain.crop(box).tobytes() != marked.crop(box).tobytes():
                changed += 1
    assert changed >= 14


def test_rejects_non_images_and_truncated_files():
    with pytest.raises(InvalidImage):
        render(b"this is not an image")
    with pytest.raises(InvalidImage):
        render(make_jpeg(1000, 800)[:2000])
