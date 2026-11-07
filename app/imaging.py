"""Thumbnails and watermarked previews. Pure functions: bytes in, bytes out."""

import io
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageFont, ImageOps

# Refuse absurdly large images (decompression bombs). 100 MP covers any real camera.
Image.MAX_IMAGE_PIXELS = 100_000_000

THUMB_LONG_SIDE = 400
PREVIEW_LONG_SIDE = 1600
WATERMARK_TEXT = "ZURAG"


class InvalidImage(Exception):
    pass


@dataclass(frozen=True)
class Rendered:
    thumb: bytes
    preview: bytes
    width: int  # of the original, after EXIF rotation
    height: int


def open_image(data: bytes) -> Image.Image:
    """Decode, fully verify, apply EXIF rotation and convert to RGB."""
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()  # catches truncated / corrupt files
        img = Image.open(io.BytesIO(data))
        if img.format not in {"JPEG", "PNG", "WEBP"}:
            raise InvalidImage(f"unsupported format {img.format}")
        img = ImageOps.exif_transpose(img)
        return img.convert("RGB")
    except InvalidImage:
        raise
    except Exception as e:  # Pillow raises many different errors for bad input
        raise InvalidImage(str(e)) from e


def resized(img: Image.Image, long_side: int) -> Image.Image:
    copy = img.copy()
    copy.thumbnail((long_side, long_side), Image.Resampling.LANCZOS)  # never upscales
    return copy


def add_watermark(img: Image.Image) -> Image.Image:
    """Diagonal repeated text across the whole image plus a bold centre mark.
    Strong enough that a cropped screenshot is not a usable photo."""
    base = img.convert("RGBA")
    w, h = base.size
    font_size = max(18, int(min(w, h) / 9))
    font = ImageFont.load_default(size=font_size)

    tile = Image.new("RGBA", (w * 2, h * 2), (0, 0, 0, 0))
    draw = ImageDraw.Draw(tile)
    step_x, step_y = int(font_size * 4.2), int(font_size * 2.6)
    for row, y in enumerate(range(0, tile.height, step_y)):
        offset = (row % 2) * step_x // 2
        for x in range(-step_x, tile.width, step_x):
            draw.text((x + offset, y), WATERMARK_TEXT, font=font, fill=(255, 255, 255, 70), stroke_width=1, stroke_fill=(0, 0, 0, 40))
    tile = tile.rotate(30, resample=Image.Resampling.BICUBIC)
    left, top = (tile.width - w) // 2, (tile.height - h) // 2
    base.alpha_composite(tile.crop((left, top, left + w, top + h)))

    # Drawn on its own layer and composited, so its transparency is kept.
    centre_font = ImageFont.load_default(size=int(font_size * 1.8))
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    box = draw.textbbox((0, 0), WATERMARK_TEXT, font=centre_font)
    tw, th = box[2] - box[0], box[3] - box[1]
    draw.text(((w - tw) / 2, (h - th) / 2 - box[1]), WATERMARK_TEXT, font=centre_font, fill=(255, 255, 255, 120), stroke_width=2, stroke_fill=(0, 0, 0, 70))
    base.alpha_composite(layer)
    return base.convert("RGB")


def to_webp(img: Image.Image, quality: int) -> bytes:
    out = io.BytesIO()
    # Saving a new image drops all EXIF, including GPS location.
    img.save(out, "WEBP", quality=quality, method=4)
    return out.getvalue()


def render(data: bytes) -> Rendered:
    img = open_image(data)
    thumb = add_watermark(resized(img, THUMB_LONG_SIDE))
    preview = add_watermark(resized(img, PREVIEW_LONG_SIDE))
    return Rendered(thumb=to_webp(thumb, 72), preview=to_webp(preview, 80), width=img.width, height=img.height)
