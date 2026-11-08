"""Header thumbnails of leak posts (owner decision 2026-10-14: "header crop only"; migration 0109).

A leak-post screenshot carries samples of stolen personal data below the header. Only the top of
the page is kept - the group's banner, the victim's name, the countdown, the size and date - and
it is scaled to 400 px wide, at which body text is illegible. The original image is held in memory
for the crop and never written anywhere.
"""

from __future__ import annotations

import io
import urllib.parse

from PIL import Image

BASE = "https://www.ransomlook.io/"
WIDTH = 400
HEADER_FRACTION = 0.32     # of the page height
HEADER_MAX_PX = 520        # at the original 1280 px width


def screenshot_url(path: str) -> str | None:
    if not path or ".." in path or path.startswith(("/", "http")):
        return None
    return BASE + urllib.parse.quote(path)


def header_thumb(png: bytes) -> tuple[bytes, int, int]:
    """WebP of the page header only, WIDTH px wide."""
    # Only the formats a screenshot arrives in: the bytes come from a third party, and without `formats` Pillow tries
    # every decoder it has (PSD, TIFF, EPS via Ghostscript...) on them (security review 2026-10-26).
    with Image.open(io.BytesIO(png), formats=["PNG", "JPEG", "WEBP"]) as im:
        im = im.convert("RGB")
        w, h = im.size
        cut = int(min(h * HEADER_FRACTION, HEADER_MAX_PX * (w / 1280)))
        head = im.crop((0, 0, w, max(1, cut)))
        nh = max(1, round(head.height * WIDTH / w))
        small = head.resize((WIDTH, nh), Image.LANCZOS)
        out = io.BytesIO()
        small.save(out, "WEBP", quality=60, method=4)
        return out.getvalue(), WIDTH, nh
