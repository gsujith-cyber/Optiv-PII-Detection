"""extractors package (Member 1): file-type detection + shared helpers (OCR, text clean-up).

Every extractor exposes:   extract(path, progress=None) -> [{"page": int, "text": str}, ...]
  * page = page number (PDF / DOCX) or slide number (PPTX)
  * progress(done, total) is optional; the app uses it to show OCR progress
Use extract_any(path) to pick the right extractor automatically.
"""
import io
import os
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}
MIN_TEXT = 25            # a PDF page with fewer characters than this is treated as scanned
OCR_DPI = 150            # lower = faster OCR, higher = more accurate (150-200 is a good range)
MIN_IMG = (200, 60)      # ignore tiny images (logos, bullets) smaller than this (px)
_WIN_TESSERACT = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


# --------------------------------------------------------------- file type ---

def detect_type(path) -> str:
    """Detect file type using extension and file signature."""
    p = Path(path)
    ext = p.suffix.lower()

    with open(p, "rb") as f:
        head = f.read(4096)

    # PDF
    if ext == ".pdf":
        if not head.startswith(b"%PDF"):
            return "unknown"
        return "pdf_scanned" if _pdf_is_scanned(p) else "pdf_text"

    # DOCX and PPTX
    if ext in {".docx", ".pptx"}:
        if not head.startswith(b"PK"):
            return "unknown"

        try:
            with zipfile.ZipFile(p) as archive:
                names = set(archive.namelist())
                if archive.testzip() is not None:
                    return "unknown"

                if ext == ".docx":
                    return (
                        "docx"
                        if "[Content_Types].xml" in names
                        and "word/document.xml" in names
                        else "unknown"
                    )

                return (
                    "pptx"
                    if "[Content_Types].xml" in names
                    and "ppt/presentation.xml" in names
                    else "unknown"
                )
        except (zipfile.BadZipFile, OSError):
            return "unknown"

    # Image files
    if ext == ".png" and head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image"

    if ext in {".jpg", ".jpeg"} and head.startswith(b"\xff\xd8\xff"):
        return "image"

    if ext in {".tif", ".tiff"} and head[:4] in (
        b"II*\x00", b"MM\x00*"
    ):
        return "image"

    if ext == ".bmp" and head.startswith(b"BM"):
        return "image"

    if (
        ext == ".webp"
        and head[:4] == b"RIFF"
        and head[8:12] == b"WEBP"
    ):
        return "image"

    # Plain text
    if ext == ".txt":
        try:
            content = p.read_bytes()

            # Reject binary or known non-text file signatures
            if (
                content.startswith(b"%PDF")
                or content.startswith(b"PK")
                or content.startswith(b"\x89PNG\r\n\x1a\n")
                or content.startswith(b"\xff\xd8\xff")
                or content.startswith(b"BM")
            ):
                return "unknown"

            content.decode("utf-8-sig")
            return "txt"
        except (UnicodeDecodeError, OSError):
            return "unknown"

    return "unknown"



def _pdf_is_scanned(path: Path) -> bool:
    import pymupdf
    with pymupdf.open(str(path)) as doc:
        sample = [doc[i].get_text("text") for i in range(min(5, len(doc)))]
    return bool(sample) and all(len(t.strip()) < MIN_TEXT for t in sample)


# --------------------------------------------------------------------- OCR ---
def _tesseract():
    try:
        import pytesseract
    except ImportError:
        raise RuntimeError("OCR needs: pip install pytesseract pillow pymupdf")
    if os.name == "nt" and os.path.exists(_WIN_TESSERACT):
        pytesseract.pytesseract.tesseract_cmd = _WIN_TESSERACT
    try:
        pytesseract.get_tesseract_version()
    except Exception:
        raise RuntimeError("Tesseract OCR program not found. Install it (Windows: UB-Mannheim installer) and restart the app.")
    return pytesseract


def ocr_available() -> bool:
    try:
        _tesseract()
        return True
    except RuntimeError:
        return False


def ocr_many(images, progress=None):
    """OCR a list of PIL images in parallel; returns texts in the same order."""
    pytesseract = _tesseract()
    os.environ.setdefault("OMP_THREAD_LIMIT", "1")   # one thread per Tesseract, many in parallel
    workers = min(8, os.cpu_count() or 4)
    out = []
    with ThreadPoolExecutor(workers) as pool:
        for i, text in enumerate(pool.map(lambda im: pytesseract.image_to_string(im, config="--oem 1 --psm 4"), images), 1):
            out.append(clean_ocr_text(text))
            if progress:
                progress(i, len(images))
    return out


def ocr_blobs(blobs):
    """OCR embedded pictures (bytes). Skips tiny images. Returns a list of non-empty texts.
    Raises RuntimeError if OCR is not installed (callers decide how to tell the user)."""
    from PIL import Image
    imgs = []
    for b in blobs:
        try:
            im = Image.open(io.BytesIO(b))
            if im.width >= MIN_IMG[0] and im.height >= MIN_IMG[1]:
                imgs.append(im.convert("L"))
        except Exception:
            continue
    if not imgs:
        return []
    return [t for t in ocr_many(imgs) if t.strip()]


def clean_ocr_text(text: str) -> str:
    """Repair common OCR damage: re-join an email split as 'name@site.' / 'com', then normalise."""
    gap = r"(?:[ \t]*\n){1,2}[ \t]*"
    tld = r"(com|org|net|edu|gov|in|co|io|uk|us|ai)\b"
    text = re.sub(r"([\w.+-]+@[\w-]+(?:\.[\w-]+)*\.)" + gap + tld, r"\1\2", text)
    text = re.sub(r"([\w.+-]+@[\w-]+)" + gap + r"(\.(?:com|org|net|edu|gov|in|co|io|uk|us|ai)\b)", r"\1\2", text)
    return normalize_text(text)


def normalize_text(text: str) -> str:
    """Tidy whitespace without changing the words: strip line ends, max one blank line in a row."""
    text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    return re.sub(r"\n{3,}", "\n\n", text).strip()


# ------------------------------------------------------------ simple types ---
def extract_txt(path, progress=None):
    data = Path(path).read_bytes()
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return [{"page": 1, "text": normalize_text(data.decode(enc))}]
        except (UnicodeDecodeError, UnicodeError):
            continue
    return [{"page": 1, "text": ""}]


def extract_image(path, progress=None):
    """Scanned image (PNG/JPG/TIFF...): OCR every frame."""
    from PIL import Image, ImageSequence
    with Image.open(path) as im:
        frames = [f.convert("L") for f in ImageSequence.Iterator(im)]
    texts = ocr_many(frames, progress)
    return [{"page": i, "text": t} for i, t in enumerate(texts, 1)]


def extract_any(path, progress=None):
    """Detect the real file type and run the matching extractor."""
    kind = detect_type(path)
    if kind in ("pdf_text", "pdf_scanned"):
        from . import pdf_extractor as m
    elif kind == "docx":
        from . import docx_extractor as m
    elif kind == "pptx":
        from . import pptx_extractor as m
    elif kind == "txt":
        return extract_txt(path)
    elif kind == "image":
        return extract_image(path, progress)
    else:
        raise ValueError("Unsupported or unreadable file type.")
    return m.extract(path, progress)