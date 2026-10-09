"""extractors/pdf_extractor.py (Member 1) - text PDFs, scanned PDFs and mixed PDFs.

For every page:
  1. read the text layer (PyMuPDF). Text with a white/hidden font colour is still read, so nothing hides from detection;
  2. tables are rebuilt as rows  "cell | cell | cell"  so the structure survives;
  3. form-field values and annotation comments are added (PII often sits there);
  4. a page with (almost) no text is treated as a scan and read with OCR (parallel + cached).
"""
import hashlib
import json
from pathlib import Path

from . import MIN_TEXT, OCR_DPI, normalize_text, ocr_many

CACHE_DIR = Path("data") / "cache"


def _page_text(page) -> str:
    import pymupdf
    tables = []                                   # (y_top, rect, text)
    try:
        if len(page.get_drawings()) < 4:          # no ruling lines on this page -> no ruled table, skip the slow search
            raise ValueError
        for t in page.find_tables().tables:
            rows = []
            for r in t.extract():
                cells = [(c or "").replace("\n", " ").strip() for c in r]
                if any(cells):
                    rows.append(" | ".join(cells))
            if rows:
                tables.append((t.bbox[1], pymupdf.Rect(t.bbox), "\n".join(rows)))
    except Exception:
        tables = []
    tables.sort(key=lambda x: x[0])

    def in_table(w):                              # is this word inside a table area?
        cx, cy = (w[0] + w[2]) / 2, (w[1] + w[3]) / 2
        return any(r.x0 - 2 <= cx <= r.x1 + 2 and r.y0 - 2 <= cy <= r.y1 + 2 for _, r, _ in tables)

    lines = {}                                    # words outside tables, grouped into lines (reading order kept)
    for w in page.get_text("words"):
        if not in_table(w):
            lines.setdefault((w[5], w[6]), []).append(w)

    parts, pending = [], list(tables)
    for ws in lines.values():
        y0 = min(w[1] for w in ws)
        while pending and pending[0][0] <= y0:    # put each table where it sits on the page
            parts.append(pending.pop(0)[2])
        parts.append(" ".join(w[4] for w in sorted(ws, key=lambda w: w[0])))
    parts += [p[2] for p in pending]

    extras = []                                   # form fields + comments
    try:
        for w in page.widgets() or []:
            if w.field_value not in (None, "", "Off"):
                extras.append(f"{w.field_name or 'Field'}: {w.field_value}")
    except Exception:
        pass
    try:
        for a in page.annots() or []:
            content = (a.info or {}).get("content", "").strip()
            if content:
                extras.append(f"Comment: {content}")
    except Exception:
        pass
    if extras:
        parts.append("[Form fields and comments]\n" + "\n".join(extras))
    return normalize_text("\n".join(parts))


def _ocr_pages(doc, path: Path, numbers, progress):
    """OCR the given 1-based pages; results are cached by file content so a repeat upload is instant."""
    import pymupdf
    from PIL import Image
    key = hashlib.sha1(path.read_bytes()).hexdigest()
    cache_file = CACHE_DIR / f"{key}_ocr{OCR_DPI}_p4.json"        # same cache the pipeline uses
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    todo = [n for n in numbers if str(n) not in cache]
    total, done = len(numbers), len(numbers) - len(todo)
    if progress:
        progress(done, total)
    batch_size = 16
    for i in range(0, len(todo), batch_size):
        batch, imgs = todo[i:i + batch_size], []
        for n in batch:                                           # render in this thread (PyMuPDF is not thread-safe)
            pix = doc[n - 1].get_pixmap(dpi=OCR_DPI, colorspace=pymupdf.csGRAY)
            imgs.append(Image.frombytes("L", (pix.width, pix.height), pix.samples))
        for n, text in zip(batch, ocr_many(imgs)):
            cache[str(n)] = text
            done += 1
            if progress:
                progress(done, total)
    if todo:
        cache_file.write_text(json.dumps(cache))
    return {n: cache[str(n)] for n in numbers}


def extract(path, progress=None):
    import pymupdf
    path = Path(path)
    with pymupdf.open(str(path)) as doc:
        if doc.needs_pass:
            raise ValueError("This PDF is password protected. Remove the password and upload again.")
        pages = [{"page": i, "text": _page_text(pg)} for i, pg in enumerate(doc, 1)]
        scanned = [p["page"] for p in pages if len(p["text"].strip()) < MIN_TEXT]
        if scanned:
            try:
                ocr = _ocr_pages(doc, path, scanned, progress)
            except RuntimeError as e:                              # OCR not installed
                raise ValueError(f"This looks like a scanned file. {e}")
            for p in pages:
                if p["page"] in ocr:
                    p["text"] = (p["text"] + "\n" + ocr[p["page"]]).strip()
    return pages