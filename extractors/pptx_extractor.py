"""extractors/pptx_extractor.py (Member 1) - PowerPoint decks.

One page per slide, in reading order (title first, then top-to-bottom, left-to-right):
text frames (indent kept), tables (rows as "cell | cell"), grouped shapes, charts, SmartArt text,
hyperlink targets, speaker notes, and text inside pictures (OCR). Font colour does not matter.
"""
import hashlib

from pptx import Presentation
from pptx.enum.shapes import MSO_SHAPE_TYPE

from . import normalize_text, ocr_blobs


def _sorted(shapes):
    return sorted(shapes, key=lambda s: (s.top if s.top is not None else 0, s.left if s.left is not None else 0))


def _walk(shape, lines, links, pics):
    if shape.shape_type == MSO_SHAPE_TYPE.GROUP:
        for s in _sorted(shape.shapes):
            _walk(s, lines, links, pics)
        return
    if getattr(shape, "has_table", False) and shape.has_table:
        for row in shape.table.rows:
            cells = [c.text.replace("\n", " ").strip() for c in row.cells]
            if any(cells):
                lines.append(" | ".join(cells))
        return
    if getattr(shape, "has_chart", False) and shape.has_chart:
        ch = shape.chart
        try:
            if ch.has_title:
                lines.append(ch.chart_title.text_frame.text)
            for plot in ch.plots:
                lines.append(" | ".join(str(c) for c in plot.categories))
                for s in plot.series:
                    lines.append(f"{s.name}: " + " | ".join("" if v is None else str(v) for v in s.values))
        except Exception:
            pass
        return
    if shape.shape_type == MSO_SHAPE_TYPE.PICTURE:
        try:
            pics.append(shape.image.blob)
        except Exception:
            pass
        return
    if shape.has_text_frame:
        for p in shape.text_frame.paragraphs:
            text = "".join(r.text for r in p.runs).strip() or p.text.strip()
            if text:
                lines.append("  " * min(p.level, 4) + text)
            for r in p.runs:
                try:
                    if r.hyperlink.address:
                        links.append(r.hyperlink.address)
                except Exception:
                    pass
        return
    for t in shape._element.xpath(".//a:t"):          # SmartArt and other shapes without a text frame
        if t.text and t.text.strip():
            lines.append(t.text.strip())


def extract(path, progress=None):
    prs = Presentation(str(path))
    pages, seen_pics = [], set()
    for i, slide in enumerate(prs.slides, 1):
        lines, links, pics = [], [], []
        shapes = _sorted(slide.shapes)
        title = slide.shapes.title
        if title is not None and title.has_text_frame and title.text_frame.text.strip():
            lines.append(title.text_frame.text.strip())
            shapes = [s for s in shapes if s.shape_id != title.shape_id]
        for s in shapes:
            _walk(s, lines, links, pics)
        for addr in dict.fromkeys(links):             # mailto:/tel:/web links can hold PII too
            if not any(addr in l for l in lines):
                lines.append(f"[Link] {addr}")
        new_pics = []
        for b in pics:
            h = hashlib.sha1(b).hexdigest()
            if h not in seen_pics:                    # a logo repeated on every slide is read once
                seen_pics.add(h)
                new_pics.append(b)
        if new_pics:
            try:
                texts = ocr_blobs(new_pics)
                if texts:
                    lines.append("[Text found in pictures]\n" + "\n".join(texts))
            except RuntimeError:
                lines.append("[Pictures on this slide were not read because OCR is not installed]")
        if slide.has_notes_slide and slide.notes_slide.notes_text_frame is not None:
            notes = slide.notes_slide.notes_text_frame.text.strip()
            if notes:
                lines.append("[Speaker notes]\n" + notes)
        pages.append({"page": i, "text": normalize_text("\n".join(lines))})
        if progress:
            progress(i, len(prs.slides))
    return pages