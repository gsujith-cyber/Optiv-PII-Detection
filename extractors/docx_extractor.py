"""extractors/docx_extractor.py (Member 1) - Word documents.

Reads, in document order: paragraphs (headings and bullets kept), tables (rows as "cell | cell"),
text boxes, headers/footers, and text inside embedded pictures (OCR). Font colour does not matter:
white or hidden text is still extracted.
"""
from docx import Document
from docx.oxml.ns import qn
from docx.table import Table
from docx.text.paragraph import Paragraph

from . import normalize_text, ocr_blobs


def _blocks(parent):
    """Paragraphs and tables of a document / table cell, in the order they appear."""
    elm = parent.element.body if hasattr(parent, "element") and hasattr(parent.element, "body") else parent._tc
    for child in elm.iterchildren():
        if child.tag == qn("w:p"):
            yield Paragraph(child, parent)
        elif child.tag == qn("w:tbl"):
            yield Table(child, parent)


def _para_text(p: Paragraph) -> str:
    text = p.text.strip()
    if not text:
        return ""
    style = (p.style.name if p.style is not None else "") or ""
    if style.startswith("Heading") or style == "Title":
        return "\n" + text
    ppr = p._p.pPr
    if ppr is not None and ppr.numPr is not None:        # bullet / numbered list item
        return "- " + text
    return text


def _table_lines(table: Table):
    lines = []
    for row in table.rows:
        seen, cells = set(), []
        for cell in row.cells:
            if id(cell._tc) in seen:                      # merged cells repeat the same cell
                continue
            seen.add(id(cell._tc))
            cells.append(" ".join(_cell_lines(cell)).strip())
        if any(cells):
            lines.append(" | ".join(cells))
    return lines


def _cell_lines(cell):
    out = []
    for b in _blocks(cell):
        if isinstance(b, Table):
            out += _table_lines(b)
        elif b.text.strip():
            out.append(b.text.strip())
    return out


def _has_page_break(p: Paragraph, mode: str) -> bool:
    if mode == "rendered":
        return bool(p._p.xpath(".//w:lastRenderedPageBreak"))
    return bool(p._p.xpath('.//w:br[@w:type="page"]'))


def extract(path, progress=None):
    doc = Document(str(path))
    body = doc.element.body
    mode = "rendered" if body.xpath(".//w:lastRenderedPageBreak") else "explicit"

    pages, cur = [], []

    def new_page():
        nonlocal cur
        pages.append("\n".join(cur))
        cur = []

    for b in _blocks(doc):
        if isinstance(b, Table):
            cur += _table_lines(b)
            continue
        if mode == "rendered" and _has_page_break(b, mode) and cur:
            new_page()
        t = _para_text(b)
        if t:
            cur.append(t)
        if mode == "explicit" and _has_page_break(b, mode):
            new_page()
    new_page()

    # text boxes (Word often stores them twice, so de-duplicate)
    boxes, seen = [], set()
    for tb in body.xpath(".//w:txbxContent"):
        txt = "\n".join(
    "".join(t.text or "" for t in p.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"))
    for p in tb.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p")
).strip()
        if txt and txt not in seen:
            seen.add(txt)
            boxes.append(txt)
    extra = []
    if boxes:
        extra.append("[Text boxes]\n" + "\n".join(boxes))

    # headers and footers
    hf, seen_hf = [], set()
    for s in doc.sections:
        for part in (s.header, s.footer, s.first_page_header, s.first_page_footer, s.even_page_header, s.even_page_footer):
            try:
                lines = [p.text.strip() for p in part.paragraphs if p.text.strip()]
                for t in part.tables:
                    lines += _table_lines(t)
            except Exception:
                continue
            txt = "\n".join(lines)
            if txt and txt not in seen_hf:
                seen_hf.add(txt)
                hf.append(txt)
    if hf:
        extra.append("[Headers and footers]\n" + "\n".join(hf))

    # pictures inside the document (scans, screenshots of IDs, ...)
    blobs = [r.target_part.blob for r in doc.part.rels.values() if r.reltype.endswith("/image")]
    if blobs:
        try:
            texts = ocr_blobs(blobs)
            if texts:
                extra.append("[Text found in pictures]\n" + "\n".join(texts))
        except RuntimeError:
            extra.append("[Pictures in this file were not read because OCR is not installed]")

    if extra:
        pages[0] = (pages[0] + "\n\n" + "\n\n".join(extra)).strip()
    return [{"page": i, "text": normalize_text(t)} for i, t in enumerate(pages, 1)]