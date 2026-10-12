"""processing/file_redactor.py - writes a redacted COPY of the original file in its own format.

    result = redact_file("data/original/x.docx", mapping)        # mapping = {"[PERSON_1]": "John Smith", ...}
    result -> {"path": "data/redacted/x_redacted.docx", "leftovers": 0, "warnings": [...]}

PDF   real redaction: the text under each match is removed (not just covered with a box). Scanned pages are
      read with OCR, the matching words are blacked out in the image and the page is rebuilt from that image.
DOCX  every text node in the body, headers, footers, text boxes, comments and footnotes; hyperlink targets; author fields.
PPTX  every slide, notes page, layout and master; hyperlink targets; author fields.
TXT   plain replace.
After saving, the new file is read again and checked: `leftovers` = how many original values are still found in it.
Pictures inside DOCX/PPTX are read with OCR and the PII in them is blacked out (needs Tesseract; a warning appears if missing).
"""
import io
import os
import re
import zipfile
from difflib import SequenceMatcher
from pathlib import Path

_PH = re.compile(r"\[[A-Z_]+_\d+\]")
OCR_DPI = 150
MIN_TEXT = 25
MIN_IMG = (200, 60)
_XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
_C_V = "{http://schemas.openxmlformats.org/drawingml/2006/chart}v"
_MARKERS = {"[Text found in pictures]": "inside a picture", "[Speaker notes]": "speaker notes", "[Headers and footers]": "header or footer",
            "[Text boxes]": "text box", "[Form fields and comments]": "form field or comment"}


# ------------------------------------------------------------ shared helpers --
def _pairs(mapping: dict):
    """[(real value, tag)] longest first. A multi-line value is split into its lines."""
    out = {}
    for tag, value in mapping.items():
        if not _PH.fullmatch(tag) or not value:
            continue
        for part in str(value).split("\n"):
            part = part.strip()
            if len(part) >= 2:
                out[part] = tag
    return sorted(out.items(), key=lambda kv: -len(kv[0]))


def _compile(pairs):
    if not pairs:
        return None, {}
    rx = re.compile("|".join(r"(?<!\w)" + re.escape(v) + r"(?!\w)" for v, _ in pairs), re.I)
    return rx, {v.lower(): t for v, t in pairs}


def _sub(text: str, rx, lookup) -> str:
    return text if rx is None else rx.sub(lambda m: lookup.get(m.group().lower(), "[REDACTED]"), text)


def _count_pictures(path: Path, folder: str) -> int:
    try:
        from PIL import Image
        n = 0
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.startswith(folder) and name.lower().endswith((".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif")):
                    try:
                        im = Image.open(io.BytesIO(z.read(name)))
                        if im.width >= MIN_IMG[0] and im.height >= MIN_IMG[1]:
                            n += 1
                    except Exception:
                        pass
        return n
    except Exception:
        return 0


# --------------------------------------------------------------------- TXT ---
def _redact_txt(src, out, rx, lookup, warnings, pairs=None, notes=None, aggressive=False):
    data = Path(src).read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    Path(out).write_text(_sub(text, rx, lookup), encoding="utf-8")


# ------------------------------------------------------- DOCX / PPTX (XML) ---
def _fix_xml(root, p_tag, t_tag, rx, lookup) -> None:
    """For every paragraph: join its text pieces, replace, and write the result back into the first piece."""
    for p in root.iter(p_tag):
        ts = []
        for t in p.iter(t_tag):
            a = t.getparent()
            while a is not None and a.tag != p_tag:
                a = a.getparent()
            if a is p:                                  # only this paragraph's own text (not a nested text box)
                ts.append(t)
        if not ts:
            continue
        full = "".join(t.text or "" for t in ts)
        new = _sub(full, rx, lookup)
        if new != full:
            ts[0].text = new
            ts[0].set(_XML_SPACE, "preserve")
            for t in ts[1:]:
                t.text = ""


def _fix_misc(root, rx, lookup) -> None:
    """Chart values (c:v) and picture / shape alt text (descr, title)."""
    for el in root.iter():
        tag = el.tag if isinstance(el.tag, str) else ""
        if tag == _C_V and el.text:
            el.text = _sub(el.text, rx, lookup)
        elif tag.endswith("}cNvPr") or tag.endswith("}docPr"):
            for a in ("descr", "title"):
                if el.get(a):
                    el.set(a, _sub(el.get(a), rx, lookup))


def _fix_diagram(part, p_tag, t_tag, rx, lookup) -> None:
    """SmartArt data parts are stored as plain XML bytes."""
    from lxml import etree
    try:
        root = etree.fromstring(part.blob)
        _fix_xml(root, p_tag, t_tag, rx, lookup)
        part._blob = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
    except Exception:
        pass


def _fix_links(part, rx, lookup) -> None:
    try:
        for rel in part.rels.values():
            if rel.is_external:
                new = _sub(rel.target_ref, rx, lookup)
                if new != rel.target_ref:
                    rel._target = new
    except Exception:
        pass


def _redact_docx(src, out, rx, lookup, warnings, pairs=None, notes=None, aggressive=False):
    from docx import Document
    from docx.oxml.ns import qn
    from lxml import etree
    doc = Document(str(src))
    for part in doc.part.package.iter_parts():
        el = getattr(part, "_element", None)
        if el is not None:
            _fix_xml(el, qn("w:p"), qn("w:t"), rx, lookup)
            _fix_misc(el, rx, lookup)
        elif "/diagrams/" in str(part.partname) and str(part.partname).endswith(".xml"):
            _fix_diagram(part, qn("a:p"), qn("a:t"), rx, lookup)
        elif re.search(r"/word/(footnotes|endnotes|comments)\.xml$", str(part.partname)):
            try:
                root = etree.fromstring(part.blob)
                _fix_xml(root, qn("w:p"), qn("w:t"), rx, lookup)
                part._blob = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
            except Exception:
                pass
        _fix_links(part, rx, lookup)
    cp = doc.core_properties
    cp.author = cp.last_modified_by = cp.comments = cp.keywords = cp.subject = ""
    _blackout_pictures(doc.part.package, pairs, "/word/media/", warnings, notes, aggressive)
    doc.save(str(out))


def _redact_pptx(src, out, rx, lookup, warnings, pairs=None, notes=None, aggressive=False):
    from pptx import Presentation
    from pptx.oxml.ns import qn
    prs = Presentation(str(src))
    for part in prs.part.package.iter_parts():
        el = getattr(part, "_element", None)
        if el is not None:
            _fix_xml(el, qn("a:p"), qn("a:t"), rx, lookup)
            _fix_misc(el, rx, lookup)
        elif "/diagrams/" in str(part.partname) and str(part.partname).endswith(".xml"):
            _fix_diagram(part, qn("a:p"), qn("a:t"), rx, lookup)
        _fix_links(part, rx, lookup)
    cp = prs.core_properties
    cp.author = cp.last_modified_by = cp.comments = cp.keywords = cp.subject = ""
    _blackout_pictures(prs.part.package, pairs, "/ppt/media/", warnings, notes, aggressive)
    prs.save(str(out))


# --------------------------------------------------------------------- PDF ---
def _tesseract():
    import pytesseract
    win = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.name == "nt" and os.path.exists(win):
        pytesseract.pytesseract.tesseract_cmd = win
    pytesseract.get_tesseract_version()
    return pytesseract


def _blackout(img, pairs, aggressive: bool = False) -> int:
    """Find the PII words in a PIL RGB image with OCR and paint them black. Returns how many boxes were painted.
    aggressive: OCR the picture at 2x size, accept looser matches and black out single words of a value too."""
    from PIL import Image, ImageDraw
    pyt = _tesseract()
    k = 2 if (aggressive and img.width < 2000) else 1
    gray = img.convert("L")
    if k > 1:
        gray = gray.resize((gray.width * k, gray.height * k), Image.LANCZOS)
    d = pyt.image_to_data(gray, config="--oem 1 --psm 4", output_type=pyt.Output.DICT)
    words = [(d["text"][i], d["left"][i] / k, d["top"][i] / k, d["width"][i] / k, d["height"][i] / k)
             for i in range(len(d["text"])) if d["text"][i].strip()]
    norm = [re.sub(r"\W", "", w[0]).lower() for w in words]
    draw, painted = ImageDraw.Draw(img), 0
    limit = 0.8 if aggressive else 0.88

    def paint(i, j):
        nonlocal painted
        for q in range(i, j):
            _, x, y, w, h = words[q]
            draw.rectangle([x - 3, y - 3, x + w + 3, y + h + 3], fill=(0, 0, 0))
            painted += 1

    for value, _tag in pairs:
        target = re.sub(r"\W", "", value).lower()
        if len(target) < 2:
            continue
        for i in range(len(words)):
            acc, j = "", i
            while j < len(words) and len(acc) < len(target):
                acc += norm[j]
                j += 1
            if acc and abs(len(acc) - len(target)) <= 2 and (acc == target or SequenceMatcher(None, acc, target).ratio() >= limit):
                paint(i, j)
        if aggressive:
            for tok in re.findall(r"\w{3,}", value):
                t = tok.lower()
                for i, w in enumerate(norm):
                    if len(w) >= 3 and abs(len(w) - len(t)) <= 2 and (w == t or SequenceMatcher(None, w, t).ratio() >= 0.8):
                        paint(i, i + 1)
    return painted


def _blackout_scanned_page(page, pairs, aggressive=False) -> bytes:
    """Render a scanned PDF page, black out the PII words, return PNG bytes."""
    import pymupdf
    from PIL import Image
    pix = page.get_pixmap(dpi=OCR_DPI, colorspace=pymupdf.csRGB)
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    _blackout(img, pairs, aggressive)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _blackout_pictures(package, pairs, folder, warnings, notes, aggressive=False) -> None:
    """DOCX/PPTX: OCR every embedded picture and black out the PII in it (same picture format is kept)."""
    from PIL import Image
    try:
        _tesseract()
    except Exception:
        n = sum(1 for p in package.iter_parts() if str(p.partname).startswith(folder))
        if n:
            warnings.append("Pictures were not checked because OCR (Tesseract) is not installed.")
        return
    changed = 0
    for part in package.iter_parts():
        name = str(part.partname)
        if not name.startswith(folder) or not name.lower().endswith((".png", ".jpg", ".jpeg")):
            continue
        try:
            im = Image.open(io.BytesIO(part.blob))
            fmt = im.format
            if im.width < MIN_IMG[0] or im.height < MIN_IMG[1]:
                continue
            rgb = im.convert("RGB")
            if _blackout(rgb, pairs, aggressive):
                buf = io.BytesIO()
                rgb.save(buf, "JPEG" if fmt == "JPEG" else "PNG")
                part._blob = buf.getvalue()
                changed += 1
        except Exception:
            continue
    if changed:
        notes.append(f"PII inside {changed} picture(s) was blacked out.")


def _redact_pdf(src, out, rx, lookup, warnings, pairs=None, notes=None, aggressive=False):
    import pymupdf
    doc = pymupdf.open(str(src))
    scanned = []
    for i, page in enumerate(doc):
        if len(page.get_text("text").strip()) < MIN_TEXT:
            scanned.append(i)
            continue
        hit = False
        for value, tag in pairs:
            for rect in page.search_for(value):
                page.add_redact_annot(rect, text=tag, fontname="helv", fontsize=7, fill=(0.05, 0.05, 0.1), text_color=(1, 1, 1))
                hit = True
        if hit:
            page.apply_redactions()                       # removes the text under the boxes
    if scanned:
        try:
            images = {i: _blackout_scanned_page(doc[i], pairs, aggressive) for i in scanned}
        except Exception as e:
            doc.close()
            raise RuntimeError(f"Scanned pages need OCR (Tesseract): {e}")
        base = pymupdf.open("pdf", doc.tobytes())
        final = pymupdf.open()
        for i in range(len(base)):
            if i in images:
                pg = final.new_page(width=base[i].rect.width, height=base[i].rect.height)
                pg.insert_image(pg.rect, stream=images[i])
            else:
                final.insert_pdf(base, from_page=i, to_page=i)
        base.close()
    else:
        final = doc
    final.set_metadata({})
    final.save(str(out), garbage=4, deflate=True)
    final.close()
    if final is not doc:
        doc.close()


# ------------------------------------------------------------------- main ----
def redact_file(src_path, mapping: dict, out_path=None, verify: bool = True, aggressive: bool = False) -> dict:
    src = Path(src_path)
    ext = src.suffix.lower()
    if out_path is None:
        out_dir = Path("data") / "redacted"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{src.stem}_redacted{ext}"
    out = Path(out_path)
    pairs = _pairs(mapping)
    rx, lookup = _compile(pairs)
    warnings, notes = [], []

    if ext == ".pdf":
        _redact_pdf(src, out, rx, lookup, warnings, pairs, notes, aggressive)
    elif ext == ".docx":
        _redact_docx(src, out, rx, lookup, warnings, pairs, notes, aggressive)
    elif ext == ".pptx":
        _redact_pptx(src, out, rx, lookup, warnings, pairs, notes, aggressive)
    elif ext == ".txt":
        _redact_txt(src, out, rx, lookup, warnings, pairs, notes, aggressive)
    else:
        raise ValueError("A redacted copy in the original format is available for PDF, DOCX, PPTX and TXT.")

    leftovers, items = None, []
    if verify:
        try:                                              # read the new file again and look for the old values
            from extractors import extract_any
            pages = [{"page": p["page"], "text": p["text"]} for p in extract_any(str(out))]
            items, leftovers = _scan_leftovers(pages, pairs)
        except Exception:
            leftovers = None
    return {"path": str(out), "leftovers": leftovers, "leftover_items": items, "warnings": warnings, "notes": notes}


# ------------------------------------------------- check coverage / rescan ----
def _where(text: str, pos: int) -> str:
    """Which part of the page a match sits in (main text, picture, notes ...), from the section markers the extractors write."""
    best, name = -1, "main text"
    for marker, label in _MARKERS.items():
        i = text.rfind(marker, 0, pos)
        if i > best:
            best, name = i, label
    return name


def _scan_leftovers(pages, pairs):
    """Original values still present: ([{tag, type, page, where}], number of distinct values)."""
    items, values = [], set()
    for pg in pages:
        text = pg["text"]
        low = text.lower()
        for value, tag in pairs:
            if len(value) < 3:
                continue
            m = re.search(r"(?<!\w)" + re.escape(value.lower()) + r"(?!\w)", low)
            if m:
                items.append({"tag": tag, "type": tag.strip("[]").rsplit("_", 1)[0], "page": pg["page"], "where": _where(text, m.start())})
                values.add(value)
    return items, len(values)


def check_copy(copy_path, mapping: dict) -> dict:
    """Did the redacted copy keep any original value, and does a fresh scan find PII that was never redacted?
    Returns locations and types only (never the real values)."""
    import pipeline
    from extractors import extract_any
    pairs = _pairs(mapping)
    pages = pipeline._norm_pages(extract_any(str(copy_path)))
    items, n = _scan_leftovers(pages, pairs)
    known = {v.lower() for v, _ in pairs}
    new = []
    for f in pipeline._detect(pages):
        if f["value"].strip().lower() in known:
            continue
        text = next(p["text"] for p in pages if p["page"] == f["page"])
        new.append({"type": f["type"], "page": f["page"], "where": _where(text, f["start"])})
    return {"pages": len(pages), "leftover_items": items, "leftovers": n, "new_items": new}


def _next_tag(mapping: dict, typ: str) -> str:
    n = 0
    for k in mapping:
        m = re.fullmatch(r"\[" + re.escape(typ) + r"_(\d+)\]", k)
        if m:
            n = max(n, int(m.group(1)))
    return f"[{typ}_{n + 1}]"


def rescan_copy(copy_path, mapping: dict, max_rounds: int = 2) -> dict:
    """Read the redacted copy again, add any PII the first pass missed, redact it, and use the stronger picture
    black-out. The copy is replaced in place. Returns the extended mapping and a before / after check."""
    import pipeline
    from extractors import extract_any
    path, mapping = Path(copy_path), dict(mapping)
    before = check_copy(path, mapping)
    added, warnings, notes = 0, [], []
    for _ in range(max_rounds):
        pages = pipeline._norm_pages(extract_any(str(path)))
        known = {str(v).lower() for v in mapping.values()}
        round_added = 0
        for f in pipeline._detect(pages):
            v = f["value"].strip()
            if v and v.lower() not in known:
                mapping[_next_tag(mapping, f["type"])] = v
                known.add(v.lower())
                round_added += 1
        added += round_added
        tmp = path.with_name(path.stem + "__tmp" + path.suffix)
        res = redact_file(path, mapping, out_path=tmp, verify=True, aggressive=True)
        os.replace(tmp, path)
        warnings, notes = res["warnings"], res["notes"]
        if res["leftovers"] == 0 and round_added == 0:
            break
    return {"path": str(path), "mapping": mapping, "added": added, "before": before, "after": check_copy(path, mapping),
            "warnings": warnings, "notes": notes}