"""tests/evaluate.py - measures the two targets in the case study:  PII coverage  and  structure retention.

Usage (from the repo root):
    python tests/evaluate.py tests/ground_truth.json

ground_truth.json (you write it once, by hand, for your sample files):
    [ {"file": "test_data/input/policy.docx",
       "pii": [ {"type": "PERSON", "value": "Priya Sharma"},
                {"type": "EMAIL",  "value": "priya.sharma@cadence.com"} ] },
      ... ]

Prints a table and writes tests/evaluation_report.md (paste it into the deck).

  Coverage (recall)   = labelled PII values that are NOT in the redacted output / all labelled values   (target: ~100%)
  Precision           = detected items that are really PII / all detected items  (shows over-redaction)
  Structure retention = share of the file's own paragraphs / table rows / slide lines that appear in the extracted text
                        (target: >= 80%). The reference is read straight from the file's XML (or pdfplumber for PDFs),
                        independent of the extractor.
"""
import json
import re
import sys
import time
import zipfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pipeline  # noqa: E402


def _norm(s: str) -> str:
    return re.sub(r"\W+", " ", s.lower()).strip()


# ------------------------------------------------------- structure retention ---
def _reference_units(path: Path):
    """Independent list of the file's text units (paragraphs, table rows, slide lines). None = not measurable."""
    ext = path.suffix.lower()
    units = []
    try:
        if ext in (".docx", ".pptx"):
            tag = "w:p" if ext == ".docx" else "a:p"
            with zipfile.ZipFile(path) as z:
                names = [n for n in z.namelist() if re.match(r"(word/(document|header\d*|footer\d*)\.xml|ppt/slides/slide\d+\.xml)$", n)]
                for n in names:
                    xml = z.read(n).decode("utf8", "ignore")
                    for para in re.findall(rf"<{tag}[ >].*?</{tag}>", xml, flags=re.S):
                        t = "".join(re.findall(r"<(?:w|a):t[^>]*>([^<]*)</(?:w|a):t>", para))
                        if len(t.strip()) >= 4:
                            units.append(t)
        elif ext == ".pdf":
            import pdfplumber
            with pdfplumber.open(path) as pdf:
                for pg in pdf.pages:
                    for line in (pg.extract_text() or "").splitlines():
                        if len(line.strip()) >= 4:
                            units.append(line)
            if not units:
                return None                      # scanned PDF: no text layer to compare with
        elif ext == ".txt":
            units = [l for l in path.read_text(errors="ignore").splitlines() if len(l.strip()) >= 4]
        else:
            return None
    except Exception:
        return None
    return units or None


def structure_retention(path: Path, pages) -> float | None:
    units = _reference_units(path)
    if not units:
        return None
    extracted = _norm(" ".join(p["text"] for p in pages))
    found = sum(1 for u in units if _norm(u) and _norm(u) in extracted)
    return found / len(units)


# ------------------------------------------------------------------ evaluation ---
def evaluate(truth_file: str):
    items = json.loads(Path(truth_file).read_text(encoding="utf-8"))
    base = Path(truth_file).resolve().parent
    rows, per_type = [], defaultdict(lambda: [0, 0])
    tot_truth = tot_leaked = tot_found = tot_correct = 0
    leaks_detail, fp_detail = [], []

    for it in items:
        path = Path(it["file"])
        if not path.exists():
            path = (base.parent / it["file"]) if (base.parent / it["file"]).exists() else base / it["file"]
        t0 = time.time()
        res = pipeline.run_pipeline(path.read_bytes(), path.name)
        secs = time.time() - t0
        red = _norm(res["redacted_text"])
        truth = it["pii"]

        leaked = [t for t in truth if _norm(t["value"]) and _norm(t["value"]) in red]
        for t in truth:
            per_type[t["type"]][0] += 1
            if t not in leaked:
                per_type[t["type"]][1] += 1
        tvals = [_norm(t["value"]) for t in truth]
        correct = 0
        for f in res["findings"]:
            fv = _norm(f["value"])
            if any(fv and (fv in tv or tv in fv) for tv in tvals):
                correct += 1
            else:
                fp_detail.append((path.name, f["type"], f["value"]))
        leaks_detail += [(path.name, t["type"], t["value"]) for t in leaked]

        pages = pipeline._norm_pages(pipeline._extract(Path(res["orig_path"]), {}))
        sr = structure_retention(path, pages)
        rows.append((path.name, res["file_type"], len(truth), len(truth) - len(leaked), len(res["findings"]), correct, sr, secs))
        tot_truth += len(truth)
        tot_leaked += len(leaked)
        tot_found += len(res["findings"])
        tot_correct += correct

    recall = (tot_truth - tot_leaked) / tot_truth if tot_truth else 1.0
    precision = tot_correct / tot_found if tot_found else 1.0
    return rows, per_type, recall, precision, leaks_detail, fp_detail


def report(rows, per_type, recall, precision, leaks, fps) -> str:
    out = ["# Evaluation report", "",
           f"- **PII coverage (recall): {recall:.1%}**  (target: close to 100%)",
           f"- **Precision: {precision:.1%}**",
           "", "## Per file", "",
           "| File | Type | Labelled PII | Redacted | Detected | Correct | Structure retained | Time (s) |", "|---|---|---|---|---|---|---|---|"]
    for n, ft, lab, red, det, cor, sr, sec in rows:
        out.append(f"| {n} | {ft} | {lab} | {red} | {det} | {cor} | {'n/a' if sr is None else f'{sr:.0%}'} | {sec:.1f} |")
    srs = [r[6] for r in rows if r[6] is not None]
    if srs:
        out += ["", f"**Average structure retention: {sum(srs) / len(srs):.1%}**  (target: at least 80%)"]
    out += ["", "## Coverage by PII type", "", "| Type | Labelled | Redacted | Coverage |", "|---|---|---|---|"]
    for t, (n, ok) in sorted(per_type.items()):
        out.append(f"| {t} | {n} | {ok} | {ok / n:.0%} |")
    out += ["", "## Missed PII (leaks)", ""] + ([f"- {f}: {t} `{v}`" for f, t, v in leaks] or ["- none"])
    out += ["", "## Possible over-redaction (detected but not in the labels)", ""] + ([f"- {f}: {t} `{v}`" for f, t, v in fps] or ["- none"])
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    pipeline.warmup()
    md = report(*evaluate(sys.argv[1]))
    print(md)
    Path(__file__).with_name("evaluation_report.md").write_text(md, encoding="utf-8")
    print("Saved tests/evaluation_report.md")