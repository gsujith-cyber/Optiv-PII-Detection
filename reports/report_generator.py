"""reports/report_generator.py - audit report for one processed file.

The report says WHAT was found and WHERE (type, page, character position, tag) but never contains the real PII
values, so it is safe to share with auditors, attach to a ticket, or show in the deck.

    report = build_report(result)        # result = the dict returned by pipeline.run_pipeline()
    to_csv(report)  /  to_json(report)  /  to_markdown(report)
"""
import csv
import io
import json
import re
from datetime import datetime, timezone

_PH = re.compile(r"\[[A-Z_]+_\d+\]")


def build_report(result: dict) -> dict:
    tags = {v: k for k, v in result.get("mapping", {}).items() if _PH.fullmatch(k)}   # real value -> tag
    findings = result.get("findings", [])

    by_type = {}
    for f in findings:
        d = by_type.setdefault(f["type"], {"count": 0, "pages": set()})
        d["count"] += 1
        d["pages"].add(f["page"])

    return {
        "file": result.get("name"),
        "file_type": result.get("file_type"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "pages_or_slides": result.get("page_count"),
        "pii_found": result.get("total", len(findings)),
        "redaction_percent": result.get("redaction_pct"),
        "remaining_after_check": result.get("remaining"),
        "time_seconds": result.get("timings", {}),
        "summary_by_type": [{"type": t, "count": d["count"], "pages": sorted(d["pages"])} for t, d in sorted(by_type.items())],
        "locations": [{"tag": tags.get(f["value"], ""), "type": f["type"], "page": f["page"],
                       "start": f["start"], "end": f["end"], "length": f["end"] - f["start"]} for f in findings],
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_csv(report: dict) -> str:
    """One row per PII item (no real values) - opens directly in Excel."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["file", "file_type", "tag", "pii_type", "page_or_slide", "start", "end", "length"])
    for loc in report["locations"]:
        w.writerow([report["file"], report["file_type"], loc["tag"], loc["type"], loc["page"], loc["start"], loc["end"], loc["length"]])
    return buf.getvalue()


def to_markdown(report: dict) -> str:
    lines = [f"# PII audit report: {report['file']}", "",
             f"- File type: {report['file_type']}",
             f"- Pages / slides: {report['pages_or_slides']}",
             f"- PII items found: {report['pii_found']}",
             f"- Redaction: {report['redaction_percent']}%",
             f"- Remaining after the second check: {report['remaining_after_check']}",
             f"- Generated (UTC): {report['generated_at']}", "",
             "| PII type | Count | Pages |", "|---|---|---|"]
    for row in report["summary_by_type"]:
        lines.append(f"| {row['type']} | {row['count']} | {', '.join(map(str, row['pages']))} |")
    return "\n".join(lines) + "\n"