from copy import deepcopy
import pymupdf
from .text_rules import scan_text


def span_signals(span, page_rect):
    reasons = []
    if span["render_type"] == 3:
        reasons.append("invisible_render_mode")
    if span["opacity"] <= 0.01:
        reasons.append("near_zero_opacity")
    if span["size"] < 3:
        reasons.append("tiny_font")
    color = span.get("color", ())
    if color and min(color) >= 0.95:
        reasons.append("near_white_text")
    if not page_rect.intersects(pymupdf.Rect(span["bbox"])):
        reasons.append("outside_page")
    return reasons


def scan_document(document):
    result = deepcopy(document)
    count = 0
    findings = []
    for key, value in result.get("metadata", {}).items():
        if isinstance(value, str):
            findings.extend(scan_text(value, f"metadata.{key}"))
    for key in ("xmp_metadata",):
        if isinstance(result.get(key), str):
            findings.extend(scan_text(result[key], key))
    for page in result["pages"]:
        page_number = page.get("number")
        # Include invisible spans: raw_text extraction may omit them.
        fields = [
            ("raw_text", page.get("raw_text", "")),
            (
                "span_text",
                "\n".join(s["text"] for s in page["spans"]),
            ),
        ]
        for index, annotation in enumerate(page.get("annotations", [])):
            for key, value in annotation.get("info", {}).items():
                if isinstance(value, str):
                    fields.append((f"annotations.{index}.info.{key}", value))
        seen = set()
        for source, text in fields:
            for finding in scan_text(text, source, page_number):
                # Prefer raw_text evidence when the same phrase also occurs in spans.
                identity = (
                    finding["rule_id"],
                    finding["matched_text"].casefold(),
                )
                if source == "span_text" and identity in seen:
                    continue
                findings.append(finding)
                seen.add(identity)
        rect = pymupdf.Rect(0, 0, page["width"], page["height"])
        for span in page["spans"]:
            span["signals"] = span_signals(span, rect)
            count += bool(
                span["signals"] or span["unicode_findings"]
            )
    result["security"] = {
        "method": "heuristic_rules_v2",
        "flagged_span_count": count,
        "verdict": "suspicious" if findings else "no_rule_match",
        "text_findings": findings,
        "text_finding_count": len(findings),
        "limitations": [
            "Rule matches are indicators, not proof of an attack.",
            "No rule match does not establish safety.",
            "Quoted attack examples may trigger rules; paraphrases may evade them.",
            "Visual signals alone do not establish prompt injection.",
        ],
    }
    return result