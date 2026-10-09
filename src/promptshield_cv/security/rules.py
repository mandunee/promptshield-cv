from copy import deepcopy
import pymupdf


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
    for page in result["pages"]:
        rect = pymupdf.Rect(0, 0, page["width"], page["height"])
        for span in page["spans"]:
            span["signals"] = span_signals(span, rect)
            count += bool(span["signals"] or span["unicode_findings"])
    result["security"] = {"method": "heuristic_rules_v1", "flagged_span_count": count,
                          "verdict": "not_assessed"}
    return result
