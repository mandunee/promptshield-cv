from copy import deepcopy
import pymupdf
from ..extraction.normalization import normalize_for_comparison


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

def scan_ocr_discrepancy(document, ocr_results):
    for page in document["pages"]:
        page_num = page["number"]
        raw_text = page["raw_text"]
        ocr_text = ocr_results.get(page_num, "")
        
        # normalize both ocr and raw text
        raw_clean = normalize_for_comparison(raw_text)
        ocr_clean = normalize_for_comparison(ocr_text)
        
        # ignore one-letter words
        raw_words = set(w for w in raw_clean.split() if len(w) > 1)
        ocr_words = set(w for w in ocr_clean.split() if len(w) > 1)

        # calculate ratio
        missing_words = raw_words - ocr_words
        total_raw = len(raw_words)
        missing_ratio = (len(missing_words) / total_raw) if total_raw > 0 else 0
        
        # add to schema
        page["ocr_text"] = ocr_text
        page["missing_word_ratio"] = round(missing_ratio, 2)
        
        # flagged for hidden text if above threshold (currently 0.15, but TBD)
        if missing_ratio > 0.15: 
            page.setdefault("signals", []).append("ocr_text_discrepancy")
            document["security"]["flagged_span_count"] += 1
            document["security"]["verdict"] = "hidden_text_detected_via_ocr"
            
    return document
