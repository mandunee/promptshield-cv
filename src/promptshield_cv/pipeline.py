from .extraction.pdf import extract_pdf
from .extraction.ocr import extract_visible_text
from .security.rules import scan_document, scan_ocr_discrepancy

def extract_and_scan(path, password=None, max_pages=200, max_bytes=50 * 1024 * 1024):
    document = scan_document(extract_pdf(path, password, max_pages, max_bytes))
    
    # if raw text extraction doesn't find anything flagged, run OCR to make sure
    if document["security"]["flagged_span_count"] == 0:
        ocr_results = extract_visible_text(path)
        document = scan_ocr_discrepancy(document, ocr_results)
        
    return document
