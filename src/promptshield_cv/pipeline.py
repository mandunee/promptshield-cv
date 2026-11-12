from .extraction.pdf import extract_pdf
from .extraction.ocr import extract_visible_text
from .security.rules import scan_document
from .security.discrepancy import scan_ocr_discrepancy

def extract_and_scan(path, password=None, max_pages=200, max_bytes=50 * 1024 * 1024,
                     ocr=False, ocr_threshold=0.15):
    document = scan_document(extract_pdf(path, password, max_pages, max_bytes))
    if ocr:
        document = scan_ocr_discrepancy(
            document, extract_visible_text(path, password), ocr_threshold)
    else:
        document['security']['ocr'] = {'status': 'skipped', 'reason': 'OCR not requested'}
    return document