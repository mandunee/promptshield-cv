from .extraction.pdf import extract_pdf
from .security.rules import scan_document


def extract_and_scan(path, password=None, max_pages=200, max_bytes=50 * 1024 * 1024):
    return scan_document(extract_pdf(path, password, max_pages, max_bytes))
