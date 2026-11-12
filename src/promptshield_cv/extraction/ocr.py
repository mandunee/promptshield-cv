import pymupdf


def extract_visible_text(pdf_path, password=None):
    results = {}

    with pymupdf.open(pdf_path) as doc:
        if doc.needs_pass and not doc.authenticate(password or ""):
            raise ValueError("Password required or incorrect for OCR")

        for page in doc:
            try:
                textpage = page.get_textpage_ocr(
                    language="eng",
                    dpi=200,
                    full=True,
                )

                results[page.number + 1] = {
                    "status": "completed",
                    "text": textpage.extractText(),
                }

            except Exception as exc:
                results[page.number + 1] = {
                    "status": "failed",
                    "error": str(exc),
                }

    return results