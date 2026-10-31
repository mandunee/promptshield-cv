import pymupdf

# Requires Tesseract to be installed
def extract_visible_text(pdf_path):
    ocr_results = {}
    
    try:
        with pymupdf.open(pdf_path) as doc:
            for page in doc:

                # PyMuPDF is smart, will skip OCR if can read text layer, disable this via full = True.
                textpage = page.get_textpage_ocr(language="eng", dpi=200, full=True)
                
                # Extract the text from the OCR'd page
                text = textpage.extractText()
                
                # Save to our results dictionary
                ocr_results[page.number + 1] = text
                
    except Exception as e:
        print(f"OCR failed (Is the Tesseract engine installed?): {e}")
        # if OCR fails entirely, return empty strings so the pipeline doesn't crash 
        # (the comparison will just flag it as highly suspicious but will print the above message first).
        with pymupdf.open(pdf_path) as doc:
            for page in doc:
                ocr_results[page.number + 1] = ""

    return ocr_results
