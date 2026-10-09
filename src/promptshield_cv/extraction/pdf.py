"""Local evidence extraction; no security verdicts."""
import hashlib
from pathlib import Path
import pymupdf
from .normalization import normalize_text, unicode_findings

def extract_pdf(path, password=None, max_pages=200, max_bytes=50 * 1024 * 1024):
    path = Path(path)
    if path.stat().st_size > max_bytes:
        raise ValueError("PDF exceeds input size limit")
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError("PDF exceeds input size limit")
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        if not doc.is_pdf:
            raise ValueError("Input must be a PDF")
        encrypted = bool(doc.needs_pass)
        if doc.needs_pass and not doc.authenticate(password or ""):
            raise ValueError("Password required or incorrect")
        if len(doc) > max_pages:
            raise ValueError("PDF exceeds page limit")
        pages = []
        for page in doc:
            raw = page.get_text("text", sort=True)
            spans = []
            for span in page.get_texttrace():
                text = "".join(chr(c[0]) for c in span["chars"])
                spans.append({"text": text, "bbox": list(span["bbox"]),
                              "font": span["font"], "size": span["size"],
                              "color": list(span.get("color", ())), "opacity": span["opacity"],
                              "render_type": span["type"],
                              "unicode_findings": unicode_findings(text)})
            annotations = []
            for annot in page.annots() or []:
                annotations.append({"type": annot.type[1], "bbox": list(annot.rect), "info": annot.info})
            warnings = []
            if not raw.strip():
                warnings.append("no_extractable_text_ocr_may_be_required")
            pages.append({"number": page.number + 1, "width": page.rect.width,
                          "height": page.rect.height, "raw_text": raw,
                          "normalized_text": normalize_text(raw),
                          "unicode_findings": unicode_findings(raw), "spans": spans,
                          "annotations": annotations,
                          "links": [{"bbox": list(x["from"]), "uri": x.get("uri"),
                                     "target_page": x.get("page"), "kind": x["kind"]}
                                    for x in page.get_links()],
                          "image_count": len(page.get_images()), "warnings": warnings})
        return {"schema_version": "1.0", "source": {"filename": path.name,
                "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)},
                "page_count": len(doc), "encrypted": encrypted,
                "metadata": doc.metadata, "xmp_metadata": doc.get_xml_metadata(),
                "embedded_files": doc.embfile_names(), "pages": pages,
                "limitations": ["Signals are heuristics, not proof of malicious injection.",
                                "Normalization is not a prompt-injection defense.",
                                "No OCR, table reconstruction, occlusion or background analysis.",
                                "All extracted text, metadata and annotations are untrusted."]}
