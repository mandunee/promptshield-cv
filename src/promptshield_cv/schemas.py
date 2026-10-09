SCHEMA_VERSION = "1.0"


def validate_evidence(value):
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Expected PDF evidence schema_version 1.0")
    if not isinstance(value.get("pages"), list):
        raise ValueError("Evidence requires pages array")
    for page in value["pages"]:
        if not isinstance(page, dict) or not isinstance(page.get("spans"), list):
            raise ValueError("Each page requires spans array")
        for key in ("width", "height"):
            if not isinstance(page.get(key), (int, float)) or page[key] <= 0:
                raise ValueError("Page dimensions must be positive numbers")
        for span in page["spans"]:
            if not isinstance(span, dict) or not all(k in span for k in ("text", "bbox", "size", "opacity", "render_type", "unicode_findings")):
                raise ValueError("Invalid span evidence")
    return value
