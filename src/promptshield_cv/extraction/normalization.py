import unicodedata
import re

def unicode_findings(text):
    return [{"offset": i, "codepoint": f"U+{ord(c):04X}",
             "name": unicodedata.name(c, "UNKNOWN")}
            for i, c in enumerate(text)
            if unicodedata.category(c) == "Cf" or (unicodedata.category(c) == "Cc" and c not in "\n\r\t")]


def normalize_text(text):
    # Keep joiners: removing ZWJ/ZWNJ can damage legitimate writing.
    removable = {"\u200b", "\ufeff", "\u2060"}
    return unicodedata.normalize("NFC", "".join(c for c in text if c not in removable))

# helps normalizing results from both OCR and raw text, to be compared
# lowering letters and replacing non-alphanumeric characters with space, remove leading & trailing whitespaces
def normalize_for_comparison(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    return text.strip()
