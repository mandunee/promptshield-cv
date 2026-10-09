import unicodedata

def unicode_findings(text):
    return [{"offset": i, "codepoint": f"U+{ord(c):04X}",
             "name": unicodedata.name(c, "UNKNOWN")}
            for i, c in enumerate(text)
            if unicodedata.category(c) == "Cf" or (unicodedata.category(c) == "Cc" and c not in "\n\r\t")]


def normalize_text(text):
    # Keep joiners: removing ZWJ/ZWNJ can damage legitimate writing.
    removable = {"\u200b", "\ufeff", "\u2060"}
    return unicodedata.normalize("NFC", "".join(c for c in text if c not in removable))


