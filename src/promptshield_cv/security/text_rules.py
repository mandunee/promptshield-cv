import re
import unicodedata

_RULES = (
    ("instruction_override", "high", r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?)\b"),
    ("evaluation_manipulation", "high", r"\b(?:give|assign|award)\s+(?:this\s+)?(?:candidate|applicant|resume|cv)\s+(?:a\s+|the\s+)?(?:maximum|highest|perfect|full)\s+(?:score|rating|marks)\b|\b(?:rank|rate)\s+(?:this\s+)?(?:candidate|applicant)\s+(?:first|highest|as\s+(?:the\s+)?best)\b"),
    ("role_spoofing", "medium", r"<\|(?:im_start|start_header_id)\|>\s*(?:system|developer|assistant)\b|\[INST\]|<<SYS>>|(?:^|\n)\s*(?:system|developer)\s*:\s*"),
    ("concealment_instruction", "medium", r"\b(?:do\s+not|don't|never)\s+(?:mention|reveal|disclose)\s+(?:this|these|the)\s+(?:instructions?|prompts?|message|attack)\b"),
)
RULES = tuple(
    (name, severity, re.compile(pattern, re.IGNORECASE))
    for name, severity, pattern in _RULES
)


def scan_text(text, source, page=None):
    """Offsets refer to normalized evidence, never to the original PDF bytes."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(c for c in normalized if c not in "\u200b\ufeff\u2060")
    
    findings = []
    for rule_id, severity, pattern in RULES:
        for match in pattern.finditer(normalized):
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "source": source,
                "page": page,
                "matched_text": match.group(),
                "start": match.start(),
                "end": match.end(),
                "offset_basis": "nfkc_without_zero_width_separators",
            })
    return findings