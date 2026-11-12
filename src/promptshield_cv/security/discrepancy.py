from copy import deepcopy
import re
import unicodedata


def words(text):
    text = unicodedata.normalize('NFKC', text).casefold()
    return {word for word in re.findall(r'[a-z0-9]+', text) if len(word) > 1}


def scan_ocr_discrepancy(document, outcomes, threshold=0.15):
    if not 0 <= threshold <= 1:
        raise ValueError('OCR threshold must be between 0 and 1')
    result = deepcopy(document)
    flagged = failures = 0
    for page in result['pages']:
        outcome = outcomes.get(page['number'], {'status': 'skipped', 'reason': 'No OCR result'})
        comparison = dict(outcome)
        if outcome['status'] == 'completed':
            raw = words('\n'.join(span['text'] for span in page['spans']))
            visible = words(outcome['text'])
            missing = raw - visible
            ratio = len(missing) / len(raw) if raw else 0
            comparison.update(missing_words=sorted(missing), missing_unique_word_ratio=ratio,
                              threshold=threshold, flagged=ratio > threshold)
            flagged += ratio > threshold
        elif outcome['status'] == 'failed':
            failures += 1
        page['ocr'] = comparison
    result['security']['ocr'] = {
        'method': 'unique_word_coverage_v1', 'threshold': threshold,
        'flagged_page_count': flagged, 'failed_page_count': failures,
        'status': 'incomplete' if failures else 'completed',
        'limitations': ['Ignores word order, frequency and single-letter words.',
                        'OCR omissions are not proof of hidden instructions.'],
    }
    return result