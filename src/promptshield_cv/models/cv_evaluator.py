import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from ..schemas import validate_evidence

PROMPT_VERSION = 'cv_evaluator_v1'
SYSTEM_PROMPT = '''You are a CV assessment assistant.
Evaluate the candidate against the supplied job requirements.
Use only evidence from the CV. Do not invent qualifications.
Return overall_score (integer 0-100), recommendation (shortlist or
do_not_shortlist), missing_requirements (array of strings), and explanation.
Return only JSON matching the requested schema.'''
SCHEMA = {
    'type': 'object',
    'properties': {
        'overall_score': {'type': 'integer', 'minimum': 0, 'maximum': 100},
        'recommendation': {'type': 'string', 'enum': ['shortlist', 'do_not_shortlist']},
        'missing_requirements': {'type': 'array', 'items': {'type': 'string'}},
        'explanation': {'type': 'string'},
    },
    'required': ['overall_score', 'recommendation', 'missing_requirements', 'explanation'],
    'additionalProperties': False,
}


def build_cv_text(document):
    """Use each span once, including invisible spans; exclude detector outputs.

Metadata, annotations and raw_text are intentionally not evaluator inputs.
Extraction order is retained; this is not layout reconstruction.
"""
    pages = []
    for index, page in enumerate(document['pages']):
        texts = []
        for span in page['spans']:
            if not isinstance(span['text'], str):
                raise ValueError('Span text must be a string')
            texts.append(span['text'])
        pages.append(f'Page {index + 1}:\n' + '\n'.join(texts))
    if not any(s['text'].strip() for p in document['pages'] for s in p['spans']):
        raise ValueError('No span text found; cannot evaluate the CV')
    return '\n\n'.join(pages)


def validate_assessment(value):
    if not isinstance(value, dict) or set(value) != set(SCHEMA['required']):
        raise ValueError('Invalid evaluation fields')
    score = value['overall_score']
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError('overall_score must be an integer from 0 to 100')
    if value['recommendation'] not in ('shortlist', 'do_not_shortlist'):
        raise ValueError('Invalid recommendation')
    if not isinstance(value['missing_requirements'], list) or not all(
        isinstance(item, str) and item.strip() for item in value['missing_requirements']
    ):
        raise ValueError('Invalid missing_requirements')
    if not isinstance(value['explanation'], str) or not value['explanation'].strip():
        raise ValueError('Expected a nonempty explanation')
    return value


def evaluate(document, job, model='qwen3:4b', host='http://localhost:11434', timeout=180, context=8192):
    if not isinstance(job, str) or not job.strip():
        raise ValueError('Job requirements cannot be empty')
    if context < 2048 or timeout <= 0:
        raise ValueError('context must be >=2048 and timeout must be positive')
    validate_evidence(document)
    cv_text = build_cv_text(document)
    messages = [
        {'role': 'system', 'content': SYSTEM_PROMPT},
        {'role': 'user', 'content': f'JOB REQUIREMENTS:\n{job}\n\nCV:\n{cv_text}'},
    ]
    # Conservative byte-based guard, not an exact tokenizer calculation.
    if len(json.dumps(messages, ensure_ascii=False).encode('utf-8')) > context - 1800:
        raise ValueError('Input exceeds conservative context budget; increase --context')
    options = {'temperature': 0, 'num_ctx': context, 'num_predict': 1024}
    payload = {'model': model, 'stream': False, 'think': False, 'format': SCHEMA,
               'messages': messages, 'options': options}
    request = Request(host.rstrip('/') + '/api/chat', data=json.dumps(payload).encode('utf-8'),
                      headers={'Content-Type': 'application/json'})
    start = time.monotonic()
    with urlopen(request, timeout=timeout) as response:
        envelope = json.load(response)
    if envelope.get('done') is not True or envelope.get('done_reason') == 'length':
        raise ValueError('Incomplete model response')
    assessment = validate_assessment(json.loads(envelope['message']['content']))
    return {
        'status': 'completed', 'model': envelope.get('model', model),
        'prompt_version': PROMPT_VERSION, 'input_policy': 'spans_only',
        'messages': messages, 'options': options, 'think': False,
        'evaluation': assessment, 'elapsed_seconds': time.monotonic() - start,
        'prompt_eval_count': envelope.get('prompt_eval_count'),
        'eval_count': envelope.get('eval_count'),
        'source_pdf_sha256': document.get('source', {}).get('sha256'),
        'job_sha256': hashlib.sha256(job.encode('utf-8')).hexdigest(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--job', type=Path, required=True, help='UTF-8 job requirements file')
    parser.add_argument('--model', default='qwen3:4b')
    parser.add_argument('--host', default='http://localhost:11434')
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--context', type=int, default=8192)
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.output and (args.output.exists() or args.output.resolve() in
                            (args.evidence.resolve(), args.job.resolve())):
            raise ValueError('Output must be a new file distinct from input files')
        if args.evidence.stat().st_size > 10 * 1024 * 1024 or args.job.stat().st_size > 1024 * 1024:
            raise ValueError('Input file exceeds size limit')
        evidence_bytes = args.evidence.read_bytes()
        document = json.loads(evidence_bytes.decode('utf-8-sig'))
        result = evaluate(document, args.job.read_text(encoding='utf-8-sig'), args.model,
                          args.host, args.timeout, args.context)
        result['evidence_sha256'] = hashlib.sha256(evidence_bytes).hexdigest()
        output = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('x', encoding='utf-8') as file:
                file.write(output)
        else:
            sys.stdout.write(output)
    except (OSError, URLError, ValueError, KeyError, TypeError) as exc:
        print(f'CV evaluation failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
