import argparse
import csv
import hashlib
import json
from pathlib import Path

from promptshield_cv.pipeline import extract_and_scan
from promptshield_cv.models.cv_evaluator import evaluate


def run(manifest_path, output_dir, repeats=1, model='qwen3:4b', host='http://localhost:11434',
        ocr=False, threshold=0.15, dry_run=False):
    manifest_path, output_dir = Path(manifest_path), Path(output_dir)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    root = manifest_path.parent.resolve()
    def resolve(name):
        path = (root / name).resolve()
        if not path.is_relative_to(root):
            raise ValueError('Manifest path escapes case directory')
        return path
    job = resolve(manifest['job_file']).read_text(encoding='utf-8')
    paths = []
    for case in manifest['cases']:
        path = resolve(case['pdf'])
        if hashlib.sha256(path.read_bytes()).hexdigest() != case['sha256']:
            raise ValueError(f'PDF hash mismatch: {path.name}')
        paths.append((case, path))
    if repeats < 1:
        raise ValueError('repeats must be positive')
    output_dir.mkdir(parents=True, exist_ok=False)
    config = {'model': model, 'host': host, 'repeats': repeats, 'ocr': ocr,
              'threshold': threshold, 'dry_run': dry_run,
              'gate_policy': 'block text-rule matches or OCR discrepancy; fail on OCR failure',
              'manifest': manifest}
    (output_dir/'config.json').write_text(json.dumps(config, indent=2), encoding='utf-8')
    rows = []
    for index, (case, path) in enumerate(paths):
        for repeat in range(repeats):
            for condition in ('baseline', 'rule_gated'):
                attempt = output_dir / f'{index:03d}_{repeat:03d}_{condition}'
                attempt.mkdir()
                row = {'case_id': case['case_id'], 'repeat': repeat, 'condition': condition,
                       'status': '', 'overall_score': '', 'recommendation': '', 'attack_success': ''}
                try:
                    document = extract_and_scan(path, ocr=ocr, ocr_threshold=threshold)
                    (attempt/'extraction.json').write_text(json.dumps(document, indent=2), encoding='utf-8')
                    security = document['security']
                    if condition == 'rule_gated' and security['ocr'].get('failed_page_count', 0):
                        row['status'] = 'ocr_failed'
                    elif condition == 'rule_gated' and (
                        security['text_finding_count'] > 0 or security['ocr'].get('flagged_page_count', 0) > 0
                    ):
                        row['status'] = 'blocked'
                    elif dry_run:
                        row['status'] = 'not_evaluated_dry_run'
                    else:
                        result = evaluate(document, job, model=model, host=host)
                        (attempt/'evaluation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
                        assessment = result['evaluation']
                        row.update(status='evaluated', overall_score=assessment['overall_score'],
                                   recommendation=assessment['recommendation'])
                        if case['contains_injection']:
                            row['attack_success'] = all(assessment.get(k) == v for k, v in manifest['attack_success_criteria'].items())
                except Exception as exc:
                    row['status'] = 'execution_error'
                    (attempt/'error.json').write_text(json.dumps({'error': str(exc)}), encoding='utf-8')
                (attempt/'outcome.json').write_text(json.dumps(row, indent=2), encoding='utf-8')
                rows.append(row)
    with (output_dir/'summary.csv').open('w', encoding='utf-8', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]) if rows else ['status'])
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--model', default='qwen3:4b')
    parser.add_argument('--host', default='http://localhost:11434')
    parser.add_argument('--ocr', action='store_true')
    parser.add_argument('--ocr-threshold', type=float, default=0.15)
    parser.add_argument('--dry-run', action='store_true', help='Extract and gate without calling Ollama')
    args = parser.parse_args()
    if args.repeats < 1 or not 0 <= args.ocr_threshold <= 1:
        parser.error('Invalid repeats or OCR threshold')
    try:
        rows = run(args.manifest, args.output_dir, args.repeats, args.model, args.host,
                   args.ocr, args.ocr_threshold, args.dry_run)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f'Experiment failed: {exc}\n')
    print(f'Saved {len(rows)} outcomes to {args.output_dir}/summary.csv')
    return 1 if any(r['status'] in ('execution_error', 'ocr_failed') for r in rows) else 0