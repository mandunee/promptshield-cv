import argparse
import getpass
import json
import sys
from pathlib import Path

from .pipeline import extract_and_scan
from .security.rules import scan_document
from .schemas import validate_evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract PDF evidence locally (no LLM or network calls)")
    commands = parser.add_subparsers(dest="command", required=True)
    extract = commands.add_parser("extract", help="Extract PDF evidence and heuristic signals")
    extract.add_argument("pdf", type=Path)
    scan = commands.add_parser("scan", help="Rescan a previously extracted JSON file")
    scan.add_argument("pdf", type=Path)
    for command in (extract, scan):
        command.add_argument("-o", "--output", type=Path)
        command.add_argument("--format", choices=["json", "text"], default="json")
        command.add_argument("--ask-password", action="store_true", help="Prompt without exposing password in shell history")
        command.add_argument("--max-pages", type=int, default=200)
        command.add_argument("--max-mb", type=int, default=50)
        command.add_argument("--force", action="store_true", help="Overwrite existing output")
    args = parser.parse_args(argv)
    if args.max_pages <= 0 or args.max_mb <= 0:
        parser.error("Limits must be positive")
        
    try:
        if args.output and args.output.resolve() == args.pdf.resolve():
            raise ValueError("Output cannot overwrite the input PDF")
        if args.command == "scan":
            if args.pdf.stat().st_size > args.max_mb * 1024 * 1024:
                raise ValueError("JSON exceeds input size limit")
            result = scan_document(validate_evidence(json.loads(args.pdf.read_text(encoding="utf-8"))))
        else:
            result = extract_and_scan(args.pdf, getpass.getpass("PDF password: ") if args.ask_password else None,
                             args.max_pages, args.max_mb * 1024 * 1024)
        output = (json.dumps(result, ensure_ascii=False, indent=2) if args.format == "json"
                  else "\n\f\n".join(p["raw_text"] for p in result["pages"]))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w" if args.force else "x", encoding="utf-8") as f:
                f.write(output + "\n")
        else:
            sys.stdout.write(output + "\n")
    except (OSError, ValueError, RuntimeError, EOFError, KeyError, TypeError, OverflowError) as exc:
        print(f"promptshield-cv: {exc}", file=sys.stderr)
        return 1
    return 0
