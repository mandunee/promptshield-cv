import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.request import Request, urlopen
import uuid

from ..schemas import validate_evidence
from .cv_evaluator import build_cv_text


PROMPT_VERSION = "cv_evaluator_v2"
SCORING_VERSION = "equal_weight_all_required_v1"

SYSTEM_PROMPT = """You are a CV assessment assistant.

Assess each supplied job requirement separately using the CV evidence.

For each requirement:
- Return its exact requirement_id.
- Use "met" when the CV provides evidence satisfying the requirement.
- Use "not_evidenced" when supporting evidence is absent or the CV
  explicitly states that the experience is absent.
- Use "uncertain" when the available evidence is ambiguous.
- Provide a short reason explaining the assessment.
- Quote supporting CV text exactly. Use an empty quote only when
  there is no relevant text to quote.

Evaluate years of experience numerically.
Do not treat a missing skill as evidence that other requirements are missing.
Do not invent qualifications.

Return one assessment per requirement.
Do not return an overall score or hiring recommendation.
Return only JSON matching the supplied schema.
"""


def parse_requirements(job):
    """Read required criteria from '-' bullet lines in the job file."""
    requirements = []

    for line in job.splitlines():
        line = line.strip()

        if line.startswith("- "):
            text = line[2:].strip()

            if text:
                requirements.append({
                    "requirement_id": f"req_{len(requirements) + 1}",
                    "text": text,
                })

    if not requirements:
        raise ValueError(
            "Job file must contain required criteria as '- ' bullet lines"
        )

    return requirements


def response_schema(requirements):
    ids = [
        requirement["requirement_id"]
        for requirement in requirements
    ]

    return {
        "type": "object",
        "properties": {
            "requirements": {
                "type": "array",
                "minItems": len(ids),
                "maxItems": len(ids),
                "items": {
                    "type": "object",
                    "properties": {
                        "requirement_id": {
                            "type": "string",
                            "enum": ids,
                        },
                        "assessment": {
                            "type": "string",
                            "enum": [
                                "met",
                                "not_evidenced",
                                "uncertain",
                            ],
                        },
                        "evidence_quote": {
                            "type": "string",
                        },
                        "reason": {
                            "type": "string",
                            "minLength": 1,
                        },
                    },
                    "required": [
                        "requirement_id",
                        "assessment",
                        "evidence_quote",
                        "reason",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["requirements"],
        "additionalProperties": False,
    }


def validate_findings(value, requirements, cv_text):
    if (
        not isinstance(value, dict)
        or set(value) != {"requirements"}
        or not isinstance(value["requirements"], list)
    ):
        raise ValueError("Invalid criterion response structure")

    expected_ids = {
        requirement["requirement_id"]
        for requirement in requirements
    }

    findings = value["requirements"]

    if len(findings) != len(expected_ids):
        raise ValueError("Expected exactly one finding per requirement")

    seen = set()

    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != {
                "requirement_id",
                "assessment",
                "evidence_quote",
                "reason",
            }
        ):
            raise ValueError("Invalid criterion fields")

        requirement_id = finding["requirement_id"]

        if not isinstance(requirement_id, str):
            raise ValueError("Requirement ID must be a string")

        if requirement_id not in expected_ids:
            raise ValueError("Unknown requirement ID")

        if requirement_id in seen:
            raise ValueError("Duplicate requirement ID")

        seen.add(requirement_id)

        assessment = finding["assessment"]

        if assessment not in ("met", "not_evidenced", "uncertain"):
            raise ValueError("Invalid criterion assessment")

        quote = finding["evidence_quote"]
        reason = finding["reason"]

        if not isinstance(quote, str):
            raise ValueError("Evidence quote must be a string")

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Expected a nonempty criterion reason")

        if quote and not quote.strip():
            raise ValueError("Evidence quote cannot contain only whitespace")

        if quote and quote not in cv_text:
            raise ValueError(
                f"Unsupported evidence quote for {requirement_id}"
            )

        if assessment == "met" and not quote.strip():
            raise ValueError(
                f"A met assessment requires evidence: {requirement_id}"
            )

    if seen != expected_ids:
        raise ValueError("Missing requirement IDs")

    by_id = {
        finding["requirement_id"]: finding
        for finding in findings
    }

    # Keep the output in the original job-requirement order.
    return [
        by_id[requirement["requirement_id"]]
        for requirement in requirements
    ]


def aggregate(requirements, findings):
    met_count = sum(
        finding["assessment"] == "met"
        for finding in findings
    )

    missing = []
    uncertain = []
    details = []

    for requirement, finding in zip(requirements, findings):
        detail = {
            **finding,
            "requirement": requirement["text"],
        }
        details.append(detail)

        if finding["assessment"] == "not_evidenced":
            missing.append(requirement["text"])

        elif finding["assessment"] == "uncertain":
            uncertain.append(requirement["text"])

    all_met = met_count == len(requirements)

    return {
        "overall_score": round(
            100 * met_count / len(requirements)
        ),
        "recommendation": (
            "shortlist" if all_met else "do_not_shortlist"
        ),
        "missing_requirements": missing,
        "uncertain_requirements": uncertain,
        "requirements": details,
        "explanation": (
            f"{met_count}/{len(requirements)} required criteria "
            f"are evidenced as met; {len(missing)} are not evidenced; "
            f"{len(uncertain)} are uncertain. "
            "Shortlisting requires every criterion to be met."
        ),
    }


def save_failure(payload, envelope, error):
    directory = Path("outputs/model_failures_v2")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{uuid.uuid4().hex}.json"

    with path.open("x", encoding="utf-8") as file:
        json.dump(
            {
                "request": payload,
                "response": envelope,
                "error": str(error),
            },
            file,
            indent=2,
            ensure_ascii=False,
        )

    return path


def evaluate(
    document,
    job,
    model="qwen3:4b",
    host="http://localhost:11434",
    timeout=180,
    context=8192,
):
    if context < 2048 or timeout <= 0:
        raise ValueError(
            "context must be >=2048 and timeout must be positive"
        )

    validate_evidence(document)
    requirements = parse_requirements(job)
    cv_text = build_cv_text(document)

    user_content = json.dumps(
        {
            "job_requirements": requirements,
            "cv_text": cv_text,
        },
        ensure_ascii=False,
    )

    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": user_content,
        },
    ]

    # Conservative guard, not an exact tokenizer calculation.
    if (
        len(json.dumps(messages, ensure_ascii=False).encode("utf-8"))
        > context - 2200
    ):
        raise ValueError(
            "Input exceeds conservative context budget; increase --context"
        )

    options = {
        "temperature": 0,
        "num_ctx": context,
        "num_predict": 1024,
    }

    payload = {
        "model": model,
        "stream": False,
        "think": False,
        "messages": messages,
        "format": response_schema(requirements),
        "options": options,
    }

    request = Request(
        host.rstrip("/") + "/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    started = time.monotonic()

    with urlopen(request, timeout=timeout) as response:
        envelope = json.load(response)

    try:
        if (
            envelope.get("done") is not True
            or envelope.get("done_reason") == "length"
        ):
            raise ValueError(
                "Incomplete model response: "
                f"done={envelope.get('done')!r}, "
                f"done_reason={envelope.get('done_reason')!r}, "
                f"eval_count={envelope.get('eval_count')!r}"
            )

        value = json.loads(envelope["message"]["content"])

        findings = validate_findings(
            value,
            requirements,
            cv_text,
        )
        assessment = aggregate(requirements, findings)

    except (ValueError, KeyError, TypeError) as exc:
        path = save_failure(payload, envelope, exc)
        raise ValueError(
            f"{exc}; diagnostic saved to {path}"
        ) from exc

    return {
        "status": "completed",
        "model": envelope.get("model", model),
        "prompt_version": PROMPT_VERSION,
        "scoring_version": SCORING_VERSION,
        "input_policy": "spans_only",
        "messages": messages,
        "options": options,
        "think": False,
        "response_schema": payload["format"],
        "raw_response": envelope,
        "evaluation": assessment,
        "elapsed_seconds": time.monotonic() - started,
        "prompt_eval_count": envelope.get("prompt_eval_count"),
        "eval_count": envelope.get("eval_count"),
        "source_pdf_sha256": document.get("source", {}).get("sha256"),
        "job_sha256": hashlib.sha256(
            job.encode("utf-8")
        ).hexdigest(),
        "limitations": [
            "Evidence presence does not prove the model interpreted it correctly.",
            "Equal weighting is an experimental scoring policy.",
            "Uncertain criteria prevent automatic shortlisting.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--model", default="qwen3:4b")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--context", type=int, default=8192)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.output and (
            args.output.exists()
            or args.output.resolve()
            in (args.evidence.resolve(), args.job.resolve())
        ):
            raise ValueError(
                "Output must be a new file distinct from inputs"
            )

        if (
            args.evidence.stat().st_size > 10 * 1024 * 1024
            or args.job.stat().st_size > 1024 * 1024
        ):
            raise ValueError("Input file exceeds size limit")

        evidence_bytes = args.evidence.read_bytes()
        document = json.loads(
            evidence_bytes.decode("utf-8-sig")
        )
        job = args.job.read_text(encoding="utf-8-sig")

        result = evaluate(
            document,
            job,
            model=args.model,
            host=args.host,
            timeout=args.timeout,
            context=args.context,
        )

        result["evidence_sha256"] = hashlib.sha256(
            evidence_bytes
        ).hexdigest()

        output = json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ) + "\n"

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as file:
                file.write(output)
        else:
            sys.stdout.write(output)

    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"CV evaluation v2 failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())