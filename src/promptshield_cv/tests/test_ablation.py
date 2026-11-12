import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from promptshield_cv.scripts import (
    generate_experiment_cases as generator,
)
from promptshield_cv.scripts import run_experiment as runner


class AblationTests(unittest.TestCase):
    def test_gate_independence_and_errors(self):
        security = {
            "text_finding_count": 1,
            "ocr": {
                "status": "completed",
                "flagged_page_count": 0,
            },
        }

        decisions = [
            runner.gate(security, condition)
            for condition in runner.CONDITIONS
        ]

        self.assertEqual(
            decisions,
            ["passed", "blocked", "passed", "blocked"],
        )

        security["ocr"] = {
            "status": "incomplete",
            "failed_page_count": 1,
        }

        self.assertEqual(
            runner.gate(security, "ocr_only"),
            "ocr_failed",
        )

        # A text match conclusively blocks without requiring OCR.
        self.assertEqual(
            runner.gate(security, "combined"),
            "blocked",
        )

        security["text_finding_count"] = 0

        self.assertEqual(
            runner.gate(security, "combined"),
            "ocr_failed",
        )

    def test_suite_and_cached_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            manifest = generator.generate_development_suite(
                root / "cases"
            )

            self.assertEqual(len(manifest["cases"]), 18)
            self.assertEqual(
                sum(
                    case["contains_injection"]
                    for case in manifest["cases"]
                ),
                12,
            )

            document = {
                "security": {
                    "text_finding_count": 0,
                    "ocr": {
                        "status": "completed",
                        "flagged_page_count": 0,
                        "failed_page_count": 0,
                    },
                },
            }

            with patch.object(
                runner,
                "extract_and_scan",
                return_value=document,
            ) as extract:
                with patch.object(runner, "evaluate") as evaluate:
                    rows = runner.run(
                        root / "cases/manifest.json",
                        root / "run",
                        repeats=2,
                        ocr=True,
                        dry_run=True,
                    )

                    self.assertEqual(extract.call_count, 18)
                    evaluate.assert_not_called()

            # 18 documents × 2 repetitions × 4 conditions.
            self.assertEqual(len(rows), 144)

            metrics = json.loads(
                (root / "run/metrics.json").read_text(
                    encoding="utf-8"
                )
            )
            baseline = metrics["conditions"][0]

            self.assertEqual(
                baseline["injection_documents"],
                12,
            )
            self.assertIsNone(
                baseline["success_rate_among_evaluated"]
            )
            self.assertEqual(
                baseline["incomplete_attempts"],
                24,
            )


if __name__ == "__main__":
    unittest.main()