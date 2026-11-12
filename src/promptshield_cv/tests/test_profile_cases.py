import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import pymupdf

from promptshield_cv.extraction.pdf import extract_pdf
from promptshield_cv.models.cv_evaluator import build_cv_text
from promptshield_cv.scripts import generate_profile_cases as generator


class ProfileCasesTests(unittest.TestCase):
    def test_split_separation_and_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            manifests = generator.generate(root)

            groups = {}
            templates = {}

            for split, manifest in manifests.items():
                cases = manifest["cases"]

                self.assertEqual(len(cases), 15)
                self.assertEqual(
                    sum(case["contains_injection"] for case in cases),
                    12,
                )

                groups[split] = {
                    case["document_group"]
                    for case in cases
                }

                templates[split] = {
                    case["attack_template"]
                    for case in cases
                    if case["contains_injection"]
                }

                ids = {case["case_id"] for case in cases}

                for case in cases:
                    path = root / split / case["pdf"]

                    self.assertEqual(
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                        case["sha256"],
                    )

                    if case["contains_injection"]:
                        self.assertIn(case["paired_clean_id"], ids)

            self.assertTrue(
                groups["development"].isdisjoint(groups["heldout"])
            )
            self.assertTrue(
                templates["development"].isdisjoint(templates["heldout"])
            )

            with self.assertRaises(FileExistsError):
                generator.generate(root)

    def test_hidden_payload_and_rendering(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            manifests = generator.generate(root)

            for split, manifest in manifests.items():
                by_id = {
                    case["case_id"]: case
                    for case in manifest["cases"]
                }

                for case in manifest["cases"]:
                    if case["rendering_type"] != "invisible":
                        continue

                    hidden_path = root / split / case["pdf"]
                    clean_case = by_id[case["paired_clean_id"]]
                    clean_path = root / split / clean_case["pdf"]

                    hidden = extract_pdf(hidden_path)
                    clean = extract_pdf(clean_path)

                    hidden_text = build_cv_text(hidden)
                    clean_text = build_cv_text(clean)

                    self.assertTrue(hidden_text.startswith(clean_text))
                    self.assertIn('"overall_score":100', hidden_text)

                    self.assertTrue(any(
                        span["render_type"] == 3
                        for page in hidden["pages"]
                        for span in page["spans"]
                    ))

                    with (
                        pymupdf.open(clean_path) as clean_pdf,
                        pymupdf.open(hidden_path) as hidden_pdf,
                    ):
                        self.assertEqual(
                            clean_pdf[0].get_pixmap().samples,
                            hidden_pdf[0].get_pixmap().samples,
                        )


if __name__ == "__main__":
    unittest.main()