import unittest

from promptshield_cv.models.cv_evaluator_v2 import (
    aggregate,
    parse_requirements,
    validate_findings,
)


JOB = """Senior Backend Engineer
- At least five years of backend experience
- Production Kubernetes experience
- Professional PostgreSQL experience
"""

CV = (
    "Six years of backend experience. "
    "No Kubernetes experience is listed. "
    "Used PostgreSQL in production."
)


def casey_findings():
    return {
        "requirements": [
            {
                "requirement_id": "req_1",
                "assessment": "met",
                "evidence_quote": "Six years of backend experience.",
                "reason": "Six years exceeds the required five years.",
            },
            {
                "requirement_id": "req_2",
                "assessment": "not_evidenced",
                "evidence_quote": "No Kubernetes experience is listed.",
                "reason": "Production Kubernetes experience is not evidenced.",
            },
            {
                "requirement_id": "req_3",
                "assessment": "met",
                "evidence_quote": "Used PostgreSQL in production.",
                "reason": "Professional PostgreSQL experience is evidenced.",
            },
        ],
    }


class EvaluatorV2Tests(unittest.TestCase):
    def test_casey_aggregation(self):
        requirements = parse_requirements(JOB)

        findings = validate_findings(
            casey_findings(),
            requirements,
            CV,
        )
        result = aggregate(requirements, findings)

        self.assertEqual(result["overall_score"], 67)
        self.assertEqual(
            result["recommendation"],
            "do_not_shortlist",
        )
        self.assertEqual(
            result["missing_requirements"],
            ["Production Kubernetes experience"],
        )

    def test_rejects_duplicate_requirement(self):
        value = casey_findings()
        value["requirements"][1]["requirement_id"] = "req_1"

        with self.assertRaises(ValueError):
            validate_findings(
                value,
                parse_requirements(JOB),
                CV,
            )

    def test_rejects_invented_quote(self):
        value = casey_findings()
        value["requirements"][0]["evidence_quote"] = (
            "Ten years of experience."
        )

        with self.assertRaises(ValueError):
            validate_findings(
                value,
                parse_requirements(JOB),
                CV,
            )

    def test_rejects_met_without_evidence(self):
        value = casey_findings()
        value["requirements"][0]["evidence_quote"] = ""

        with self.assertRaises(ValueError):
            validate_findings(
                value,
                parse_requirements(JOB),
                CV,
            )

    def test_uncertain_prevents_shortlisting(self):
        requirements = parse_requirements(JOB)
        value = casey_findings()
        value["requirements"][1]["assessment"] = "uncertain"

        findings = validate_findings(
            value,
            requirements,
            CV,
        )
        result = aggregate(requirements, findings)

        self.assertEqual(result["missing_requirements"], [])
        self.assertEqual(
            result["uncertain_requirements"],
            ["Production Kubernetes experience"],
        )
        self.assertEqual(
            result["recommendation"],
            "do_not_shortlist",
        )

    def test_all_met_shortlists(self):
        requirements = parse_requirements(JOB)
        value = casey_findings()

        for finding in value["requirements"]:
            finding["assessment"] = "met"

        # This tests aggregation, not whether the evidence supports the label.
        result = aggregate(
            requirements,
            value["requirements"],
        )

        self.assertEqual(result["overall_score"], 100)
        self.assertEqual(result["recommendation"], "shortlist")

    def test_job_requires_bullets(self):
        with self.assertRaises(ValueError):
            parse_requirements("Senior Backend Engineer")


if __name__ == "__main__":
    unittest.main()