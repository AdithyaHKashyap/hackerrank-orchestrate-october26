import csv
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from deletion_audit.evidence_index import ExtractionStatus
from main import _case_diagnostic, _write_sample_diagnostics


class CaseDiagnosticTests(unittest.TestCase):
    def test_diagnostic_classifies_blockers_and_preserves_source_trace(self):
        record = SimpleNamespace(
            evidence_id="evidence-1",
            source_path="evidence/sample.json",
            extraction_method="json-object-path",
            fact=SimpleNamespace(
                provenance=SimpleNamespace(
                    record_locator="$.records[0]",
                    available_at=None,
                ),
                observed_at=None,
                system_id=None,
                resource_id=None,
                data_category=None,
                inspection_status=SimpleNamespace(value="INCONCLUSIVE"),
                observed_state=None,
            ),
        )
        observation = SimpleNamespace(
            record=record,
            temporal_disposition=SimpleNamespace(value="UNRESOLVED"),
            kind=SimpleNamespace(value="UNCLASSIFIED"),
        )
        request = SimpleNamespace(case_id="case-1")
        classification = SimpleNamespace(
            authorization=SimpleNamespace(value="UNCERTAIN")
        )
        grounded = SimpleNamespace(
            identity_status=SimpleNamespace(value="RESOLVED"),
            ledger=SimpleNamespace(
                groups=(),
                eligible=(),
                excluded=(),
                unresolved=(observation,),
            ),
            activity=(),
        )
        unknown_rule = SimpleNamespace(
            system_id=None,
            resource_id=None,
            data_category=None,
            rule_id=None,
            required_action=None,
            applicable=None,
            status=SimpleNamespace(value="UNKNOWN"),
            evidence_ids=(),
            unresolved_evidence_ids=("evidence-1",),
            excluded_evidence_ids=(),
            explanation="No supplied deletion rule can be tied to this scope.",
        )
        decision = SimpleNamespace(
            unresolved_reasons=(
                "Deletion authorization is unresolved.",
                "No evidence-backed verification is available.",
            )
        )
        report = SimpleNamespace(status=ExtractionStatus.PARTIAL)
        diagnostic = _case_diagnostic(
            request,
            classification,
            grounded,
            SimpleNamespace(assessments=(unknown_rule,)),
            SimpleNamespace(edges=()),
            decision,
            {"evidence-1": report},
        )

        self.assertEqual(
            diagnostic["blocker_types"],
            [
                "authorization",
                "missing_resource_evidence",
                "missing_verification",
                "unmapped_policy_category",
            ],
        )
        trace = json.loads(diagnostic["evidence_trace_json"])
        self.assertEqual(trace[0]["evidence_id"], "evidence-1")
        self.assertEqual(trace[0]["source_path"], "evidence/sample.json")
        self.assertEqual(trace[0]["extraction_status"], "PARTIAL")
        self.assertEqual(trace[0]["temporal_disposition"], "UNRESOLVED")

    def test_diagnostics_write_separately_as_csv_with_json_details(self):
        diagnostic = {
            "case_id": "case-2",
            "authorization_status": "AUTHORIZED",
            "identity_status": "RESOLVED",
            "blocker_types": ["unknown_state"],
            "blocker_details_json": json.dumps(["unknown"]),
            "assessments_json": "[]",
            "evidence_trace_json": "[]",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "diagnostics.csv"
            _write_sample_diagnostics(path, [diagnostic])
            with path.open(encoding="utf-8", newline="") as source:
                rows = list(csv.DictReader(source))

        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]["blocker_types"]), ["unknown_state"])
        self.assertEqual(json.loads(rows[0]["evidence_trace_json"]), [])


if __name__ == "__main__":
    unittest.main()
