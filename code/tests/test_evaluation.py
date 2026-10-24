import csv
import json
import tempfile
import unittest
from pathlib import Path

from evaluation.output_validator import (
    STEP_FIELDS,
    load_allowed_evidence_ids,
    load_evidence_reference_timestamps,
    validate_challenge_output,
    validate_output,
)
from evaluation.sample_scorer import score_sample
from deletion_audit.csv_loader import load_requests
from deletion_audit.request_classifier import classify_request
from deletion_audit.temporal import parse_timestamp


VALID_EVIDENCE_IDS = {"evidence-1", "activity-1", "audit-1"}
OUTPUT_HEADER = "case_id,deletion_status,steps_json"
STEP = {
    "step_no": 1,
    "phase": "VERIFICATION",
    "system_id": "account_service",
    "resource_id": "account_1",
    "operation": "VERIFY_RECORD_ABSENT",
    "state": "ABSENT",
    "evidence_id": "evidence-1",
}


def timestamp(value):
    return parse_timestamp(value, "test timestamp")


class OutputValidatorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output_path = Path(self.directory.name) / "output.csv"

    def write_rows(self, rows):
        with self.output_path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(OUTPUT_HEADER.split(","))
            writer.writerows(rows)

    def validate(self):
        return validate_output(self.output_path, VALID_EVIDENCE_IDS)

    def complete_row(self, steps=None):
        return ("case-1", "COMPLETE", json.dumps([STEP] if steps is None else steps))

    def test_accepts_valid_complete_row_and_realistic_reference_types(self):
        step = dict(STEP, evidence_id="activity-1")
        self.write_rows([self.complete_row([step])])
        report = self.validate()
        self.assertTrue(report.is_valid, report.issues)

    def test_rejects_complete_row_without_verification_steps(self):
        self.write_rows([("case-1", "COMPLETE", "[]")])
        self.assertTrue(
            any(
                "evidence-backed verification steps" in issue.message
                for issue in self.validate().issues
            )
        )

    def test_challenge_validator_requires_explicitly_unauthorized_request(self):
        dataset_dir = Path(__file__).resolve().parents[2] / "dataset"
        sample_requests = load_requests(
            dataset_dir / "sample_deletion_requests.csv"
        )
        authorized = next(
            request
            for request in sample_requests
            if classify_request(request.request_text).authorization.value
            == "AUTHORIZED"
        )
        self.write_rows([(authorized.case_id, "NOT_APPLICABLE", "[]")])
        report = validate_challenge_output(self.output_path, dataset_dir)
        self.assertTrue(
            any(
                "explicitly unauthorized" in issue.message
                for issue in report.issues
            )
        )

    def test_rejects_malformed_json(self):
        self.write_rows([("case-1", "COMPLETE", "[not-json")])
        self.assertTrue(
            any(
                issue.message.startswith("steps_json is not valid JSON")
                for issue in self.validate().issues
            )
        )

    def test_rejects_invalid_evidence_id(self):
        step = dict(STEP, evidence_id="not-in-participant-data")
        self.write_rows([self.complete_row([step])])
        self.assertTrue(
            any("valid participant evidence ID" in issue.message for issue in self.validate().issues)
        )

    def test_rejects_cited_evidence_after_request_cutoff(self):
        self.write_rows([self.complete_row()])
        report = validate_output(
            self.output_path,
            VALID_EVIDENCE_IDS,
            evidence_timestamps={"evidence-1": timestamp("2026-03-01T00:00:01Z")},
            case_audit_at={"case-1": timestamp("2026-03-01T00:00:00Z")},
        )
        self.assertTrue(
            any("created after audit_at" in issue.message for issue in report.issues)
        )

    def test_rejects_incorrect_status(self):
        self.write_rows([("case-1", "DONE", json.dumps([STEP]))])
        self.assertTrue(
            any("deletion_status" in issue.message for issue in self.validate().issues)
        )

    def test_rejects_missing_step_field(self):
        step = dict(STEP)
        del step["resource_id"]
        self.write_rows([self.complete_row([step])])
        self.assertTrue(
            any("missing fields resource_id" in issue.message for issue in self.validate().issues)
        )

    def test_rejects_extra_step_field(self):
        step = dict(STEP, explanation="not in the contract")
        self.write_rows([self.complete_row([step])])
        self.assertTrue(
            any("unexpected fields explanation" in issue.message for issue in self.validate().issues)
        )

    def test_rejects_duplicate_step_number_and_duplicate_logical_step(self):
        duplicate = dict(STEP, step_no=1)
        self.write_rows([self.complete_row([STEP, duplicate])])
        messages = [issue.message for issue in self.validate().issues]
        self.assertTrue(any("consecutive" in message for message in messages))
        self.assertTrue(any("duplicate logical step" in message for message in messages))

    def test_rejects_operation_and_state_not_allowed_by_contract(self):
        step = dict(STEP, operation="DELETE_RECORD", state="ABSENT")
        self.write_rows([self.complete_row([step])])
        self.assertTrue(
            any("not allowed in VERIFICATION" in issue.message for issue in self.validate().issues)
        )

    def test_rejects_wrong_state_for_allowed_operation(self):
        step = dict(STEP, state="PRESENT")
        self.write_rows([self.complete_row([step])])
        self.assertTrue(
            any("state does not match" in issue.message for issue in self.validate().issues)
        )

    def test_rejects_phase_operation_and_identifier_sort_order(self):
        later_resource = dict(STEP, resource_id="account_z")
        earlier_resource = dict(STEP, step_no=2, resource_id="account_a")
        self.write_rows([self.complete_row([later_resource, earlier_resource])])
        self.assertTrue(
            any("phase, operation, system_id, and resource_id ordering" in issue.message
                for issue in self.validate().issues)
        )

    def test_rejects_operation_table_order_violation(self):
        retained = dict(
            STEP,
            operation="VERIFY_RECORD_PRESENT",
            state="PRESENT",
            resource_id="security_1",
        )
        absent = dict(STEP, step_no=2, resource_id="account_1")
        self.write_rows([self.complete_row([retained, absent])])
        self.assertTrue(
            any(
                "phase, operation, system_id, and resource_id ordering" in issue.message
                for issue in self.validate().issues
            )
        )

    def test_not_applicable_requires_empty_steps(self):
        self.write_rows([("case-1", "NOT_APPLICABLE", json.dumps([STEP]))])
        self.assertTrue(
            any("empty steps array" in issue.message for issue in self.validate().issues)
        )

    def test_incomplete_requires_findings_remediation_and_verification(self):
        self.write_rows([("case-1", "INCOMPLETE", json.dumps([STEP]))])
        self.assertTrue(
            any("must include FINDING, REMEDIATION, and VERIFICATION" in issue.message
                for issue in self.validate().issues)
        )

    def test_incomplete_finding_needs_evidence_and_future_steps_must_not_cite(self):
        finding = {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "account_1",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "",
        }
        remediation = {
            "step_no": 2,
            "phase": "REMEDIATION",
            "system_id": "account_service",
            "resource_id": "account_1",
            "operation": "DELETE_RECORD",
            "state": "ABSENT",
            "evidence_id": "evidence-1",
        }
        verification = dict(STEP, step_no=3, evidence_id="")
        self.write_rows(
            [
                (
                    "case-1",
                    "INCOMPLETE",
                    json.dumps([finding, remediation, verification]),
                )
            ]
        )
        messages = [issue.message for issue in self.validate().issues]
        self.assertTrue(any("valid participant evidence ID" in message for message in messages))
        self.assertTrue(any("evidence_id must be empty" in message for message in messages))

    def test_requires_exact_output_header_and_sorted_unique_case_ids(self):
        self.output_path.write_text(
            "deletion_status,case_id,steps_json\nCOMPLETE,case-1,[]\n",
            encoding="utf-8",
        )
        self.assertFalse(self.validate().is_valid)

        self.write_rows(
            [
                ("case-b", "NOT_APPLICABLE", "[]"),
                ("case-a", "NOT_APPLICABLE", "[]"),
                ("case-a", "NOT_APPLICABLE", "[]"),
            ]
        )
        messages = [issue.message for issue in self.validate().issues]
        self.assertTrue(any("sorted by case_id" in message for message in messages))
        self.assertTrue(any("duplicate case_id" in message for message in messages))


class SampleScorerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.expected_path = self.root / "expected.csv"
        self.candidate_path = self.root / "candidate.csv"

    def write_prediction(self, path, status, steps):
        with path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(OUTPUT_HEADER.split(","))
            writer.writerow(("sample-case", status, json.dumps(steps)))

    def test_reports_status_field_step_and_sequence_accuracy_separately(self):
        expected_step = dict(STEP, evidence_id="evidence-1")
        self.write_prediction(self.expected_path, "COMPLETE", [expected_step])
        self.write_prediction(self.candidate_path, "INCOMPLETE", [expected_step])

        score = score_sample(
            self.candidate_path,
            self.expected_path,
            allowed_evidence_ids=VALID_EVIDENCE_IDS,
        )

        self.assertEqual(score.case_count, 1)
        self.assertEqual(score.status_accuracy, 0.0)
        self.assertEqual(score.field_accuracy, 1.0)
        self.assertEqual(score.step_accuracy, 1.0)
        self.assertEqual(score.sequence_accuracy, 1.0)

    def test_field_score_detects_wrong_evidence_even_if_other_fields_match(self):
        expected_step = dict(STEP, evidence_id="evidence-1")
        candidate_step = dict(STEP, evidence_id="audit-1")
        self.write_prediction(self.expected_path, "COMPLETE", [expected_step])
        self.write_prediction(self.candidate_path, "COMPLETE", [candidate_step])

        score = score_sample(
            self.candidate_path,
            self.expected_path,
            allowed_evidence_ids=VALID_EVIDENCE_IDS,
        )

        self.assertEqual(score.status_accuracy, 1.0)
        self.assertEqual(score.field_accuracy_by_name["evidence_id"], 0.0)
        self.assertEqual(score.field_accuracy, (len(STEP_FIELDS) - 1) / len(STEP_FIELDS))
        self.assertEqual(score.step_accuracy, 0.0)
        self.assertEqual(score.sequence_accuracy, 0.0)

    def test_missing_candidate_cases_count_as_failures_and_validation_errors(self):
        expected_step = dict(STEP, evidence_id="evidence-1")
        self.write_prediction(self.expected_path, "COMPLETE", [expected_step])
        with self.expected_path.open("a", encoding="utf-8", newline="") as output:
            csv.writer(output).writerow(
                ("sample-case-2", "COMPLETE", json.dumps([expected_step]))
            )
        self.write_prediction(self.candidate_path, "COMPLETE", [expected_step])

        score = score_sample(
            self.candidate_path,
            self.expected_path,
            allowed_evidence_ids=VALID_EVIDENCE_IDS,
        )

        self.assertEqual(score.case_count, 2)
        self.assertEqual(score.status_accuracy, 0.5)
        self.assertEqual(score.step_accuracy, 0.5)
        self.assertEqual(score.sequence_accuracy, 0.5)
        self.assertFalse(score.validation.is_valid)
        self.assertTrue(
            any("missing" in issue.message.casefold() for issue in score.validation.issues)
        )

    def test_public_sample_validates_against_participant_evidence_and_cutoffs(self):
        dataset_dir = Path(__file__).resolve().parents[2] / "dataset"
        requests = load_requests(dataset_dir / "sample_deletion_requests.csv")
        with (dataset_dir / "sample_output.csv").open(
            "r", encoding="utf-8-sig", newline=""
        ) as source:
            expected_rows = list(csv.DictReader(source))
        report = validate_output(
            dataset_dir / "sample_output.csv",
            load_allowed_evidence_ids(dataset_dir),
            expected_case_ids=[row["case_id"] for row in expected_rows],
            evidence_timestamps=load_evidence_reference_timestamps(dataset_dir),
            case_audit_at={request.case_id: request.audit_at for request in requests},
        )
        self.assertTrue(report.is_valid, report.issues)


if __name__ == "__main__":
    unittest.main()
