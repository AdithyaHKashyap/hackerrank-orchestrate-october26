import tempfile
import unittest
from pathlib import Path

from deletion_audit.csv_loader import (
    load_dataset,
    load_identities,
    load_requests,
)
from deletion_audit.errors import DataValidationError
from deletion_audit.identity import IdentityResolver
from deletion_audit.models import (
    DeletionRequest,
    EvidenceFact,
    Identity,
    IdentityEvent,
    InspectionStatus,
    MatchSource,
    Provenance,
    ResolutionStatus,
)
from deletion_audit.temporal import (
    filter_evidence_for_request,
    parse_timestamp,
)


def timestamp(value):
    return parse_timestamp(value, "test timestamp")


def make_request(audit_at="2026-03-01T00:00:00Z"):
    return DeletionRequest(
        case_id="test",
        email="person@example.test",
        requested_at=timestamp("2026-01-01T00:00:00Z"),
        reported_status="COMPLETE",
        reported_at=timestamp("2026-01-02T00:00:00Z"),
        audit_at=timestamp(audit_at),
        request_text="Please delete my account.",
    )


def make_fact(
    available_at,
    inspection_status=InspectionStatus.CONFIRMED,
    observed_state="PRESENT",
    observed_at=None,
):
    return EvidenceFact(
        system_id="profile_service",
        resource_id="profile-1",
        data_category="USER_PROFILE",
        observed_state=observed_state,
        inspection_status=inspection_status,
        provenance=Provenance(
            source_type="file_id",
            source_id="evidence-test",
            source_path="evidence/test.json",
            available_at=available_at,
        ),
        observed_at=observed_at,
    )


class TimestampTests(unittest.TestCase):
    def test_normalizes_offsets_to_utc(self):
        self.assertEqual(
            timestamp("2026-03-01T05:30:00+05:30"),
            timestamp("2026-03-01T00:00:00Z"),
        )

    def test_cutoff_is_inclusive(self):
        request = make_request()
        fact = make_fact(request.audit_at)
        self.assertEqual(filter_evidence_for_request([fact], request), [fact])

    def test_evidence_captured_after_cutoff_is_excluded(self):
        request = make_request()
        fact = make_fact(timestamp("2026-03-01T00:00:01Z"))
        self.assertEqual(filter_evidence_for_request([fact], request), [])

    def test_post_cutoff_observation_is_excluded(self):
        request = make_request()
        fact = make_fact(
            available_at=timestamp("2026-02-28T23:00:00Z"),
            observed_at=timestamp("2026-03-01T00:00:01Z"),
        )
        self.assertEqual(filter_evidence_for_request([fact], request), [])

    def test_missing_availability_timestamp_is_not_eligible(self):
        request = make_request()
        fact = make_fact(None)
        self.assertEqual(filter_evidence_for_request([fact], request), [])

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(DataValidationError):
            timestamp("2026-03-01T00:00:00")


class IdentityResolutionTests(unittest.TestCase):
    def setUp(self):
        self.current = Identity(
            user_id="user-1",
            name="Example",
            email="current@example.test",
            phone="000",
            email_hash="hash",
            updated_at=timestamp("2026-02-01T00:00:00Z"),
        )
        self.old_email_event = IdentityEvent(
            audit_id="audit-1",
            user_id="user-1",
            event_time=timestamp("2026-02-01T00:00:00Z"),
            field_name="email",
            old_value="historical@example.test",
            new_value="current@example.test",
        )

    def test_resolves_historical_email_and_preserves_audit_provenance(self):
        resolver = IdentityResolver([self.current], [self.old_email_event])
        result = resolver.resolve(
            " HISTORICAL@example.test ", timestamp("2026-03-01T00:00:00Z")
        )
        self.assertEqual(result.status, ResolutionStatus.RESOLVED)
        self.assertEqual(result.user_id, "user-1")
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(result.matches[0].source, MatchSource.HISTORICAL)
        self.assertEqual(result.matches[0].provenance.source_type, "audit_id")
        self.assertEqual(result.matches[0].provenance.source_id, "audit-1")

    def test_does_not_use_identity_records_after_audit_cutoff(self):
        resolver = IdentityResolver([self.current], [self.old_email_event])
        result = resolver.resolve(
            "current@example.test", timestamp("2026-01-31T23:59:59Z")
        )
        self.assertEqual(result.status, ResolutionStatus.UNMATCHED)

    def test_reports_ambiguous_email_without_choosing_a_user(self):
        another_user = Identity(
            user_id="user-2",
            name="Another",
            email="historical@example.test",
            phone="111",
            email_hash="hash-2",
            updated_at=timestamp("2026-02-01T00:00:00Z"),
        )
        resolver = IdentityResolver(
            [self.current, another_user], [self.old_email_event]
        )
        result = resolver.resolve(
            "historical@example.test", timestamp("2026-03-01T00:00:00Z")
        )
        self.assertEqual(result.status, ResolutionStatus.AMBIGUOUS)
        self.assertIsNone(result.user_id)
        self.assertEqual(
            {match.user_id for match in result.matches}, {"user-1", "user-2"}
        )

    def test_unmatched_email_does_not_trigger_heuristic_identity_match(self):
        resolver = IdentityResolver([self.current], [self.old_email_event])
        result = resolver.resolve(
            "unrelated@example.test", timestamp("2026-03-01T00:00:00Z")
        )
        self.assertEqual(result.status, ResolutionStatus.UNMATCHED)
        self.assertEqual(result.matches, tuple())


class EvidenceInspectionTests(unittest.TestCase):
    def test_failed_and_inconclusive_inspections_are_not_confirmations(self):
        failed = make_fact(
            timestamp("2026-02-28T00:00:00Z"),
            InspectionStatus.FAILED,
            observed_state="ABSENT",
        )
        inconclusive = make_fact(
            timestamp("2026-02-28T00:00:00Z"),
            InspectionStatus.INCONCLUSIVE,
            observed_state="ABSENT",
        )
        self.assertFalse(failed.confirms_presence)
        self.assertFalse(failed.confirms_absence)
        self.assertFalse(inconclusive.confirms_presence)
        self.assertFalse(inconclusive.confirms_absence)

    def test_absence_requires_an_explicit_absent_observation(self):
        absent = make_fact(
            timestamp("2026-02-28T00:00:00Z"), observed_state="ABSENT"
        )
        no_facts = []
        self.assertFalse(any(fact.confirms_absence for fact in no_facts))
        self.assertTrue(absent.confirms_absence)

    def test_confirmed_inspection_requires_an_observed_state(self):
        with self.assertRaises(ValueError):
            EvidenceFact(
                system_id="profile_service",
                resource_id="profile-1",
                data_category="USER_PROFILE",
                observed_state=None,
                inspection_status=InspectionStatus.CONFIRMED,
                provenance=Provenance(
                    source_type="file_id",
                    source_id="evidence-test",
                    available_at=timestamp("2026-02-28T00:00:00Z"),
                ),
            )


class CsvValidationTests(unittest.TestCase):
    def test_loads_all_dataset_inputs_against_actual_schemas(self):
        dataset_dir = Path(__file__).resolve().parents[2] / "dataset"
        inputs = load_dataset(dataset_dir)
        self.assertTrue(inputs.requests)
        self.assertTrue(inputs.identities)
        self.assertTrue(inputs.identity_events)
        self.assertTrue(inputs.system_activity)
        self.assertTrue(inputs.deletion_rules)
        self.assertTrue(inputs.evidence_files)

    def test_rejects_header_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requests.csv"
            path.write_text("case_id,email\ncase-1,user@example.test\n", encoding="utf-8")
            with self.assertRaises(DataValidationError):
                load_requests(path)

    def test_rejects_invalid_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identities.csv"
            path.write_text(
                "user_id,name,email,phone,email_hash,updated_at\n"
                "user-1,Name,user@example.test,000,hash,not-a-time\n",
                encoding="utf-8",
            )
            with self.assertRaises(DataValidationError):
                load_identities(path)

    def test_rejects_row_with_missing_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identities.csv"
            path.write_text(
                "user_id,name,email,phone,email_hash,updated_at\n"
                "user-1,Name,user@example.test,000,hash\n",
                encoding="utf-8",
            )
            with self.assertRaises(DataValidationError):
                load_identities(path)

    def test_rejects_duplicate_identity_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identities.csv"
            path.write_text(
                "user_id,name,email,phone,email_hash,updated_at\n"
                "user-1,Name,user@example.test,000,hash,2026-01-01T00:00:00Z\n"
                "user-1,Name,user2@example.test,111,hash2,2026-01-02T00:00:00Z\n",
                encoding="utf-8",
            )
            with self.assertRaises(DataValidationError):
                load_identities(path)


if __name__ == "__main__":
    unittest.main()
