import json
import unittest

from deletion_audit.evidence_index import (
    EvidenceIndex,
    ExtractionStatus,
    FileExtractionReport,
    IndexedEvidence,
)
from deletion_audit.identity_links import (
    IdentityLink,
    IdentityLinkConfidence,
    IdentityLinkSource,
    IdentifierType,
)
from deletion_audit.evidence_reconciliation import (
    CoverageStatus,
    ExpectedResourceScope,
    InspectionSourceStatus,
    ObservationKind,
    TemporalDisposition,
    _record_matches_subject,
    reconcile_request,
)
from deletion_audit.models import (
    DeletionRequest,
    EvidenceFact,
    InspectionStatus,
    Provenance,
)
from deletion_audit.temporal import parse_timestamp


def timestamp(value):
    return parse_timestamp(value, "test timestamp")


def request(audit_at="2026-04-01T00:00:00Z"):
    return DeletionRequest(
        case_id="case-test",
        email="person@example.test",
        requested_at=timestamp("2026-03-01T00:00:00Z"),
        reported_status="COMPLETE",
        reported_at=timestamp("2026-03-10T00:00:00Z"),
        audit_at=timestamp(audit_at),
        request_text="Delete my account",
    )


def record(
    evidence_id,
    attributes,
    observed_at="2026-03-15T00:00:00Z",
    available_at="2026-03-16T00:00:00Z",
    observed_state=None,
    inspection_status=InspectionStatus.INCONCLUSIVE,
    extraction_method="json-object-path",
    locator="$.records[0]",
    metadata=None,
    source_path=None,
):
    source_path = source_path or "evidence/{}.json".format(evidence_id)
    return IndexedEvidence(
        evidence_id=evidence_id,
        source_path=source_path,
        source_origin="test",
        extraction_method=extraction_method,
        fact=EvidenceFact(
            system_id=attributes.get("system_id"),
            resource_id=attributes.get("resource_id"),
            data_category=attributes.get("data_category"),
            observed_state=observed_state,
            inspection_status=inspection_status,
            provenance=Provenance(
                source_type="EVIDENCE_FILE",
                source_id=evidence_id,
                source_path=source_path,
                record_locator=locator,
                available_at=timestamp(available_at) if available_at else None,
            ),
            subject_user_id=attributes.get("user_id"),
            observed_at=timestamp(observed_at) if observed_at else None,
        ),
        attributes_json=json.dumps(attributes, sort_keys=True),
        metadata_json=json.dumps(metadata or {}, sort_keys=True),
        identifiers=tuple(),
        timestamp_fields=tuple(),
    )


def extraction_report(
    evidence_id, status=ExtractionStatus.SUCCESS, captured_at="2026-03-16T00:00:00Z"
):
    return FileExtractionReport(
        evidence_id=evidence_id,
        source_path="evidence/{}.json".format(evidence_id),
        source_origin="test",
        captured_at=captured_at,
        status=status,
        extraction_method="fixture",
        record_count=1 if status != ExtractionStatus.UNSUPPORTED else 0,
        error="test extraction failure"
        if status in {ExtractionStatus.UNREADABLE, ExtractionStatus.UNSUPPORTED}
        else None,
    )


def build_index(*records, report_statuses=None):
    statuses = report_statuses or {}
    reports = [
        extraction_report(
            record.evidence_id,
            statuses.get(record.evidence_id, ExtractionStatus.SUCCESS),
        )
        for record in records
    ]
    return EvidenceIndex(records, reports)


class EvidenceReconciliationTests(unittest.TestCase):
    def test_subject_index_is_a_complete_candidate_superset_of_exact_matching(self):
        email_hash = "a" * 64
        records = (
            record("stable-id", {"user_id": "user-1"}),
            record("customer-ref", {"customer_reference": "user-1"}),
            record("typed-email", {"requester_email": "PERSON@example.test"}),
            record("typed-phone", {"phone": "+1 (555) 123-4567"}),
            record("typed-hash", {"email_hash": email_hash}),
            record(
                "reference-email",
                {"subject_key": "Person@Example.Test"},
            ),
            record(
                "complete-lookup",
                {"lookup_key": "person@example.test"},
                metadata={"readback_export_complete": True},
            ),
            record("incomplete-lookup", {"lookup_key": "person@example.test"}),
            record("unrelated-email", {"email": "other@example.test"}),
        )
        index = EvidenceIndex(records, ())
        identifiers = {
            "email": {"person@example.test"},
            "phone": {"+15551234567"},
            "email_hash": {email_hash},
        }

        candidates = index.for_subject("user-1", identifiers)
        actual_matches = {
            id(item)
            for item in candidates
            if _record_matches_subject(item, "user-1", identifiers)
        }
        expected_matches = {
            id(item)
            for item in index.records
            if _record_matches_subject(item, "user-1", identifiers)
        }

        self.assertEqual(actual_matches, expected_matches)

    def test_cutoff_boundary_and_temporal_uncertainty_are_preserved(self):
        exact = record(
            "exact",
            {"user_id": "user-1", "system_id": "profile", "resource_id": "r1"},
            observed_at="2026-04-01T00:00:00Z",
            available_at="2026-04-01T00:00:00Z",
        )
        later = record(
            "later",
            {"user_id": "user-1", "system_id": "profile", "resource_id": "r2"},
            observed_at="2026-04-01T00:00:00.000001Z",
            available_at="2026-04-01T00:00:00Z",
        )
        unresolved = record(
            "unresolved",
            {"user_id": "user-1", "system_id": "profile", "resource_id": "r3"},
            observed_at=None,
            available_at="2026-04-01T00:00:00Z",
            extraction_method="tesseract-ocr",
        )

        ledger = reconcile_request(
            request(),
            build_index(exact, later, unresolved),
            subject_user_id="user-1",
        )

        self.assertEqual([item.evidence_id for item in ledger.eligible], ["exact"])
        self.assertEqual([item.evidence_id for item in ledger.excluded], ["later"])
        self.assertEqual(
            [item.evidence_id for item in ledger.unresolved], ["unresolved"]
        )
        self.assertEqual(
            ledger.unresolved[0].temporal_disposition,
            TemporalDisposition.UNRESOLVED,
        )
        self.assertEqual(
            ledger.unresolved[0].kind, ObservationKind.UNCLASSIFIED
        )

    def test_conflicting_direct_observations_are_preserved(self):
        present = record(
            "present",
            {
                "user_id": "user-1",
                "system_id": "profile",
                "resource_id": "r1",
                "data_category": "USER_PROFILE",
            },
            observed_state="PRESENT",
            inspection_status=InspectionStatus.CONFIRMED,
        )
        absent = record(
            "absent",
            {
                "user_id": "user-1",
                "system_id": "profile",
                "resource_id": "r1",
                "data_category": "USER_PROFILE",
            },
            observed_state="ABSENT",
            inspection_status=InspectionStatus.CONFIRMED,
        )

        ledger = reconcile_request(
            request(),
            build_index(present, absent),
            subject_user_id="user-1",
        )

        self.assertEqual(len(ledger.groups), 1)
        self.assertTrue(ledger.groups[0].contradictory)
        self.assertEqual(ledger.groups[0].status, CoverageStatus.INCONCLUSIVE)
        self.assertEqual(
            {item.evidence_id for item in ledger.groups[0].observations},
            {"present", "absent"},
        )
        self.assertEqual(
            {item.kind for item in ledger.groups[0].observations},
            {ObservationKind.DIRECT_RESOURCE_STATE},
        )

    def test_groups_require_explicit_system_resource_and_category_keys(self):
        first = record(
            "profile",
            {
                "user_id": "user-1",
                "system_id": "store",
                "resource_id": "r1",
                "data_category": "PROFILE",
            },
        )
        second = record(
            "order",
            {
                "user_id": "user-1",
                "system_id": "store",
                "resource_id": "r1",
                "data_category": "ORDER",
            },
        )
        missing_system = record(
            "unscoped",
            {
                "user_id": "user-1",
                "resource_id": "r1",
                "data_category": "PROFILE",
            },
        )

        ledger = reconcile_request(
            request(),
            build_index(first, second, missing_system),
            subject_user_id="user-1",
        )

        self.assertEqual(len(ledger.groups), 3)
        self.assertEqual(
            {
                (group.system_id, group.resource_id, group.data_category)
                for group in ledger.groups
            },
            {
                ("store", "r1", "PROFILE"),
                ("store", "r1", "ORDER"),
                (None, "r1", "PROFILE"),
            },
        )

    def test_confirmed_absence_requires_declared_complete_source(self):
        absent = record(
            "complete_snapshot",
            {
                "user_id": "user-1",
                "system_id": "profile",
                "resource_id": "r1",
                "data_category": "USER_PROFILE",
            },
            observed_state="ABSENT",
            inspection_status=InspectionStatus.CONFIRMED,
        )
        index = build_index(absent)
        scope_without_declaration = ExpectedResourceScope(
            "profile", "r1", "USER_PROFILE"
        )
        scope_with_declaration = ExpectedResourceScope(
            "profile",
            "r1",
            "USER_PROFILE",
            complete_evidence_ids=("complete_snapshot",),
        )

        incomplete = reconcile_request(
            request(),
            index,
            subject_user_id="user-1",
            expected_scopes=(scope_without_declaration,),
        )
        complete = reconcile_request(
            request(),
            index,
            subject_user_id="user-1",
            expected_scopes=(scope_with_declaration,),
        )

        self.assertEqual(incomplete.groups[0].status, CoverageStatus.INCONCLUSIVE)
        self.assertEqual(complete.groups[0].status, CoverageStatus.CONFIRMED_ABSENT)

    def test_complete_scoped_readback_can_prove_absence_for_exact_lookup_key(self):
        absent = record(
            "readback",
            {
                "lookup_key": "person@example.test",
                "system_id": "account_service",
                "resource_id": "account_1",
                "data_category": "USER_PROFILE",
            },
            observed_state="ABSENT",
            inspection_status=InspectionStatus.CONFIRMED,
            metadata={
                "complete_scoped_inspection": True,
                "readback_export_complete": True,
            },
        )

        ledger = reconcile_request(
            request(),
            build_index(absent),
            subject_identifiers={"email": ("person@example.test",)},
        )

        self.assertEqual(
            [item.evidence_id for item in ledger.eligible], ["readback"]
        )
        self.assertEqual(
            ledger.groups[0].status, CoverageStatus.CONFIRMED_ABSENT
        )

    def test_unverified_lookup_key_does_not_link_a_resource_to_the_subject(self):
        unrelated_lookup = record(
            "unverified-readback",
            {
                "lookup_key": "person@example.test",
                "system_id": "account_service",
                "resource_id": "account_1",
                "data_category": "USER_PROFILE",
            },
            observed_state="PRESENT",
            inspection_status=InspectionStatus.CONFIRMED,
        )

        ledger = reconcile_request(
            request(),
            build_index(unrelated_lookup),
            subject_identifiers={"email": ("person@example.test",)},
        )

        self.assertEqual(ledger.eligible, ())
        self.assertEqual(ledger.groups, ())

    def test_correlation_key_links_only_an_exact_stable_user_reference(self):
        exact_link = record(
            "exact-correlation",
            {
                "correlation_key": "user-1",
                "system_id": "backup_service",
                "resource_id": "backup_1",
                "data_category": "BACKUP_ARCHIVE",
            },
        )
        unrelated = record(
            "unrelated-correlation",
            {
                "correlation_key": "trace-1",
                "system_id": "backup_service",
                "resource_id": "backup_2",
                "data_category": "BACKUP_ARCHIVE",
            },
        )

        ledger = reconcile_request(
            request(),
            build_index(exact_link, unrelated),
            subject_user_id="user-1",
        )

        self.assertEqual(
            [item.evidence_id for item in ledger.eligible],
            ["exact-correlation"],
        )

    def test_subject_key_trace_links_sibling_events_within_same_source_file(self):
        source_path = "evidence/logs/service-events.log"
        anchor = record(
            "evidence-log",
            {
                "subject_key": "person@example.test",
                "trace_id": "trace-1",
                "system_id": "backup_service",
            },
            locator="$.events[0]",
            source_path=source_path,
        )
        sibling = record(
            "evidence-log",
            {
                "trace_id": "trace-1",
                "system_id": "backup_service",
                "resource_id": "backup-1",
                "data_category": "BACKUP_ARCHIVE",
            },
            locator="$.events[1]",
            source_path=source_path,
        )
        unrelated_sibling = record(
            "evidence-log",
            {
                "trace_id": "trace-2",
                "system_id": "backup_service",
                "resource_id": "backup-2",
                "data_category": "BACKUP_ARCHIVE",
            },
            locator="$.events[2]",
            source_path=source_path,
        )
        other_file = record(
            "other-evidence",
            {
                "trace_id": "trace-1",
                "system_id": "backup_service",
                "resource_id": "backup-2",
                "data_category": "BACKUP_ARCHIVE",
            },
            source_path="evidence/logs/other-service-events.log",
        )

        ledger = reconcile_request(
            request(),
            build_index(anchor, sibling, unrelated_sibling, other_file),
            subject_user_id="user-1",
            subject_identifiers={"email": ["person@example.test"]},
        )

        self.assertEqual(
            {
                item.record.fact.provenance.record_locator
                for item in ledger.eligible
            },
            {"$.events[0]", "$.events[1]"},
        )

    def test_post_cutoff_subject_anchor_cannot_link_trace_siblings(self):
        source_path = "evidence/logs/service-events.log"
        post_cutoff_anchor = record(
            "evidence-log",
            {
                "subject_key": "person@example.test",
                "trace_id": "trace-1",
            },
            observed_at="2026-04-01T00:00:00.000001Z",
            available_at="2026-04-01T00:00:00.000001Z",
            locator="$.events[0]",
            source_path=source_path,
        )
        sibling = record(
            "evidence-log",
            {
                "trace_id": "trace-1",
                "system_id": "backup_service",
                "resource_id": "backup-1",
                "data_category": "BACKUP_ARCHIVE",
            },
            locator="$.events[1]",
            source_path=source_path,
        )

        ledger = reconcile_request(
            request(),
            build_index(post_cutoff_anchor, sibling),
            subject_user_id="user-1",
            subject_identifiers={"email": ["person@example.test"]},
        )

        self.assertEqual(ledger.eligible, ())
        self.assertEqual(
            [
                item.record.fact.provenance.record_locator
                for item in ledger.excluded
            ],
            ["$.events[0]"],
        )

    def test_partial_snapshot_cannot_satisfy_complete_source_declaration(self):
        absent = record(
            "partial_snapshot",
            {
                "user_id": "user-1",
                "system_id": "profile",
                "resource_id": "r1",
                "data_category": "USER_PROFILE",
            },
            observed_state="ABSENT",
            inspection_status=InspectionStatus.CONFIRMED,
        )
        scope = ExpectedResourceScope(
            "profile",
            "r1",
            "USER_PROFILE",
            complete_evidence_ids=("partial_snapshot",),
        )

        ledger = reconcile_request(
            request(),
            build_index(
                absent,
                report_statuses={"partial_snapshot": ExtractionStatus.PARTIAL},
            ),
            subject_user_id="user-1",
            expected_scopes=(scope,),
        )

        self.assertEqual(ledger.groups[0].status, CoverageStatus.INCONCLUSIVE)

    def test_snapshot_captured_after_cutoff_cannot_prove_absence(self):
        absent = record(
            "late_snapshot",
            {
                "user_id": "user-1",
                "system_id": "profile",
                "resource_id": "r1",
                "data_category": "USER_PROFILE",
            },
            observed_state="ABSENT",
            inspection_status=InspectionStatus.CONFIRMED,
        )
        late_report = extraction_report(
            "late_snapshot",
            captured_at="2026-04-01T00:00:00.000001Z",
        )
        scope = ExpectedResourceScope(
            "profile",
            "r1",
            "USER_PROFILE",
            complete_evidence_ids=("late_snapshot",),
            evidence_ids=("late_snapshot",),
        )

        ledger = reconcile_request(
            request(),
            EvidenceIndex((absent,), (late_report,)),
            subject_user_id="user-1",
            expected_scopes=(scope,),
        )

        self.assertEqual(ledger.groups[0].status, CoverageStatus.INCONCLUSIVE)
        self.assertEqual(ledger.groups[0].observations[0].temporal_disposition,
                         TemporalDisposition.ELIGIBLE)
        self.assertEqual(
            ledger.source_inspections[0].status,
            InspectionSourceStatus.NOT_INSPECTED,
        )

    def test_incomplete_or_failed_extraction_cannot_prove_absence(self):
        failed = record(
            "failed",
            {
                "user_id": "user-1",
                "system_id": "profile",
                "resource_id": "r1",
            },
            observed_state="ABSENT",
            inspection_status=InspectionStatus.FAILED,
        )
        report_statuses = {"failed": ExtractionStatus.UNREADABLE}
        ledger = reconcile_request(
            request(),
            build_index(failed, report_statuses=report_statuses),
            subject_user_id="user-1",
        )

        self.assertEqual(ledger.groups[0].status, CoverageStatus.INSPECTION_FAILED)
        self.assertFalse(ledger.groups[0].contradictory)
        self.assertEqual(
            ledger.source_inspections[0].status,
            InspectionSourceStatus.INSPECTION_FAILED,
        )
        self.assertEqual(
            ledger.source_inspections[0].related_observation_count, 1
        )

    def test_ocr_unresolved_alias_is_inconclusive_and_never_absence(self):
        ocr = record(
            "ocr",
            {
                "email": "person@example.test",
                "system_id": "support",
                "resource_id": "attachment-1",
                "data_category": "SUPPORT_ATTACHMENT",
            },
            observed_at=None,
            extraction_method="tesseract-ocr",
        )

        ledger = reconcile_request(
            request(),
            build_index(
                ocr,
                report_statuses={"ocr": ExtractionStatus.PARTIAL},
            ),
            subject_identifiers={"email": ("PERSON@example.test",)},
        )

        self.assertEqual([item.evidence_id for item in ledger.unresolved], ["ocr"])
        self.assertEqual(
            ledger.unresolved[0].temporal_disposition,
            TemporalDisposition.UNRESOLVED,
        )
        self.assertEqual(ledger.groups[0].status, CoverageStatus.INCONCLUSIVE)
        self.assertEqual(
            ledger.source_inspections[0].status,
            InspectionSourceStatus.INCONCLUSIVE,
        )

    def test_only_strong_identity_links_associate_evidence_with_subject(self):
        strong_record = record(
            "strong-alias",
            {
                "email": "old@example.test",
                "system_id": "profile",
                "resource_id": "r1",
            },
        )
        candidate_record = record(
            "candidate-alias",
            {
                "email": "possible@example.test",
                "system_id": "profile",
                "resource_id": "r2",
            },
        )
        index = build_index(strong_record, candidate_record)
        strong_link = IdentityLink(
            user_id="user-1",
            identifier_type=IdentifierType.EMAIL,
            normalized_value="old@example.test",
            source=IdentityLinkSource.HISTORICAL,
            confidence=IdentityLinkConfidence.STRONG,
            valid_from=None,
            valid_until=None,
            provenance=Provenance(
                source_type="audit_id",
                source_id="audit-1",
                available_at=timestamp("2026-03-01T00:00:00Z"),
            ),
        )
        candidate_link = IdentityLink(
            user_id="user-1",
            identifier_type=IdentifierType.EMAIL,
            normalized_value="possible@example.test",
            source=IdentityLinkSource.EVIDENCE,
            confidence=IdentityLinkConfidence.CANDIDATE,
            valid_from=None,
            valid_until=None,
            provenance=Provenance(
                source_type="evidence_id",
                source_id="evidence-ocr",
                available_at=timestamp("2026-03-01T00:00:00Z"),
            ),
            reason="OCR uncertain",
        )

        ledger = reconcile_request(
            request(),
            index,
            subject_user_id="user-1",
            identity_links=(strong_link, candidate_link),
        )

        self.assertEqual(
            {item.evidence_id for item in ledger.eligible}, {"strong-alias"}
        )
        self.assertNotIn("candidate-alias", {item.evidence_id for item in ledger.eligible})

    def test_explicit_subject_reference_matches_only_exact_subject_aliases(self):
        matching_email = record(
            "subject-email",
            {
                "subject_reference": "PERSON@example.test",
                "system_id": "search_service",
                "resource_id": "search-1",
                "record_type": "SEARCH_INDEX_ENTRY",
            },
        )
        other_email = record(
            "other-subject-email",
            {
                "subject_reference": "someone-else@example.test",
                "system_id": "search_service",
                "resource_id": "search-2",
                "record_type": "SEARCH_INDEX_ENTRY",
            },
        )
        stable_reference = record(
            "subject-user-id",
            {
                "subject_reference": "user-1",
                "system_id": "security_service",
                "resource_id": "audit-1",
                "record_type": "SECURITY_AUDIT_LOG",
            },
        )
        late_reference = record(
            "late-subject-email",
            {
                "subject_reference": "person@example.test",
                "system_id": "search_service",
                "resource_id": "search-late",
                "record_type": "SEARCH_INDEX_ENTRY",
            },
            observed_at="2026-04-02T00:00:00Z",
            available_at="2026-04-02T00:00:00Z",
        )

        ledger = reconcile_request(
            request(),
            build_index(
                matching_email,
                other_email,
                stable_reference,
                late_reference,
            ),
            subject_user_id="user-1",
            subject_identifiers={"email": ("person@example.test",)},
        )

        self.assertEqual(
            {item.evidence_id for item in ledger.eligible},
            {"subject-email", "subject-user-id"},
        )
        self.assertEqual(
            {item.resource_id for item in ledger.groups},
            {"search-1", "audit-1", "search-late"},
        )
        self.assertEqual(
            [item.evidence_id for item in ledger.excluded],
            ["late-subject-email"],
        )

    def test_workflow_claim_and_data_flow_do_not_count_as_resource_state(self):
        workflow = record(
            "workflow",
            {
                "user_id": "user-1",
                "system_id": "workflow",
                "resource_id": "job-1",
                "reported_result": "COMPLETE",
            },
        )
        flow = record(
            "flow",
            {
                "user_id": "user-1",
                "system_id": "sync",
                "resource_id": "job-2",
                "event_type": "restore",
            },
        )

        ledger = reconcile_request(
            request(),
            build_index(workflow, flow),
            subject_user_id="user-1",
        )

        kinds = {item.evidence_id: item.kind for item in ledger.eligible}
        self.assertEqual(kinds["workflow"], ObservationKind.WORKFLOW_CLAIM)
        self.assertEqual(kinds["flow"], ObservationKind.DATA_FLOW)
        self.assertTrue(
            all(group.status == CoverageStatus.INCONCLUSIVE for group in ledger.groups)
        )

    def test_declared_scope_without_observations_is_not_inspected(self):
        ledger = reconcile_request(
            request(),
            build_index(),
            subject_user_id="user-1",
            expected_scopes=(
                ExpectedResourceScope("profile", "r-never-seen", "USER_PROFILE"),
            ),
        )

        self.assertEqual(len(ledger.groups), 1)
        self.assertEqual(ledger.groups[0].status, CoverageStatus.NOT_INSPECTED)

    def test_declared_failed_source_marks_expected_scope_inspection_failed(self):
        failed_report = extraction_report(
            "failed_source",
            status=ExtractionStatus.UNREADABLE,
        )
        index = EvidenceIndex((), (failed_report,))

        ledger = reconcile_request(
            request(),
            index,
            subject_user_id="user-1",
            expected_scopes=(
                ExpectedResourceScope(
                    "profile",
                    "r1",
                    "USER_PROFILE",
                    evidence_ids=("failed_source",),
                ),
            ),
        )

        self.assertEqual(len(ledger.groups), 1)
        self.assertEqual(
            ledger.groups[0].status, CoverageStatus.INSPECTION_FAILED
        )
        self.assertEqual(
            ledger.source_inspections[0].status,
            InspectionSourceStatus.INSPECTION_FAILED,
        )


if __name__ == "__main__":
    unittest.main()
