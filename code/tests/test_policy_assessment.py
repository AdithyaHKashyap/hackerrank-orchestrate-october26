import json
import unittest

from deletion_audit.coverage_grounding import (
    ActivityKind,
    GroundedActivity,
    GroundedRequestEvidence,
)
from deletion_audit.evidence_index import (
    EvidenceIndex,
    ExtractionStatus,
    FileExtractionReport,
    IndexedEvidence,
)
from deletion_audit.evidence_reconciliation import (
    ExpectedResourceScope,
    TemporalDisposition,
    reconcile_request,
)
from deletion_audit.identity_links import IdentityLinkResolutionStatus
from deletion_audit.models import (
    DeletionRequest,
    DeletionRule,
    EvidenceFact,
    InspectionStatus,
    Provenance,
    SystemActivity,
)
from deletion_audit.policy_assessment import (
    PolicyAssessmentStatus,
    assess_request_policy,
)
from deletion_audit.temporal import parse_timestamp


def timestamp(value):
    return parse_timestamp(value, "test timestamp")


def request(audit_at="2026-04-01T00:00:00Z"):
    return DeletionRequest(
        case_id="case-policy",
        email="person@example.test",
        requested_at=timestamp("2026-03-01T00:00:00Z"),
        reported_status="COMPLETE",
        reported_at=timestamp("2026-03-10T00:00:00Z"),
        audit_at=timestamp(audit_at),
        request_text="Delete my account",
    )


def record(
    evidence_id,
    category,
    state,
    attributes=None,
    observed_at="2026-03-15T00:00:00Z",
    inspection_status=InspectionStatus.CONFIRMED,
):
    attributes = dict(attributes or {})
    attributes.update(
        {
            "user_id": attributes.get("user_id", "user_1"),
            "system_id": "account_service",
            "resource_id": "resource_1",
            "data_category": category,
        }
    )
    return IndexedEvidence(
        evidence_id=evidence_id,
        source_path="evidence/{}.json".format(evidence_id),
        source_origin="test",
        extraction_method="json-object-path",
        fact=EvidenceFact(
            system_id="account_service",
            resource_id="resource_1",
            data_category=category,
            observed_state=state,
            inspection_status=inspection_status,
            provenance=Provenance(
                source_type="EVIDENCE_FILE",
                source_id=evidence_id,
                source_path="evidence/{}.json".format(evidence_id),
                record_locator="$.resource",
                available_at=timestamp("2026-03-16T00:00:00Z"),
            ),
            subject_user_id=attributes.get("user_id"),
            observed_at=timestamp(observed_at) if observed_at else None,
        ),
        attributes_json=json.dumps(attributes, sort_keys=True),
        metadata_json="{}",
        identifiers=tuple(),
        timestamp_fields=tuple(),
    )


def rule(category, action, condition="Always"):
    return DeletionRule(
        rule_id="rule-{}".format(category.lower()),
        data_category=category,
        condition=condition,
        required_action=action,
    )


def assess(records, policy_rule, complete_ids=(), audit_at="2026-04-01T00:00:00Z"):
    reports = tuple(
        FileExtractionReport(
            evidence_id=item.evidence_id,
            source_path=item.source_path,
            source_origin=item.source_origin,
            captured_at="2026-03-16T00:00:00Z",
            status=ExtractionStatus.SUCCESS,
            extraction_method="fixture",
            record_count=1,
        )
        for item in records
    )
    index = EvidenceIndex(records, reports)
    first = records[0]
    scopes = (
        ExpectedResourceScope(
            system_id=first.fact.system_id,
            resource_id=first.fact.resource_id,
            data_category=first.fact.data_category,
            complete_evidence_ids=tuple(complete_ids),
            evidence_ids=tuple(item.evidence_id for item in records),
        ),
    )
    ledger = reconcile_request(
        request(audit_at),
        index,
        subject_user_id="user_1",
        expected_scopes=scopes,
    )
    grounded = GroundedRequestEvidence(
        case_id="case-policy",
        identity_status=IdentityLinkResolutionStatus.RESOLVED,
        subject_user_id="user_1",
        ledger=ledger,
        snapshot_contracts=tuple(),
        expected_scopes=scopes,
        activity=tuple(),
    )
    return assess_request_policy(
        grounded,
        (policy_rule,),
        subject_identifiers={"email": ("person@example.test",)},
        subject_names=("Test User",),
    ).assessments[0]


class PolicyAssessmentTests(unittest.TestCase):
    def test_delete_requires_a_confirmed_state(self):
        present = assess(
            (record("present", "USER_PROFILE", "PRESENT"),),
            rule("USER_PROFILE", "DELETE"),
        )
        absent = assess(
            (record("absent", "USER_PROFILE", "ABSENT"),),
            rule("USER_PROFILE", "DELETE"),
            complete_ids=("absent",),
        )
        self.assertEqual(present.status, PolicyAssessmentStatus.VIOLATED)
        self.assertEqual(absent.status, PolicyAssessmentStatus.SATISFIED)

    def test_conflicting_direct_observations_remain_unknown_with_both_sources(self):
        outcome = assess(
            (
                record("present", "USER_PROFILE", "PRESENT"),
                record("absent", "USER_PROFILE", "ABSENT"),
            ),
            rule("USER_PROFILE", "DELETE"),
            complete_ids=("absent",),
        )

        self.assertEqual(outcome.status, PolicyAssessmentStatus.UNKNOWN)
        self.assertEqual(outcome.evidence_ids, ("absent", "present"))
        self.assertIn("Conflicting", outcome.explanation)

    def test_tombstone_must_keep_stable_reference_and_remove_direct_identifiers(self):
        redacted = assess(
            (
                record(
                    "tombstone",
                    "ACCOUNT_TOMBSTONE",
                    "PRESENT",
                    {
                        "user_id": "user_1",
                        "account_status": "DELETED",
                        "full_name": None,
                        "email": None,
                        "phone": None,
                        "email_hash": None,
                    },
                ),
            ),
            rule(
                "ACCOUNT_TOMBSTONE",
                "REDACT",
                "Account is deleted and only a stable internal user_id is needed to preserve references to retained records",
            ),
        )
        exposed = assess(
            (
                record(
                    "tombstone-pii",
                    "ACCOUNT_TOMBSTONE",
                    "PRESENT",
                    {
                        "user_id": "user_1",
                        "account_status": "DELETED",
                        "full_name": "Test User",
                        "email": "person@example.test",
                        "phone": None,
                        "email_hash": None,
                    },
                ),
            ),
            rule(
                "ACCOUNT_TOMBSTONE",
                "REDACT",
                "Account is deleted and only a stable internal user_id is needed to preserve references to retained records",
            ),
        )

        self.assertEqual(redacted.status, PolicyAssessmentStatus.SATISFIED)
        self.assertEqual(exposed.status, PolicyAssessmentStatus.VIOLATED)
        self.assertEqual(exposed.potential_exposed_fields, ("email", "full_name"))

    def test_anonymization_requires_unlinking_and_attributable_rows_violate(self):
        outcome = assess(
            (
                record(
                    "analytics",
                    "ANALYTICS_PROFILE",
                    "PRESENT",
                    {"user_id": "user_1", "email": "person@example.test"},
                ),
            ),
            rule(
                "ANALYTICS_PROFILE",
                "ANONYMIZE",
                "Record is still attributable to a user",
            ),
        )

        self.assertEqual(outcome.applicable, True)
        self.assertEqual(outcome.status, PolicyAssessmentStatus.VIOLATED)

    def test_retention_and_legal_hold_conditions_require_temporal_support(self):
        retained = assess(
            (
                record(
                    "audit",
                    "SECURITY_AUDIT_LOG",
                    "PRESENT",
                    {"retention_until": "2027-01-01T00:00:00Z"},
                ),
            ),
            rule(
                "SECURITY_AUDIT_LOG",
                "RETAIN",
                "Record is within the supplied retention period",
            ),
        )
        unknown_hold = assess(
            (
                record("hold", "LEGAL_HOLD_RECORD", "PRESENT", {}),
            ),
            rule(
                "LEGAL_HOLD_RECORD",
                "RETAIN",
                "A supplied legal hold is active",
            ),
        )

        self.assertEqual(retained.status, PolicyAssessmentStatus.SATISFIED)
        self.assertEqual(unknown_hold.status, PolicyAssessmentStatus.UNKNOWN)

    def test_retained_record_with_subject_pii_remains_unknown_without_field_policy(self):
        outcome = assess(
            (
                record(
                    "retained-pii",
                    "SECURITY_AUDIT_LOG",
                    "PRESENT",
                    {
                        "retention_until": "2027-01-01T00:00:00Z",
                        "email": "person@example.test",
                    },
                ),
            ),
            rule(
                "SECURITY_AUDIT_LOG",
                "RETAIN",
                "Record is within the supplied retention period",
            ),
        )

        self.assertEqual(outcome.status, PolicyAssessmentStatus.UNKNOWN)
        self.assertEqual(outcome.potential_exposed_fields, ("email",))

    def test_cutoff_and_unresolved_observations_never_prove_compliance(self):
        later = assess(
            (
                record(
                    "later",
                    "USER_PROFILE",
                    "ABSENT",
                    observed_at="2026-04-01T00:00:00.000001Z",
                ),
            ),
            rule("USER_PROFILE", "DELETE"),
            complete_ids=("later",),
        )
        unresolved = assess(
            (
                record(
                    "unresolved",
                    "USER_PROFILE",
                    "ABSENT",
                    observed_at=None,
                ),
            ),
            rule("USER_PROFILE", "DELETE"),
            complete_ids=("unresolved",),
        )

        self.assertEqual(later.status, PolicyAssessmentStatus.UNKNOWN)
        self.assertEqual(later.excluded_evidence_ids, ("later",))
        self.assertEqual(unresolved.status, PolicyAssessmentStatus.UNKNOWN)
        self.assertEqual(unresolved.unresolved_evidence_ids, ("unresolved",))

    def test_matching_pii_is_reported_as_potential_when_state_is_unconfirmed(self):
        outcome = assess(
            (
                record(
                    "email-log",
                    "EMAIL_DELIVERY_LOG",
                    "PRESENT",
                    {"email": "person@example.test"},
                    inspection_status=InspectionStatus.INCONCLUSIVE,
                ),
            ),
            rule(
                "EMAIL_DELIVERY_LOG",
                "REDACT",
                "Log contains a user email address",
            ),
        )

        self.assertEqual(outcome.status, PolicyAssessmentStatus.UNKNOWN)
        self.assertEqual(outcome.potential_exposed_fields, ("email",))

    def test_scope_without_a_supplied_rule_is_preserved_as_unknown(self):
        item = record("unmapped", "UNMAPPED_CATEGORY", "PRESENT")
        index = EvidenceIndex(
            (item,),
            (
                FileExtractionReport(
                    evidence_id="unmapped",
                    source_path=item.source_path,
                    source_origin="test",
                    captured_at="2026-03-16T00:00:00Z",
                    status=ExtractionStatus.SUCCESS,
                    extraction_method="fixture",
                    record_count=1,
                ),
            ),
        )
        ledger = reconcile_request(
            request(),
            index,
            subject_user_id="user_1",
        )
        grounded = GroundedRequestEvidence(
            case_id="case-policy",
            identity_status=IdentityLinkResolutionStatus.RESOLVED,
            subject_user_id="user_1",
            ledger=ledger,
            snapshot_contracts=tuple(),
            expected_scopes=tuple(),
            activity=tuple(),
        )

        batch = assess_request_policy(grounded, (rule("USER_PROFILE", "DELETE"),))

        self.assertEqual(batch.unmapped_scope_count, 1)
        self.assertEqual(len(batch.assessments), 1)
        self.assertIsNone(batch.assessments[0].rule_id)
        self.assertEqual(
            batch.assessments[0].status, PolicyAssessmentStatus.UNKNOWN
        )

    def test_attributed_flow_activity_remains_an_unconfirmed_claim(self):
        resource = record("flow", "USER_PROFILE", "PRESENT")
        index = EvidenceIndex(
            (resource,),
            (
                FileExtractionReport(
                    evidence_id="flow",
                    source_path=resource.source_path,
                    source_origin="test",
                    captured_at="2026-03-16T00:00:00Z",
                    status=ExtractionStatus.SUCCESS,
                    extraction_method="fixture",
                    record_count=1,
                ),
            ),
        )
        ledger = reconcile_request(
            request(),
            index,
            subject_user_id="user_1",
        )
        activity = SystemActivity(
            activity_id="activity-flow",
            event_time=timestamp("2026-03-20T00:00:00Z"),
            event_type="CHECK_DATA_FLOW",
            source_system="deletion_worker",
            target_system="integration_service",
            resource_id="data_flow_1",
            reported_result="SUCCESS",
            details="Connector status check says enabled.",
        )
        grounded = GroundedRequestEvidence(
            case_id="case-policy",
            identity_status=IdentityLinkResolutionStatus.RESOLVED,
            subject_user_id="user_1",
            ledger=ledger,
            snapshot_contracts=tuple(),
            expected_scopes=tuple(),
            activity=(
                GroundedActivity(
                    activity=activity,
                    kind=ActivityKind.DATA_FLOW,
                    temporal_disposition=TemporalDisposition.ELIGIBLE,
                    system_id="integration_service",
                    resource_id="data_flow_1",
                    supporting_evidence_ids=("evidence-link",),
                    attribution_source="EXPLICIT_IDENTITY_LINK",
                ),
            ),
        )

        batch = assess_request_policy(grounded, tuple())

        self.assertEqual(len(batch.activity_risks), 1)
        self.assertEqual(
            batch.activity_risks[0].status, PolicyAssessmentStatus.UNKNOWN
        )
        self.assertEqual(
            batch.activity_risks[0].evidence_ids, ("activity-flow",)
        )
        self.assertEqual(
            batch.activity_risks[0].supporting_evidence_ids,
            ("evidence-link",),
        )


if __name__ == "__main__":
    unittest.main()
