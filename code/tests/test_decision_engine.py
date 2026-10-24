import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from deletion_audit.coverage_grounding import (
    ActivityKind,
    GroundedActivity,
    GroundedRequestEvidence,
)
from deletion_audit.decision_engine import (
    CaseDecision,
    DeletionStatus,
    decide_request,
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
from deletion_audit.policy_assessment import assess_request_policy
from deletion_audit.recreation_graph import (
    RecreationEdgeKind,
    RecreationRiskState,
    ResourceNode,
    build_recreation_graph,
)
from deletion_audit.request_classifier import classify_request
from deletion_audit.temporal import parse_timestamp
from main import _write_and_validate


def timestamp(value):
    return parse_timestamp(value, "test timestamp")


def make_request(text="Please delete my account"):
    return DeletionRequest(
        case_id="case-engine",
        email="person@example.test",
        requested_at=timestamp("2026-03-01T00:00:00Z"),
        reported_status="COMPLETE",
        reported_at=timestamp("2026-03-16T00:00:00Z"),
        audit_at=timestamp("2026-04-01T00:00:00Z"),
        request_text=text,
    )


def evidence(
    evidence_id,
    category,
    state="PRESENT",
    attributes=None,
    inspection_status=InspectionStatus.CONFIRMED,
    system_id="account_service",
    resource_id="account_1",
):
    attrs = {
        "user_id": "user_1",
        "system_id": system_id,
        "resource_id": resource_id,
        "data_category": category,
    }
    attrs.update(attributes or {})
    path = "evidence/{}.sql".format(evidence_id)
    return IndexedEvidence(
        evidence_id=evidence_id,
        source_path=path,
        source_origin="SQL snapshot",
        extraction_method="sqlite-table-row",
        fact=EvidenceFact(
            system_id=system_id,
            resource_id=resource_id,
            data_category=category,
            observed_state=state,
            inspection_status=inspection_status,
            provenance=Provenance(
                source_type="EVIDENCE_FILE",
                source_id=evidence_id,
                source_path=path,
                record_locator="table=records;row=1",
                available_at=timestamp("2026-03-20T00:00:00Z"),
            ),
            subject_user_id="user_1",
            observed_at=timestamp("2026-03-20T00:00:00Z"),
        ),
        attributes_json=json.dumps(attrs, sort_keys=True),
        metadata_json=json.dumps({"table_name": "customer_profiles"}),
        identifiers=(("email", "person@example.test"),),
        timestamp_fields=tuple(),
    )


def grounded_for(records, complete=False, activities=()):
    request = make_request()
    reports = tuple(
        FileExtractionReport(
            evidence_id=record.evidence_id,
            source_path=record.source_path,
            source_origin=record.source_origin,
            captured_at="2026-03-20T00:00:00Z",
            status=ExtractionStatus.SUCCESS,
            extraction_method="sqlite",
            record_count=1,
        )
        for record in records
    )
    index = EvidenceIndex(records, reports)
    scopes = tuple(
        ExpectedResourceScope(
            system_id=record.fact.system_id,
            resource_id=record.fact.resource_id,
            data_category=record.fact.data_category,
            complete_evidence_ids=(record.evidence_id,) if complete else tuple(),
            evidence_ids=(record.evidence_id,),
        )
        for record in records
    )
    ledger = reconcile_request(
        request,
        index,
        subject_user_id="user_1",
        expected_scopes=scopes,
    )
    return GroundedRequestEvidence(
        case_id=request.case_id,
        identity_status=IdentityLinkResolutionStatus.RESOLVED,
        subject_user_id="user_1",
        ledger=ledger,
        snapshot_contracts=tuple(),
        expected_scopes=scopes,
        activity=tuple(activities),
    )


def policy_for(grounded, rules):
    return assess_request_policy(
        grounded,
        rules,
        subject_identifiers={"email": ("person@example.test",)},
    )


def deletion_rule(category="USER_PROFILE", action="DELETE"):
    return DeletionRule(
        rule_id="rule-test",
        data_category=category,
        condition="Always",
        required_action=action,
    )


class DecisionEngineTests(unittest.TestCase):
    def test_explicitly_unauthorized_request_is_not_applicable(self):
        request = make_request("Please remove me from marketing lists only.")
        grounded = grounded_for(tuple())
        assessment = policy_for(grounded, tuple())
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            assessment,
            build_recreation_graph(grounded),
        )
        self.assertEqual(decision.status, DeletionStatus.NOT_APPLICABLE)
        self.assertEqual(decision.steps, tuple())

    def test_confirmed_present_delete_violation_gets_ordered_plan(self):
        request = make_request()
        grounded = grounded_for((evidence("profile", "USER_PROFILE"),))
        assessment = policy_for(grounded, (deletion_rule(),))
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            assessment,
            build_recreation_graph(grounded),
        )
        self.assertEqual(decision.status, DeletionStatus.INCOMPLETE)
        self.assertEqual(
            [step["phase"] for step in decision.steps],
            ["FINDING", "REMEDIATION", "VERIFICATION"],
        )
        self.assertEqual(
            [step["operation"] for step in decision.steps],
            ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
        )
        self.assertEqual(decision.steps[0]["evidence_id"], "profile")
        self.assertEqual(decision.steps[1]["evidence_id"], "")
        self.assertEqual(decision.steps[2]["evidence_id"], "")

    def test_complete_requires_confirmed_absence_and_cites_verification(self):
        request = make_request()
        absent = evidence("absence", "USER_PROFILE", "ABSENT")
        grounded = grounded_for((absent,), complete=True)
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            policy_for(grounded, (deletion_rule(),)),
            build_recreation_graph(grounded),
        )
        self.assertEqual(decision.status, DeletionStatus.COMPLETE)
        self.assertEqual(len(decision.steps), 1)
        self.assertEqual(decision.steps[0]["phase"], "VERIFICATION")
        self.assertEqual(
            decision.steps[0]["operation"], "VERIFY_RECORD_ABSENT"
        )
        self.assertEqual(decision.steps[0]["evidence_id"], "absence")

    def test_no_subject_scopes_cannot_be_promoted_to_complete(self):
        request = make_request()
        grounded = grounded_for(tuple())

        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            policy_for(grounded, (deletion_rule(),)),
            build_recreation_graph(grounded),
        )

        self.assertIsNone(decision.status)
        self.assertEqual(decision.steps, tuple())
        self.assertTrue(
            any(
                "No evidence-backed verification steps" in reason
                for reason in decision.unresolved_reasons
            )
        )

    def test_unknown_scope_does_not_become_complete_or_not_applicable(self):
        uncertain = evidence(
            "unknown",
            "USER_PROFILE",
            state=None,
            inspection_status=InspectionStatus.INCONCLUSIVE,
        )
        grounded = grounded_for((uncertain,))
        request = make_request()
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            policy_for(grounded, (deletion_rule(),)),
            build_recreation_graph(grounded),
        )
        self.assertIsNone(decision.status)
        self.assertTrue(decision.unresolved_reasons)

    def test_confirmed_violation_is_incomplete_despite_unrelated_unknown_scopes(self):
        present_profile = evidence("profile-present", "USER_PROFILE")
        unknown_profile = evidence(
            "profile-uninspected",
            "USER_PROFILE",
            state=None,
            inspection_status=InspectionStatus.INCONCLUSIVE,
            resource_id="account_2",
        )
        unsupported_scope = evidence(
            "unsupported",
            "UNMAPPED_CATEGORY",
            system_id="integration_service",
            resource_id="resource_2",
        )
        grounded = grounded_for(
            (present_profile, unknown_profile, unsupported_scope)
        )
        decision = decide_request(
            make_request(),
            classify_request("Please delete my account"),
            grounded,
            policy_for(grounded, (deletion_rule(),)),
            build_recreation_graph(grounded),
        )

        self.assertEqual(decision.status, DeletionStatus.INCOMPLETE)
        self.assertTrue(
            any(
                step["operation"] == "REPORT_REMAINING_RECORD"
                and step["resource_id"] == "account_1"
                for step in decision.steps
            )
        )
        self.assertFalse(
            any(
                step["resource_id"] in {"account_2", "resource_2"}
                for step in decision.steps
            )
        )
        self.assertTrue(
            any("unknown" in reason.casefold() for reason in decision.unresolved_reasons)
        )

    def test_contradictory_resource_states_block_a_final_status(self):
        grounded = grounded_for(
            (
                evidence("present", "USER_PROFILE", "PRESENT"),
                evidence("absent", "USER_PROFILE", "ABSENT"),
            ),
            complete=True,
        )
        request = make_request()
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            policy_for(grounded, (deletion_rule(),)),
            build_recreation_graph(grounded),
        )
        self.assertIsNone(decision.status)

    def test_active_data_flow_is_disabled_before_record_remediation(self):
        request = make_request()
        profile = evidence("profile", "USER_PROFILE")
        flow = evidence(
            "flow",
            "DATA_FLOW_CONFIGURATION",
            attributes={"enabled": 1},
            system_id="integration_service",
            resource_id="data_flow_1",
        )
        grounded = grounded_for((profile, flow))
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            policy_for(grounded, (deletion_rule(),)),
            build_recreation_graph(grounded),
        )
        remediation = [
            step["operation"]
            for step in decision.steps
            if step["phase"] == "REMEDIATION"
        ]
        self.assertEqual(
            remediation,
            ["DISABLE_DATA_FLOW", "DELETE_RECORD"],
        )
        self.assertEqual(decision.status, DeletionStatus.INCOMPLETE)

    def test_incomplete_case_still_verifies_policy_required_retained_records(self):
        request = make_request()
        profile = evidence("profile", "USER_PROFILE")
        audit = evidence(
            "audit",
            "SECURITY_AUDIT_LOG",
            system_id="security_service",
            resource_id="audit_record_1",
        )
        grounded = grounded_for((profile, audit))
        rules = (
            deletion_rule("USER_PROFILE", "DELETE"),
            deletion_rule("SECURITY_AUDIT_LOG", "RETAIN"),
        )
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            policy_for(grounded, rules),
            build_recreation_graph(grounded),
        )
        retained_check = next(
            step
            for step in decision.steps
            if step["operation"] == "VERIFY_RECORD_PRESENT"
        )
        self.assertEqual(decision.status, DeletionStatus.INCOMPLETE)
        self.assertEqual(retained_check["evidence_id"], "")

    def test_active_backup_restore_risk_uses_block_restore_plan(self):
        request = make_request()
        backup = evidence(
            "backup",
            "BACKUP_ARCHIVE",
            attributes={"restore_allowed": 1},
            system_id="backup_service",
            resource_id="backup_1",
        )
        grounded = grounded_for((backup,))
        decision = decide_request(
            request,
            classify_request(request.request_text),
            grounded,
            policy_for(
                grounded,
                (
                    deletion_rule(
                        "BACKUP_ARCHIVE",
                        "RETAIN",
                    ),
                ),
            ),
            build_recreation_graph(grounded),
        )
        self.assertEqual(decision.status, DeletionStatus.INCOMPLETE)
        self.assertEqual(
            [step["operation"] for step in decision.steps],
            [
                "REPORT_RESTORE_RISK",
                "BLOCK_RESTORE",
                "VERIFY_RECORD_PRESENT",
                "VERIFY_RESTORE_BLOCKED",
            ],
        )

    def test_recreation_graph_preserves_activity_edges_as_unknown(self):
        event = SystemActivity(
            activity_id="activity-sync",
            event_time=timestamp("2026-03-20T00:00:00Z"),
            event_type="SYNC_RECORD",
            source_system="account_service",
            target_system="search_service",
            resource_id="account_1",
            reported_result="SUCCESS",
            details="sync completed",
        )
        activity = GroundedActivity(
            activity=event,
            kind=ActivityKind.DATA_FLOW,
            temporal_disposition=TemporalDisposition.ELIGIBLE,
            system_id="account_service",
            resource_id="account_1",
            supporting_evidence_ids=("evidence-profile",),
            attribution_source="INDEXED_SUBJECT_RECORD",
        )
        grounded = grounded_for(
            (evidence("profile", "USER_PROFILE"),),
            activities=(activity,),
        )
        graph = build_recreation_graph(grounded)
        edge = next(item for item in graph.edges if item.kind == RecreationEdgeKind.SYNC)
        self.assertEqual(edge.risk_state, RecreationRiskState.UNKNOWN)
        self.assertEqual(edge.evidence_ids, ("activity-sync",))
        self.assertEqual(
            edge.source,
            ResourceNode("account_service", "account_1"),
        )
        self.assertEqual(
            edge.target,
            ResourceNode("search_service", "account_1"),
        )

    def test_recreation_graph_keeps_conflicting_and_unresolved_flow_edges(self):
        active = evidence(
            "flow-active",
            "DATA_FLOW_CONFIGURATION",
            attributes={"enabled": 1},
            system_id="integration_service",
            resource_id="data_flow_1",
        )
        inactive = evidence(
            "flow-inactive",
            "DATA_FLOW_CONFIGURATION",
            attributes={"enabled": 0},
            system_id="integration_service",
            resource_id="data_flow_1",
        )
        unresolved_record = evidence(
            "flow-unresolved",
            "DATA_FLOW_CONFIGURATION",
            attributes={"enabled": 1},
            system_id="integration_service",
            resource_id="data_flow_1",
        )
        unresolved = replace(
            unresolved_record,
            fact=replace(unresolved_record.fact, observed_at=None),
        )
        grounded = grounded_for((active, inactive, unresolved))
        graph = build_recreation_graph(grounded)
        states = {
            (edge.evidence_ids[0], edge.risk_state)
            for edge in graph.edges
            if edge.kind == RecreationEdgeKind.CONNECTOR
        }
        self.assertEqual(
            states,
            {
                ("flow-active", RecreationRiskState.ACTIVE),
                ("flow-inactive", RecreationRiskState.INACTIVE),
                ("flow-unresolved", RecreationRiskState.UNKNOWN),
            },
        )

    def test_recreation_graph_returns_directed_paths(self):
        events = []
        for event_id, source, target in (
            ("sync-1", "account_service", "search_service"),
            ("sync-2", "search_service", "export_service"),
        ):
            row = SystemActivity(
                activity_id=event_id,
                event_time=timestamp("2026-03-20T00:00:00Z"),
                event_type="SYNC_RECORD",
                source_system=source,
                target_system=target,
                resource_id="account_1",
                reported_result="SUCCESS",
                details="synchronization completed",
            )
            events.append(
                GroundedActivity(
                    activity=row,
                    kind=ActivityKind.DATA_FLOW,
                    temporal_disposition=TemporalDisposition.ELIGIBLE,
                    system_id=source,
                    resource_id="account_1",
                    supporting_evidence_ids=("evidence-profile",),
                    attribution_source="INDEXED_SUBJECT_RECORD",
                )
            )
        graph = build_recreation_graph(
            grounded_for(
                (evidence("profile", "USER_PROFILE"),),
                activities=tuple(events),
            )
        )
        paths = graph.paths_between(
            ResourceNode("account_service", "account_1"),
            ResourceNode("export_service", "account_1"),
        )
        self.assertEqual(len(paths), 1)
        self.assertEqual(
            tuple(edge.evidence_ids[0] for edge in paths[0]),
            ("sync-1", "sync-2"),
        )

    def test_output_writer_refuses_to_map_undecidable_case_to_allowed_status(self):
        decision = CaseDecision(
            case_id="case-unknown",
            status=None,
            steps=tuple(),
            unresolved_reasons=("Coverage is incomplete.",),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "output.csv"
            with self.assertRaisesRegex(ValueError, "case-unknown"):
                _write_and_validate(
                    (decision,),
                    output_path,
                    Path(temp_dir),
                )
            self.assertFalse(output_path.exists())

    def test_explicit_source_resource_ids_ground_copy_edges(self):
        replicas = []
        for evidence_id, category, table_name, system_id, resource_id in (
            (
                "replica",
                "USER_PROFILE",
                "customer_data_read_replica",
                "account_service",
                "account_replica_1",
            ),
            (
                "search-copy",
                "SEARCH_INDEX_ENTRY",
                "search_documents_primary",
                "search_service",
                "search_1",
            ),
            (
                "export-copy",
                "USER_EXPORT",
                "customer_export_jobs",
                "export_service",
                "export_1",
            ),
        ):
            value = evidence(
                evidence_id,
                category,
                attributes={"source_resource_id": "account_1"},
                system_id=system_id,
                resource_id=resource_id,
            )
            replicas.append(
                replace(
                    value,
                    metadata_json=json.dumps({"table_name": table_name}),
                )
            )
        graph = build_recreation_graph(grounded_for(tuple(replicas)))
        kinds_by_id = {
            edge.evidence_ids[0]: edge.kind
            for edge in graph.edges
            if edge.evidence_ids
        }
        self.assertEqual(kinds_by_id["replica"], RecreationEdgeKind.REPLICA)
        self.assertEqual(kinds_by_id["search-copy"], RecreationEdgeKind.INDEX)
        self.assertEqual(kinds_by_id["export-copy"], RecreationEdgeKind.EXPORT)

if __name__ == "__main__":
    unittest.main()
