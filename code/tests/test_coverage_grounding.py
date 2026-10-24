import csv
import json
import tempfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from deletion_audit.coverage_grounding import (
    ActivityKind,
    derive_snapshot_contracts,
    ground_request_evidence,
    normalize_evidence_index,
)
from deletion_audit.evidence_index import (
    EvidenceIndex,
    ExtractionStatus,
    FileExtractionReport,
    IndexedEvidence,
)
from deletion_audit.evidence_reconciliation import (
    CoverageStatus,
    TemporalDisposition,
)
from deletion_audit.identity_links import (
    IdentityLinkResolutionStatus,
    IdentityLinkResolver,
)
from deletion_audit.models import (
    DeletionRequest,
    EvidenceFact,
    Identity,
    InspectionStatus,
    Provenance,
    SystemActivity,
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


def evidence_record(
    evidence_id="evidence-test",
    attributes=None,
    observed_at="2026-03-15T00:00:00Z",
    available_at="2026-03-16T00:00:00Z",
    metadata=None,
):
    attributes = attributes or {}
    return IndexedEvidence(
        evidence_id=evidence_id,
        source_path="evidence/test.json",
        source_origin="test",
        extraction_method="json-object-path",
        fact=EvidenceFact(
            system_id=attributes.get("system_id"),
            resource_id=attributes.get("resource_id"),
            data_category=attributes.get("data_category"),
            observed_state=None,
            inspection_status=InspectionStatus.INCONCLUSIVE,
            provenance=Provenance(
                source_type="EVIDENCE_FILE",
                source_id=evidence_id,
                source_path="evidence/test.json",
                record_locator="$.record",
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


def report(
    evidence_id="evidence-test",
    status=ExtractionStatus.SUCCESS,
    source_path="evidence/test.json",
    captured_at="2026-03-16T00:00:00Z",
):
    return FileExtractionReport(
        evidence_id=evidence_id,
        source_path=source_path,
        source_origin="test",
        captured_at=captured_at,
        status=status,
        extraction_method="fixture",
        record_count=1,
    )


def activity(
    activity_id,
    event_type,
    resource_id,
    target_system="account_service",
    source_system="deletion_worker",
    event_time="2026-03-20T00:00:00Z",
    details="operation completed",
    reported_result="SUCCESS",
):
    return SystemActivity(
        activity_id=activity_id,
        event_time=timestamp(event_time),
        event_type=event_type,
        source_system=source_system,
        target_system=target_system,
        resource_id=resource_id,
        reported_result=reported_result,
        details=details,
    )


def identity_resolver(*emails):
    identities = tuple(
        Identity(
            user_id="user_{}".format(index),
            name="Test User {}".format(index),
            email=email,
            phone="+1 555 000 {}".format(index),
            email_hash="hash-{}".format(index),
            updated_at=timestamp("2025-01-01T00:00:00Z"),
        )
        for index, email in enumerate(emails, start=1)
    )
    return IdentityLinkResolver(identities, tuple())


class CoverageGroundingTests(unittest.TestCase):
    def test_service_export_schema_links_nested_rows_and_inherits_observation_time(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_dir = Path(temp_dir)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "service_export.json").write_text(
                json.dumps(
                    {
                        "service_exports": {
                            "search_service": {
                                "index_queries": [
                                    {
                                        "observed_at": "2026-03-20T00:00:00Z",
                                        "resource_id": "query_1",
                                        "query": "person@example.test",
                                        "hits": {
                                            "total": 1,
                                            "documents": [
                                                {
                                                    "resource_id": "search_1",
                                                    "customer_reference": "user_1",
                                                    "email": "person@example.test",
                                                }
                                            ],
                                        },
                                    }
                                ]
                            },
                            "account_service": {
                                "profile_lookups": [
                                    {
                                        "observed_at": "2026-03-20T00:01:00Z",
                                        "resource_id": "account_1",
                                        "status_code": 200,
                                        "profile": {
                                            "customer_reference": "user_1",
                                            "email": "person@example.test",
                                        },
                                    },
                                    {
                                        "observed_at": "2026-03-20T00:02:00Z",
                                        "resource_id": "account_2",
                                        "status_code": 404,
                                        "profile": None,
                                    },
                                ]
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            with (dataset_dir / "evidence_files.csv").open(
                "w", encoding="utf-8", newline=""
            ) as manifest:
                writer = csv.writer(manifest)
                writer.writerow(("file_id", "file_path", "origin", "captured_at"))
                writer.writerow(
                    (
                        "service-export",
                        "evidence/service_export.json",
                        "fixture",
                        "2026-03-20T00:03:00Z",
                    )
                )

            normalized = normalize_evidence_index(
                EvidenceIndex.build(dataset_dir)
            )

        search_record = next(
            item
            for item in normalized.for_evidence("service-export")
            if item.fact.resource_id == "search_1"
        )
        self.assertEqual(search_record.fact.system_id, "search_service")
        self.assertEqual(search_record.fact.data_category, "SEARCH_INDEX_ENTRY")
        self.assertTrue(search_record.fact.confirms_presence)
        self.assertEqual(
            search_record.fact.observed_at,
            timestamp("2026-03-20T00:00:00Z"),
        )
        profile = next(
            item
            for item in normalized.for_evidence("service-export")
            if item.fact.resource_id == "account_1"
            and item.attributes.get("email") == "person@example.test"
        )
        self.assertEqual(profile.fact.system_id, "account_service")
        self.assertEqual(profile.fact.data_category, "USER_PROFILE")
        self.assertTrue(profile.fact.confirms_presence)
        lookup_404 = next(
            item
            for item in normalized.for_evidence("service-export")
            if item.fact.resource_id == "account_2"
        )
        self.assertFalse(lookup_404.fact.confirms_presence)
        self.assertFalse(lookup_404.fact.confirms_absence)

    def test_json_snapshot_container_contract_maps_child_records(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_dir = Path(temp_dir)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "snapshot.json").write_text(
                json.dumps(
                    {
                        "snapshots": [
                            {
                                "captured_at": "2026-03-20T00:00:00Z",
                                "data_store": "account_service",
                                "collection": "customer_profiles",
                                "records": [
                                    {
                                        "resource_id": "account_1",
                                        "customer_reference": "user_1",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (dataset_dir / "evidence_files.csv").open(
                "w", encoding="utf-8", newline=""
            ) as manifest:
                writer = csv.writer(manifest)
                writer.writerow(("file_id", "file_path", "origin", "captured_at"))
                writer.writerow(
                    (
                        "snapshot",
                        "evidence/snapshot.json",
                        "fixture",
                        "2026-03-20T00:05:00Z",
                    )
                )

            normalized = normalize_evidence_index(
                EvidenceIndex.build(dataset_dir)
            )
            record = next(
                item
                for item in normalized.for_evidence("snapshot")
                if item.fact.resource_id == "account_1"
            )
            contracts = derive_snapshot_contracts(
                dataset_dir, normalized, timestamp("2026-04-01T00:00:00Z")
            )
            before_capture = normalized.at_cutoff(
                timestamp("2026-03-20T00:00:04Z")
            )

        self.assertEqual(record.fact.system_id, "account_service")
        self.assertEqual(record.fact.data_category, "USER_PROFILE")
        self.assertTrue(record.fact.confirms_presence)
        self.assertEqual(record.attributes["data_store"], "account_service")
        self.assertEqual(record.attributes["collection"], "customer_profiles")
        self.assertEqual(
            record.fact.provenance.record_locator,
            "$.snapshots[0].records[0]",
        )
        self.assertEqual(
            record.fact.observed_at, timestamp("2026-03-20T00:00:00Z")
        )
        self.assertEqual(contracts, tuple())
        self.assertEqual(before_capture.eligible, tuple())
        self.assertIn(record, before_capture.excluded)

    def test_unknown_json_collection_is_not_assigned_a_policy_category(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_dir = Path(temp_dir)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "snapshot.json").write_text(
                json.dumps(
                    {
                        "snapshots": [
                            {
                                "data_store": "order_service",
                                "collection": "retained_order_records",
                                "records": [{"resource_id": "order_1"}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (dataset_dir / "evidence_files.csv").open(
                "w", encoding="utf-8", newline=""
            ) as manifest:
                writer = csv.writer(manifest)
                writer.writerow(("file_id", "file_path", "origin", "captured_at"))
                writer.writerow(
                    (
                        "snapshot",
                        "evidence/snapshot.json",
                        "fixture",
                        "2026-03-20T00:05:00Z",
                    )
                )

            record = next(
                item
                for item in normalize_evidence_index(
                    EvidenceIndex.build(dataset_dir)
                ).for_evidence("snapshot")
                if item.fact.resource_id == "order_1"
            )

        self.assertEqual(record.fact.system_id, "order_service")
        self.assertIsNone(record.fact.data_category)
        self.assertEqual(record.fact.inspection_status, InspectionStatus.INCONCLUSIVE)

    def test_successful_extraction_alone_does_not_declare_completeness(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_dir = Path(temp_dir)
            sql_path = dataset_dir / "evidence" / "inventory.sql"
            sql_path.parent.mkdir()
            sql_path.write_text(
                "CREATE TABLE customer_profiles (resource_id TEXT);",
                encoding="utf-8",
            )
            index = EvidenceIndex(
                tuple(),
                (
                    report(
                        evidence_id="inventory",
                        source_path="evidence/inventory.sql",
                    ),
                ),
            )

            contracts = derive_snapshot_contracts(
                dataset_dir, index, timestamp("2026-04-01T00:00:00Z")
            )

        self.assertEqual(contracts, tuple())

    def test_completed_snapshot_requires_explicit_table_and_system_scope(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_dir = Path(temp_dir)
            sql_path = dataset_dir / "evidence" / "inventory.sql"
            sql_path.parent.mkdir()
            sql_path.write_text(
                "\n".join(
                    (
                        "CREATE TABLE snapshot_scope (origin_system TEXT, captured_at TEXT);",
                        "CREATE TABLE customer_profiles (resource_id TEXT);",
                        "CREATE TABLE customer_search_documents (resource_id TEXT);",
                        "INSERT INTO snapshot_scope VALUES ('account_service', '2026-03-20T00:00:00Z');",
                        "-- snapshot_completed_at=2026-03-20T00:00:00Z",
                    )
                ),
                encoding="utf-8",
            )
            index = EvidenceIndex(
                tuple(),
                (
                    report(
                        evidence_id="inventory",
                        source_path="evidence/inventory.sql",
                        captured_at="2026-03-20T00:00:00Z",
                    ),
                ),
            )

            contracts = derive_snapshot_contracts(
                dataset_dir, index, timestamp("2026-04-01T00:00:00Z")
            )

        self.assertEqual(
            [(item.system_id, item.data_category) for item in contracts],
            [("account_service", "USER_PROFILE")],
        )
        self.assertEqual(contracts[0].evidence_id, "inventory")

    def test_complete_source_is_bound_to_the_subject_resource_and_category(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_dir = Path(temp_dir)
            sql_path = dataset_dir / "evidence" / "inventory.sql"
            sql_path.parent.mkdir()
            sql_path.write_text(
                "\n".join(
                    (
                        "CREATE TABLE snapshot_scope (origin_system TEXT, captured_at TEXT);",
                        "CREATE TABLE customer_profiles (resource_id TEXT);",
                        "INSERT INTO snapshot_scope VALUES ('account_service', '2026-03-20T00:00:00Z');",
                        "-- snapshot_completed_at=2026-03-20T00:00:00Z",
                    )
                ),
                encoding="utf-8",
            )
            profile = evidence_record(
                evidence_id="profile",
                attributes={
                    "user_id": "user_1",
                    "resource_id": "account_1",
                    "email": "person@example.test",
                },
                metadata={"table_name": "customer_profiles"},
            )
            index = EvidenceIndex(
                (profile,),
                (
                    report(
                        evidence_id="profile",
                        source_path="evidence/profile.json",
                    ),
                    report(
                        evidence_id="inventory",
                        source_path="evidence/inventory.sql",
                        captured_at="2026-03-20T00:00:00Z",
                    ),
                ),
            )
            request_value = request()
            resolver = identity_resolver(request_value.email)
            result = ground_request_evidence(
                request_value,
                resolver.resolve_request(request_value),
                resolver,
                index,
                tuple(),
                dataset_dir,
            )

        self.assertEqual(len(result.expected_scopes), 1)
        scope = result.expected_scopes[0]
        self.assertEqual(
            (scope.system_id, scope.resource_id, scope.data_category),
            ("account_service", "account_1", "USER_PROFILE"),
        )
        self.assertEqual(scope.complete_evidence_ids, ("inventory",))
        self.assertEqual(result.ledger.groups[0].status.value, "INCONCLUSIVE")

    def test_incomplete_or_late_snapshot_cannot_ground_coverage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_dir = Path(temp_dir)
            sql_path = dataset_dir / "evidence" / "inventory.sql"
            sql_path.parent.mkdir()
            sql_path.write_text(
                "\n".join(
                    (
                        "CREATE TABLE snapshot_scope (origin_system TEXT, captured_at TEXT);",
                        "CREATE TABLE customer_profiles (resource_id TEXT);",
                        "INSERT INTO snapshot_scope VALUES ('account_service', '2026-03-20T00:00:00Z');",
                        "-- snapshot_completed_at=2026-03-20T00:00:00Z",
                    )
                ),
                encoding="utf-8",
            )
            partial_index = EvidenceIndex(
                tuple(),
                (
                    report(
                        evidence_id="inventory",
                        status=ExtractionStatus.PARTIAL,
                        source_path="evidence/inventory.sql",
                        captured_at="2026-03-20T00:00:00Z",
                    ),
                ),
            )
            complete_index = EvidenceIndex(
                tuple(),
                (
                    report(
                        evidence_id="inventory",
                        source_path="evidence/inventory.sql",
                        captured_at="2026-03-20T00:00:00Z",
                    ),
                ),
            )

            partial = derive_snapshot_contracts(
                dataset_dir,
                partial_index,
                timestamp("2026-04-01T00:00:00Z"),
            )
            late = derive_snapshot_contracts(
                dataset_dir,
                complete_index,
                timestamp("2026-03-19T23:59:59Z"),
            )

        self.assertEqual(partial, tuple())
        self.assertEqual(late, tuple())

    def test_sql_table_and_nested_json_contracts_add_explicit_category(self):
        table_row = evidence_record(
            attributes={
                "resource_id": "account_1",
                "customer_reference": "user_1",
                "email": "person@example.test",
            },
            metadata={"table_name": "customer_profiles"},
        )
        nested_row = evidence_record(
            evidence_id="replica",
            attributes={
                "resource_id": "search_1",
                "origin_system": "search_service",
                "collection_name": "customer_search_documents",
                "record_json": json.dumps(
                    {"document": {"email": "person@example.test"}}
                ),
            },
            metadata={"table_name": "customer_data_primary"},
        )
        telemetry_row = evidence_record(
            evidence_id="telemetry",
            attributes={
                "resource_id": "telemetry_1",
                "origin_system": "analytics_platform",
                "collection_name": "customer_analytics_reports",
                "reporting_window": "last_90_days",
                "email": "person@example.test",
            },
            metadata={"table_name": "customer_data_primary"},
        )
        index = normalize_evidence_index(
            EvidenceIndex(
                (table_row, nested_row, telemetry_row),
                (
                    report(),
                    report(
                        evidence_id="replica",
                        source_path="evidence/replica.sql",
                    ),
                    report(
                        evidence_id="telemetry",
                        source_path="evidence/telemetry.sql",
                    ),
                ),
            )
        )

        by_id = {record.evidence_id: record for record in index.records}
        self.assertEqual(by_id["evidence-test"].fact.system_id, "account_service")
        self.assertEqual(by_id["evidence-test"].fact.data_category, "USER_PROFILE")
        self.assertEqual(by_id["replica"].fact.system_id, "search_service")
        self.assertEqual(
            by_id["replica"].fact.data_category, "SEARCH_INDEX_ENTRY"
        )
        self.assertEqual(
            by_id["telemetry"].fact.data_category, "PRODUCT_TELEMETRY"
        )
        self.assertEqual(
            by_id["replica"].attributes["document_email"],
            "person@example.test",
        )

    def test_parsed_sql_row_proves_presence_at_snapshot_capture(self):
        source = evidence_record(
            evidence_id="snapshot-row",
            attributes={
                "resource_id": "account_1",
                "user_id": "user_1",
                "email": "person@example.test",
            },
            available_at="2026-03-20T00:00:00Z",
        )
        from dataclasses import replace

        sql_row = replace(
            source,
            extraction_method="sqlite-table-row",
            metadata_json=json.dumps({"table_name": "customer_profiles"}),
        )
        normalized = normalize_evidence_index(
            EvidenceIndex(
                (sql_row,),
                (report("snapshot-row", source_path="evidence/snapshot.sql"),),
            )
        ).records[0]

        self.assertEqual(normalized.fact.observed_state, "PRESENT")
        self.assertEqual(
            normalized.fact.inspection_status,
            InspectionStatus.CONFIRMED,
        )
        self.assertEqual(
            normalized.fact.observed_at,
            source.fact.observed_at,
        )

    def test_activity_needs_a_resolved_subject_and_explicit_resource_link(self):
        request_value = request()
        resolver = identity_resolver(request_value.email)
        resolution = resolver.resolve_request(request_value)
        linked = activity(
            "activity-link",
            "LINK_RESOURCE_IDENTITY",
            "account_1",
            details=(
                "Data catalog linked account_1 (account_1) to "
                "person@example.test and user_1."
            ),
        )
        deletion = activity(
            "activity-delete",
            "DELETE_RECORD",
            "account_1",
            details="Deletion worker submitted account_1.",
        )
        unrelated = activity(
            "activity-unrelated", "DELETE_RECORD", "account_2"
        )
        index = EvidenceIndex(tuple(), tuple())

        result = ground_request_evidence(
            request_value,
            resolution,
            resolver,
            index,
            (unrelated, deletion, linked),
            Path("."),
        )

        self.assertEqual(result.subject_user_id, "user_1")
        self.assertEqual(
            {item.activity.activity_id for item in result.activity},
            {"activity-link", "activity-delete"},
        )
        deletion_result = next(
            item for item in result.activity if item.activity.activity_id == "activity-delete"
        )
        self.assertEqual(deletion_result.kind, ActivityKind.OPERATIONAL_CLAIM)
        self.assertEqual(
            deletion_result.supporting_evidence_ids, ("activity-link",)
        )

    def test_activity_is_cut_off_at_audit_time_and_ambiguous_identity_is_not_used(self):
        request_value = request()
        resolver = identity_resolver(request_value.email)
        resolution = resolver.resolve_request(request_value)
        link = activity(
            "activity-link",
            "LINK_RESOURCE_IDENTITY",
            "account_1",
            details=(
                "Data catalog linked account_1 (account_1) to "
                "person@example.test and user_1."
            ),
        )
        later = activity(
            "activity-later",
            "DELETE_RECORD",
            "account_1",
            event_time="2026-04-01T00:00:00.000001Z",
        )
        boundary = activity(
            "activity-boundary",
            "CHECK_DATA_FLOW",
            "account_1",
            event_time="2026-04-01T00:00:00Z",
        )
        index = EvidenceIndex(tuple(), tuple())
        grounded = ground_request_evidence(
            request_value,
            resolution,
            resolver,
            index,
            (link, later, boundary),
            Path("."),
        )
        self.assertEqual(
            next(
                item
                for item in grounded.activity
                if item.activity.activity_id == "activity-boundary"
            ).temporal_disposition,
            TemporalDisposition.ELIGIBLE,
        )
        self.assertEqual(
            next(
                item
                for item in grounded.activity
                if item.activity.activity_id == "activity-later"
            )
            .temporal_disposition,
            TemporalDisposition.EXCLUDED,
        )
        ambiguous_resolver = identity_resolver(
            request_value.email, request_value.email
        )
        ambiguous_resolution = ambiguous_resolver.resolve_request(request_value)
        ambiguous = ground_request_evidence(
            request_value,
            ambiguous_resolution,
            ambiguous_resolver,
            index,
            (link, later, boundary),
            Path("."),
        )
        self.assertEqual(
            ambiguous.identity_status, IdentityLinkResolutionStatus.AMBIGUOUS
        )
        self.assertIsNone(ambiguous.subject_user_id)
        self.assertEqual(ambiguous.activity, tuple())
        self.assertEqual(ambiguous.ledger.eligible, tuple())

    def test_customer_export_row_uses_exact_activity_target_for_system_link(self):
        request_value = request()
        record = evidence_record(
            attributes={
                "collection": "customer_export_jobs",
                "owner_email": request_value.email,
                "resource_id": "export_1",
                "download_available": True,
            },
            metadata={"container_path": "$.records[0]"},
        )
        index = EvidenceIndex(
            (record,),
            (
                report(
                    record.evidence_id,
                    source_path=record.source_path,
                ),
            ),
        )
        target_activity = activity(
            "activity-export-delete",
            "DELETE_RECORD",
            "export_1",
            target_system="export_service",
            details="Deletion failed. Target resource: export_1.",
        )

        grounded = ground_request_evidence(
            request_value,
            identity_resolver(request_value.email).resolve_request(
                request_value
            ),
            identity_resolver(request_value.email),
            index,
            (target_activity,),
            Path("."),
        )

        self.assertEqual(len(grounded.ledger.groups), 1)
        group = grounded.ledger.groups[0]
        self.assertEqual(group.system_id, "export_service")
        self.assertEqual(group.resource_id, "export_1")
        self.assertEqual(group.data_category, "USER_EXPORT")
        self.assertEqual(group.status, CoverageStatus.CONFIRMED_PRESENT)
        self.assertEqual(grounded.ledger.eligible[0].evidence_id, record.evidence_id)
        self.assertEqual(
            grounded.activity[0].activity.activity_id,
            "activity-export-delete",
        )

    def test_activity_system_link_rejects_late_and_ambiguous_targets(self):
        request_value = request()
        record = evidence_record(
            attributes={
                "collection": "customer_export_jobs",
                "owner_email": request_value.email,
                "resource_id": "export_1",
            },
            metadata={"container_path": "$.records[0]"},
        )
        index = EvidenceIndex(
            (record,),
            (report(record.evidence_id, source_path=record.source_path),),
        )
        resolver = identity_resolver(request_value.email)
        resolution = resolver.resolve_request(request_value)
        late_activity = activity(
            "activity-late",
            "DELETE_RECORD",
            "export_1",
            target_system="export_service",
            event_time="2026-04-01T00:00:00.000001Z",
            details="Deletion failed. Target resource: export_1.",
        )
        late_grounded = ground_request_evidence(
            request_value,
            resolution,
            resolver,
            index,
            (late_activity,),
            Path("."),
        )
        self.assertIsNone(late_grounded.ledger.groups[0].system_id)

        ambiguous_grounded = ground_request_evidence(
            request_value,
            resolution,
            resolver,
            index,
            (
                activity(
                    "activity-target-a",
                    "DELETE_RECORD",
                    "export_1",
                    target_system="export_service",
                    details="Target resource: export_1.",
                ),
                activity(
                    "activity-target-b",
                    "DELETE_RECORD",
                    "export_1",
                    target_system="archive_service",
                    details="Target resource: export_1.",
                ),
            ),
            Path("."),
        )
        self.assertIsNone(ambiguous_grounded.ledger.groups[0].system_id)

    def test_exact_log_event_mapping_sets_category_without_confirming_state(self):
        record = evidence_record(
            evidence_id="support-log",
            attributes={
                "service": "support_platform",
                "event": "support_ticket_read_completed",
                "resource_id": "support_14",
                "requester_email": "person@example.test",
            },
        )
        record = replace(record, extraction_method="log-key-value")

        normalized = normalize_evidence_index(
            EvidenceIndex((record,), (report(),))
        ).for_evidence("support-log")[0]

        self.assertEqual(normalized.fact.system_id, "support_platform")
        self.assertEqual(normalized.fact.data_category, "SUPPORT_MESSAGE")
        self.assertEqual(normalized.fact.resource_id, "support_14")
        self.assertIsNone(normalized.fact.observed_state)
        self.assertEqual(
            normalized.fact.inspection_status.value, "INCONCLUSIVE"
        )

    def test_unknown_log_event_does_not_inherit_category_from_service_name(self):
        record = evidence_record(
            evidence_id="unknown-service-log",
            attributes={
                "service": "support_platform",
                "event": "arbitrary_operation",
                "resource_id": "record_14",
            },
        )
        record = replace(record, extraction_method="log-key-value")

        normalized = normalize_evidence_index(
            EvidenceIndex((record,), (report(),))
        ).for_evidence("unknown-service-log")[0]

        self.assertIsNone(normalized.fact.data_category)


if __name__ == "__main__":
    unittest.main()
