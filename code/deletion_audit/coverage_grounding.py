"""Ground request-scoped resource coverage and activity attribution."""

import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, Mapping, Optional, Tuple

from .evidence_index import (
    EvidenceIndex,
    ExtractionStatus,
)
from .evidence_reconciliation import (
    ExpectedResourceScope,
    RequestCoverageLedger,
    TemporalDisposition,
    reconcile_request,
)
from .identity_links import (
    IdentityLinkConfidence,
    IdentityLinkResolution,
    IdentityLinkResolutionStatus,
    IdentityLinkResolver,
    IdentifierType,
)
from .models import DeletionRequest, InspectionStatus, SystemActivity
from .temporal import parse_timestamp


class ActivityKind(str, Enum):
    IDENTITY_LINK = "IDENTITY_LINK"
    DATA_FLOW = "DATA_FLOW"
    RESTORE_RISK = "RESTORE_RISK"
    OPERATIONAL_CLAIM = "OPERATIONAL_CLAIM"
    WORKFLOW_CLAIM = "WORKFLOW_CLAIM"


@dataclass(frozen=True)
class SnapshotSourceContract:
    evidence_id: str
    source_path: str
    system_id: str
    data_category: str
    table_name: str
    completed_at: datetime
    captured_at: datetime


@dataclass(frozen=True)
class GroundedActivity:
    activity: SystemActivity
    kind: ActivityKind
    temporal_disposition: TemporalDisposition
    system_id: str
    resource_id: str
    supporting_evidence_ids: Tuple[str, ...]
    attribution_source: str
    related_system_id: Optional[str] = None
    related_resource_id: Optional[str] = None


@dataclass(frozen=True)
class GroundedRequestEvidence:
    case_id: str
    identity_status: IdentityLinkResolutionStatus
    subject_user_id: Optional[str]
    ledger: RequestCoverageLedger
    snapshot_contracts: Tuple[SnapshotSourceContract, ...]
    expected_scopes: Tuple[ExpectedResourceScope, ...]
    activity: Tuple[GroundedActivity, ...]


class EvidenceGrounder:
    """Reuse one normalized evidence index and source-contract inventory."""

    def __init__(
        self,
        dataset_dir: Path,
        evidence_index: EvidenceIndex,
        identity_resolver: IdentityLinkResolver,
        system_activity: Iterable[SystemActivity],
    ) -> None:
        self.dataset_dir = Path(dataset_dir)
        self.evidence_index = normalize_evidence_index(evidence_index)
        self.identity_resolver = identity_resolver
        self.system_activity = tuple(system_activity)
        self.snapshot_contracts = derive_snapshot_contracts(
            self.dataset_dir,
            self.evidence_index,
            datetime.max.replace(tzinfo=timezone.utc),
        )

    def ground(
        self,
        request: DeletionRequest,
        identity_resolution: IdentityLinkResolution,
    ) -> GroundedRequestEvidence:
        return _ground_with_context(
            request,
            identity_resolution,
            self.identity_resolver,
            self.evidence_index,
            self.system_activity,
            self.snapshot_contracts,
        )


_TABLE_CONTRACTS: Mapping[str, Tuple[str, str]] = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW_CONFIGURATION"),
}
_COLLECTION_CONTRACTS: Mapping[str, str] = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "customer_analytics_reports": "PRODUCT_TELEMETRY",
    "support_records": "SUPPORT_MESSAGE",
    "support_conversations": "SUPPORT_MESSAGE",
    "customer_exports": "USER_EXPORT",
    "customer_export_jobs": "USER_EXPORT",
    "marketing_profiles": "MARKETING_PROFILE",
    "secondary_identifiers": "SECONDARY_IDENTIFIER",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "cache_entries": "CACHE_ENTRY",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "backup_catalog": "BACKUP_ARCHIVE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "connector_configurations": "DATA_FLOW_CONFIGURATION",
}
_TABLE_PATTERN = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`\[]?"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_SNAPSHOT_COMPLETION_PATTERN = re.compile(
    r"(?im)^\s*--\s*snapshot_completed_at\s*=\s*(\S+)\s*$"
)
_SNAPSHOT_SCOPE_PATTERN = re.compile(
    r"""INSERT\s+INTO\s+["`]?snapshot_scope["`]?\s+VALUES\s*
    \(\s*'((?:''|[^'])*)'\s*,\s*'((?:''|[^'])*)'\s*\)""",
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)
_EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
_USER_ID_PATTERN = re.compile(r"\buser_[A-Za-z0-9_-]+\b", re.IGNORECASE)
_DOWNSTREAM_RESOURCE_PATTERN = re.compile(
    r"\bdownstream\s+resource\s+([A-Za-z0-9_-]+)\b", re.IGNORECASE
)
_SERVICE_EXPORT_PATH_PATTERN = re.compile(
    r"^\$\.service_exports\.([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)"
)
_SERVICE_EXPORT_COLLECTIONS: Mapping[Tuple[str, str], str] = {
    ("account_service", "profile_lookups"): "USER_PROFILE",
    ("analytics_platform", "profiles"): "ANALYTICS_PROFILE",
    ("backup_service", "restore_entries"): "BACKUP_ARCHIVE",
    ("export_service", "exports"): "USER_EXPORT",
    ("security_service", "audit_records"): "SECURITY_AUDIT_LOG",
    ("support_platform", "tickets"): "SUPPORT_MESSAGE",
}
_DIRECT_JSON_RESOURCE_COLLECTIONS = {"customer_export_jobs"}
_JSON_RECORD_PATH = re.compile(r"^\$\.records\[\d+\]$")
_LOG_EVENT_CATEGORIES: Mapping[Tuple[str, str], str] = {
    ("account_service", "profile_lookup_completed"): "USER_PROFILE",
    ("analytics_platform", "analytics_identity_scan"): "ANALYTICS_PROFILE",
    ("analytics_platform", "analytics_profile_read"): "ANALYTICS_PROFILE",
    ("analytics_platform", "analytics_profile_read_completed"): "ANALYTICS_PROFILE",
    ("analytics_platform", "analytics_profile_read_started"): "ANALYTICS_PROFILE",
    ("analytics_platform", "analytics_profile_scan_started"): "ANALYTICS_PROFILE",
    ("backup_service", "restore_authorization_completed"): "BACKUP_ARCHIVE",
    ("backup_service", "restore_candidate_evaluated"): "BACKUP_ARCHIVE",
    ("backup_service", "restore_policy_read_completed"): "BACKUP_ARCHIVE",
    ("backup_service", "restore_policy_read_started"): "BACKUP_ARCHIVE",
    ("export_service", "export_download_check_completed"): "USER_EXPORT",
    ("export_service", "export_metadata_read_completed"): "USER_EXPORT",
    ("export_service", "export_metadata_read_started"): "USER_EXPORT",
    ("integration_service", "connector_config_loaded"): "DATA_FLOW_CONFIGURATION",
    ("integration_service", "connector_config_read_completed"): "DATA_FLOW_CONFIGURATION",
    ("integration_service", "connector_config_read_started"): "DATA_FLOW_CONFIGURATION",
    ("integration_service", "connector_heartbeat"): "DATA_FLOW_CONFIGURATION",
    ("legal_service", "retained_order_loaded"): "LEGAL_HOLD_RECORD",
    ("search_index_service", "record_lookup"): "SEARCH_INDEX_ENTRY",
    ("search_service", "index_query_completed"): "SEARCH_INDEX_ENTRY",
    ("security_service", "audit_record_read_completed"): "SECURITY_AUDIT_LOG",
    ("support_platform", "attachment_pii_scan"): "SUPPORT_ATTACHMENT",
    ("support_platform", "message_pii_scan"): "SUPPORT_MESSAGE",
    ("support_platform", "message_read"): "SUPPORT_MESSAGE",
    ("support_platform", "support_ticket_read_completed"): "SUPPORT_MESSAGE",
    ("support_platform", "support_ticket_read_started"): "SUPPORT_MESSAGE",
}


def normalize_evidence_index(evidence_index: EvidenceIndex) -> EvidenceIndex:
    """Add only table/category relationships explicit in indexed SQL schemas."""

    reports_by_id = {
        report.evidence_id: report for report in evidence_index.report
    }
    normalized = []
    for record in evidence_index.records:
        attributes = dict(record.attributes)
        metadata = record.metadata
        table_name = str(metadata.get("table_name", ""))
        table_contract = _TABLE_CONTRACTS.get(table_name)
        system_id = record.fact.system_id
        data_category = record.fact.data_category
        service_path_match = _SERVICE_EXPORT_PATH_PATTERN.match(
            str(metadata.get("container_path", ""))
        )
        service_resource_record = False
        if service_path_match is not None:
            service_id, collection_name = service_path_match.groups()
            service_category = _SERVICE_EXPORT_COLLECTIONS.get(
                (service_id, collection_name)
            )
            is_search_document = (
                service_id == "search_service"
                and collection_name == "index_queries"
                and ".hits.documents[" in str(metadata.get("container_path", ""))
            )
            if service_category or is_search_document:
                system_id = system_id or service_id
                data_category = data_category or (
                    service_category or "SEARCH_INDEX_ENTRY"
                )
                service_resource_record = (
                    record.fact.resource_id is not None
                    and record.fact.observed_at is not None
                    and (
                        not (
                            service_id == "account_service"
                            and collection_name == "profile_lookups"
                        )
                        or str(attributes.get("status_code", "")) == "200"
                    )
                    and (
                        not is_search_document
                        or ".hits.documents[" in str(
                            metadata.get("container_path", "")
                        )
                    )
                )
        if table_contract is not None:
            system_id = system_id or table_contract[0]
            data_category = data_category or table_contract[1]
        elif table_name in {
            "customer_data_primary",
            "customer_data_read_replica",
            "customer_data_replica_ap_south",
            "customer_data_replica_eu_west",
            "customer_data_reporting_replica",
            "customer_data_failover_replica",
        }:
            system_id = system_id or _string_value(attributes.get("origin_system"))

        record_json = attributes.get("record_json")
        if isinstance(record_json, str):
            try:
                nested = json.loads(record_json)
            except (TypeError, ValueError):
                nested = None
            if isinstance(nested, dict):
                _flatten_scalars(nested, "", attributes)

        collection = attributes.get("collection_name") or attributes.get("collection")
        if data_category is None and isinstance(collection, str):
            data_category = _COLLECTION_CONTRACTS.get(collection)
        data_category = data_category or _string_value(
            attributes.get("data_category")
        )
        if data_category is None and record.extraction_method.startswith("log-"):
            service = _string_value(
                attributes.get("service") or attributes.get("logger")
            )
            event = _string_value(attributes.get("event"))
            if service and event:
                data_category = _LOG_EVENT_CATEGORIES.get(
                    (service.casefold(), event.casefold())
                )
        system_id = (
            system_id
            or _string_value(attributes.get("system_id"))
            or _string_value(attributes.get("service"))
            or _string_value(attributes.get("logger"))
            or _string_value(attributes.get("data_store"))
        )
        resource_id = record.fact.resource_id or _string_value(
            attributes.get("resource_id")
        )
        subject_user_id = record.fact.subject_user_id or _string_value(
            attributes.get("user_id")
        )
        fact = record.fact
        report = reports_by_id.get(record.evidence_id)
        if (
            record.extraction_method == "sqlite-table-row"
            and report is not None
            and PurePosixPath(report.source_path).suffix.casefold() == ".sql"
        ):
            fact = replace(
                fact,
                observed_state="PRESENT",
                inspection_status=InspectionStatus.CONFIRMED,
            )
        if (
            metadata.get("snapshot_record") is True
            and report is not None
            and PurePosixPath(report.source_path).suffix.casefold() == ".json"
            and fact.observed_at is not None
        ):
            fact = replace(
                fact,
                observed_state="PRESENT",
                inspection_status=InspectionStatus.CONFIRMED,
            )
        if (
            service_resource_record
            and report is not None
            and PurePosixPath(report.source_path).suffix.casefold() == ".json"
        ):
            metadata = dict(metadata)
            metadata["service_resource_record"] = True
            fact = replace(
                fact,
                observed_state="PRESENT",
                inspection_status=InspectionStatus.CONFIRMED,
            )
        if (
            collection in _DIRECT_JSON_RESOURCE_COLLECTIONS
            and data_category == "USER_EXPORT"
            and record.extraction_method == "json-object-path"
            and _JSON_RECORD_PATH.match(
                str(metadata.get("container_path", ""))
            )
            and report is not None
            and report.status == ExtractionStatus.SUCCESS
            and report.source_path.casefold().endswith(".json")
            and resource_id is not None
            and fact.observed_at is not None
        ):
            fact = replace(
                fact,
                observed_state="PRESENT",
                inspection_status=InspectionStatus.CONFIRMED,
            )
        if (
            system_id == record.fact.system_id
            and resource_id == record.fact.resource_id
            and data_category == record.fact.data_category
            and subject_user_id == record.fact.subject_user_id
            and attributes == record.attributes
            and fact == record.fact
        ):
            normalized.append(record)
            continue
        identifiers = set(record.identifiers)
        for key, value in attributes.items():
            if (
                isinstance(value, str)
                and key.casefold() in {"email", "phone", "email_hash"}
            ):
                identifiers.add((key, value))
        fact = replace(
            fact,
            system_id=system_id,
            resource_id=resource_id,
            data_category=data_category,
            subject_user_id=subject_user_id,
        )
        normalized.append(
            replace(
                record,
                fact=fact,
                attributes_json=json.dumps(
                    attributes,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                identifiers=tuple(sorted(identifiers)),
            )
        )
    return EvidenceIndex(
        normalized,
        evidence_index.report,
        cache_hits=evidence_index.cache_hits,
        cache_misses=evidence_index.cache_misses,
    )


def derive_snapshot_contracts(
    dataset_dir: Path,
    evidence_index: EvidenceIndex,
    audit_at: datetime,
) -> Tuple[SnapshotSourceContract, ...]:
    """Recognize only completed, scoped SQL inventory snapshots.

    A successful extraction is necessary but not sufficient: the SQL source
    must declare a completion timestamp and per-system snapshot_scope rows.
    """

    dataset_dir = Path(dataset_dir).resolve()
    contracts = []
    for report in evidence_index.report:
        if report.status != ExtractionStatus.SUCCESS:
            continue
        relative_path = PurePosixPath(report.source_path)
        source_path = (dataset_dir / Path(*relative_path.parts)).resolve()
        try:
            source_path.relative_to(dataset_dir)
        except ValueError:
            continue
        if source_path.suffix.casefold() != ".sql":
            continue
        try:
            text = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        completion_match = _SNAPSHOT_COMPLETION_PATTERN.search(text)
        if completion_match is None:
            continue
        try:
            completed_at = parse_timestamp(
                completion_match.group(1), "snapshot completion"
            )
            captured_at = parse_timestamp(report.captured_at, "evidence capture")
        except ValueError:
            continue
        if completed_at > audit_at or captured_at > audit_at:
            continue
        table_names = set(_TABLE_PATTERN.findall(text))
        scopes = {}
        for raw_system, raw_captured_at in _SNAPSHOT_SCOPE_PATTERN.findall(text):
            system_id = raw_system.replace("''", "'").strip()
            try:
                scope_time = parse_timestamp(
                    raw_captured_at.replace("''", "'"), "snapshot scope time"
                )
            except ValueError:
                continue
            if scope_time == completed_at and scope_time <= audit_at:
                scopes[system_id] = scope_time
        for table_name in sorted(table_names):
            table_contract = _TABLE_CONTRACTS.get(table_name)
            if table_contract is None:
                continue
            system_id, data_category = table_contract
            if system_id not in scopes:
                continue
            contracts.append(
                SnapshotSourceContract(
                    evidence_id=report.evidence_id,
                    source_path=report.source_path,
                    system_id=system_id,
                    data_category=data_category,
                    table_name=table_name,
                    completed_at=completed_at,
                    captured_at=captured_at,
                )
            )
    return tuple(
        sorted(
            contracts,
            key=lambda item: (
                item.system_id,
                item.data_category,
                item.completed_at,
                item.evidence_id,
            ),
        )
    )


def ground_request_evidence(
    request: DeletionRequest,
    identity_resolution: IdentityLinkResolution,
    identity_resolver: IdentityLinkResolver,
    evidence_index: EvidenceIndex,
    system_activity: Iterable[SystemActivity],
    dataset_dir: Path,
) -> GroundedRequestEvidence:
    """Build a request ledger and include only evidence-backed activity links."""

    grounder = EvidenceGrounder(
        dataset_dir, evidence_index, identity_resolver, system_activity
    )
    return grounder.ground(request, identity_resolution)


def _ground_with_context(
    request: DeletionRequest,
    identity_resolution: IdentityLinkResolution,
    identity_resolver: IdentityLinkResolver,
    index: EvidenceIndex,
    system_activity: Iterable[SystemActivity],
    all_snapshot_contracts: Tuple[SnapshotSourceContract, ...],
) -> GroundedRequestEvidence:
    verified_resolution = identity_resolver.resolve_request(request)
    if identity_resolution.status != IdentityLinkResolutionStatus.RESOLVED:
        effective_status = identity_resolution.status
    elif verified_resolution.status != IdentityLinkResolutionStatus.RESOLVED:
        effective_status = verified_resolution.status
    elif identity_resolution.user_id != verified_resolution.user_id:
        effective_status = IdentityLinkResolutionStatus.AMBIGUOUS
    else:
        effective_status = IdentityLinkResolutionStatus.RESOLVED
    user_id = (
        verified_resolution.user_id
        if effective_status == IdentityLinkResolutionStatus.RESOLVED
        else None
    )
    if user_id is None:
        ledger = reconcile_request(request, index)
        return GroundedRequestEvidence(
            case_id=request.case_id,
            identity_status=effective_status,
            subject_user_id=None,
            ledger=ledger,
            snapshot_contracts=tuple(),
            expected_scopes=tuple(),
            activity=tuple(),
        )

    links = tuple(
        link
        for link in identity_resolver.links_for_user(user_id)
        if link.confidence == IdentityLinkConfidence.STRONG
        and link.is_known_at(request.audit_at)
    )
    identifiers: Dict[str, set] = {}
    for link in links:
        identifiers.setdefault(link.identifier_type.value, set()).add(
            link.normalized_value
        )

    observed_ledger = reconcile_request(
        request,
        index,
        subject_user_id=user_id,
        subject_identifiers=identifiers,
        identity_links=links,
    )
    resource_system_links = _activity_target_system_links(
        observed_ledger.eligible,
        system_activity,
        request.audit_at,
    )
    if resource_system_links:
        index = _index_with_activity_system_links(
            index,
            resource_system_links,
            observed_ledger.eligible,
        )
        observed_ledger = reconcile_request(
            request,
            index,
            subject_user_id=user_id,
            subject_identifiers=identifiers,
            identity_links=links,
        )
    contracts = tuple(
        contract
        for contract in all_snapshot_contracts
        if contract.completed_at <= request.audit_at
        and contract.captured_at <= request.audit_at
    )
    scopes = _expected_scopes(observed_ledger, contracts)
    ledger = reconcile_request(
        request,
        index,
        subject_user_id=user_id,
        subject_identifiers=identifiers,
        identity_links=links,
        expected_scopes=scopes,
    )
    activity = _attribute_activity(
        request,
        user_id,
        identity_resolver,
        system_activity,
        observed_ledger,
    )
    return GroundedRequestEvidence(
        case_id=request.case_id,
        identity_status=effective_status,
        subject_user_id=user_id,
        ledger=ledger,
        snapshot_contracts=contracts,
        expected_scopes=scopes,
        activity=activity,
    )


def _activity_target_system_links(
    observations,
    activity_rows: Iterable[SystemActivity],
    audit_at: datetime,
) -> Mapping[str, str]:
    resource_ids = {
        item.record.fact.resource_id
        for item in observations
        if item.record.fact.system_id is None
        and item.record.fact.resource_id
        and item.record.fact.data_category
        and item.kind.value == "DIRECT_RESOURCE_STATE"
    }
    systems_by_resource: Dict[str, set] = {}
    for row in activity_rows:
        resource_id = row.resource_id
        if (
            resource_id not in resource_ids
            or row.event_time > audit_at
            or not row.target_system.strip()
            or not _details_name_target_resource(row.details, resource_id)
        ):
            continue
        systems_by_resource.setdefault(resource_id, set()).add(row.target_system)
    return {
        resource_id: next(iter(systems))
        for resource_id, systems in systems_by_resource.items()
        if len(systems) == 1
    }


def _details_name_target_resource(details: str, resource_id: str) -> bool:
    pattern = r"\bTarget resource:\s*{}\s*(?:\.|$)".format(
        re.escape(resource_id)
    )
    return re.search(pattern, details, re.IGNORECASE) is not None


def _index_with_activity_system_links(
    evidence_index: EvidenceIndex,
    systems_by_resource: Mapping[str, str],
    observations,
) -> EvidenceIndex:
    eligible_record_keys = {
        (
            item.record.evidence_id,
            item.record.fact.provenance.record_locator,
            item.record.fact.resource_id,
        )
        for item in observations
        if item.record.fact.system_id is None
    }
    updated_records = []
    for record in evidence_index.records:
        fact = record.fact
        system_id = systems_by_resource.get(fact.resource_id or "")
        record_key = (
            record.evidence_id,
            fact.provenance.record_locator,
            fact.resource_id,
        )
        if (
            record_key in eligible_record_keys
            and fact.system_id is None
            and system_id
        ):
            record = replace(record, fact=replace(fact, system_id=system_id))
        updated_records.append(record)
    return EvidenceIndex(
        updated_records,
        evidence_index.report,
        cache_hits=evidence_index.cache_hits,
        cache_misses=evidence_index.cache_misses,
    )


def _expected_scopes(
    ledger: RequestCoverageLedger,
    contracts: Tuple[SnapshotSourceContract, ...],
) -> Tuple[ExpectedResourceScope, ...]:
    scopes = []
    for group in ledger.groups:
        if not group.system_id or not group.resource_id or not group.data_category:
            continue
        evidence_ids = tuple(
            sorted({item.evidence_id for item in group.observations})
        )
        complete_ids = tuple(
            sorted(
                contract.evidence_id
                for contract in contracts
                if contract.system_id == group.system_id
                and contract.data_category == group.data_category
            )
        )
        scopes.append(
            ExpectedResourceScope(
                system_id=group.system_id,
                resource_id=group.resource_id,
                data_category=group.data_category,
                complete_evidence_ids=complete_ids,
                evidence_ids=tuple(sorted(set(evidence_ids + complete_ids))),
            )
        )
    return tuple(scopes)


def _attribute_activity(
    request: DeletionRequest,
    user_id: str,
    identity_resolver: IdentityLinkResolver,
    activity_rows: Iterable[SystemActivity],
    ledger: RequestCoverageLedger,
) -> Tuple[GroundedActivity, ...]:
    linked_resources: Dict[Tuple[str, str], set] = {}
    for observation in ledger.eligible:
        fact = observation.record.fact
        if fact.system_id and fact.resource_id:
            linked_resources.setdefault(
                (fact.system_id, fact.resource_id), set()
            ).add(observation.evidence_id)

    rows = tuple(sorted(activity_rows, key=lambda item: (item.event_time, item.activity_id)))
    grounded = []
    for row in rows:
        if row.event_time > request.audit_at or row.event_type != "LINK_RESOURCE_IDENTITY":
            continue
        linked_user_id = _linked_user_id(row, request, identity_resolver)
        if linked_user_id != user_id:
            continue
        resource_key = (row.target_system, row.resource_id)
        linked_resources.setdefault(resource_key, set()).add(row.activity_id)
        grounded.append(
            GroundedActivity(
                activity=row,
                kind=ActivityKind.IDENTITY_LINK,
                temporal_disposition=TemporalDisposition.ELIGIBLE,
                system_id=row.target_system,
                resource_id=row.resource_id,
                supporting_evidence_ids=(row.activity_id,),
                attribution_source="EXPLICIT_IDENTITY_LINK",
            )
        )

    for row in rows:
        if row.event_type == "LINK_RESOURCE_IDENTITY":
            continue
        pair_candidates = (
            (row.target_system, row.resource_id),
            (row.source_system, row.resource_id),
        )
        supporting_ids = set()
        resource_system = ""
        for pair in pair_candidates:
            if pair in linked_resources:
                resource_system = pair[0]
                supporting_ids.update(linked_resources[pair])
        if not supporting_ids:
            continue
        disposition = (
            TemporalDisposition.ELIGIBLE
            if row.event_time <= request.audit_at
            else TemporalDisposition.EXCLUDED
        )
        related_system_id = None
        related_resource_id = None
        if row.event_type == "RESTORE_BACKUP":
            match = _DOWNSTREAM_RESOURCE_PATTERN.search(row.details)
            if match and row.target_system:
                related_system_id = row.target_system
                related_resource_id = match.group(1)
        grounded.append(
            GroundedActivity(
                activity=row,
                kind=_activity_kind(row.event_type),
                temporal_disposition=disposition,
                system_id=resource_system,
                resource_id=row.resource_id,
                supporting_evidence_ids=tuple(sorted(supporting_ids)),
                attribution_source=(
                    "INDEXED_SUBJECT_RECORD"
                    if any(value.startswith("evidence_") for value in supporting_ids)
                    else "EXPLICIT_IDENTITY_LINK"
                ),
                related_system_id=related_system_id,
                related_resource_id=related_resource_id,
            )
        )
    return tuple(
        sorted(
            grounded,
            key=lambda item: (
                item.activity.event_time,
                item.activity.activity_id,
                item.resource_id,
            ),
        )
    )


def _linked_user_id(
    activity: SystemActivity,
    request: DeletionRequest,
    identity_resolver: IdentityLinkResolver,
) -> Optional[str]:
    if activity.reported_result != "SUCCESS":
        return None
    if activity.resource_id.casefold() not in activity.details.casefold():
        return None
    user_ids = set(_USER_ID_PATTERN.findall(activity.details))
    emails = set(_EMAIL_PATTERN.findall(activity.details))
    if len(user_ids) != 1 or len(emails) != 1:
        return None
    explicit_user_id = next(iter(user_ids))
    if explicit_user_id != identity_resolver.resolve_request(request).user_id:
        return None
    resolution = identity_resolver.resolve(
        IdentifierType.EMAIL,
        next(iter(emails)),
        audit_at=request.audit_at,
        valid_at=activity.event_time,
    )
    if (
        resolution.status != IdentityLinkResolutionStatus.RESOLVED
        or resolution.user_id != explicit_user_id
    ):
        return None
    return explicit_user_id


def _activity_kind(event_type: str) -> ActivityKind:
    if event_type in {
        "SYNC_RECORD",
        "INDEX_RECORD",
        "CREATE_EXPORT",
        "REFRESH_CACHE",
        "SEND_EMAIL",
        "CHECK_DATA_FLOW",
        "DISABLE_DATA_FLOW",
    }:
        return ActivityKind.DATA_FLOW
    if event_type in {
        "CHECK_RESTORE_ACCESS",
        "RESTORE_BACKUP",
        "BLOCK_RESTORE",
    }:
        return ActivityKind.RESTORE_RISK
    if event_type in {
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
        "RETAIN_RECORD",
    }:
        return ActivityKind.OPERATIONAL_CLAIM
    return ActivityKind.WORKFLOW_CLAIM


def _flatten_scalars(
    values: Mapping[str, object], prefix: str, output: Dict[str, object]
) -> None:
    for key, value in values.items():
        path = "{}_{}".format(prefix, key) if prefix else str(key)
        if isinstance(value, dict):
            _flatten_scalars(value, path, output)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            output.setdefault(path, value)


def _string_value(value: object) -> Optional[str]:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value).strip()
        return text or None
    return None
