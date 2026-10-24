"""Per-request, provenance-preserving reconciliation of indexed observations."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .evidence_index import (
    EvidenceIndex,
    ExtractionStatus,
    FileExtractionReport,
    IndexedEvidence,
    TemporalEvidencePartition,
    _normalize_indexed_identifier,
    _reference_identifier_type,
)
from .identity_links import IdentityLink, IdentityLinkConfidence
from .models import DeletionRequest, EvidenceFact, InspectionStatus


class ObservationKind(str, Enum):
    DIRECT_RESOURCE_STATE = "DIRECT_RESOURCE_STATE"
    WORKFLOW_CLAIM = "WORKFLOW_CLAIM"
    DATA_FLOW = "DATA_FLOW"
    UNCLASSIFIED = "UNCLASSIFIED"


class CoverageStatus(str, Enum):
    CONFIRMED_PRESENT = "CONFIRMED_PRESENT"
    CONFIRMED_ABSENT = "CONFIRMED_ABSENT"
    NOT_INSPECTED = "NOT_INSPECTED"
    INSPECTION_FAILED = "INSPECTION_FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class TemporalDisposition(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    EXCLUDED = "EXCLUDED"
    UNRESOLVED = "UNRESOLVED"


class InspectionSourceStatus(str, Enum):
    NOT_INSPECTED = "NOT_INSPECTED"
    INSPECTION_FAILED = "INSPECTION_FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ExpectedResourceScope:
    """A caller-declared resource scope; completeness is never inferred."""

    system_id: str
    resource_id: str
    data_category: Optional[str] = None
    complete_evidence_ids: Tuple[str, ...] = ()
    evidence_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.system_id.strip() or not self.resource_id.strip():
            raise ValueError("expected resource scope needs system and resource IDs")
        if any(not evidence_id.strip() for evidence_id in self.complete_evidence_ids):
            raise ValueError("complete evidence IDs must not be empty")
        if any(not evidence_id.strip() for evidence_id in self.evidence_ids):
            raise ValueError("expected evidence IDs must not be empty")


@dataclass(frozen=True)
class ReconciledObservation:
    record: IndexedEvidence
    kind: ObservationKind
    temporal_disposition: TemporalDisposition

    @property
    def evidence_id(self) -> str:
        return self.record.evidence_id


@dataclass(frozen=True)
class ResourceCoverage:
    system_id: Optional[str]
    resource_id: Optional[str]
    data_category: Optional[str]
    observations: Tuple[ReconciledObservation, ...]
    status: CoverageStatus
    contradictory: bool


@dataclass(frozen=True)
class SourceInspection:
    evidence_id: str
    source_path: str
    extraction_status: ExtractionStatus
    status: InspectionSourceStatus
    captured_at: datetime
    related_observation_count: int
    error: Optional[str]


@dataclass(frozen=True)
class RequestCoverageLedger:
    case_id: str
    audit_at: datetime
    subject_user_id: Optional[str]
    eligible: Tuple[ReconciledObservation, ...]
    excluded: Tuple[ReconciledObservation, ...]
    unresolved: Tuple[ReconciledObservation, ...]
    groups: Tuple[ResourceCoverage, ...]
    source_inspections: Tuple[SourceInspection, ...]


_IDENTIFIER_KEYS = {
    "email": "email",
    "phone": "phone",
    "email_hash": "email_hash",
}
_SUBJECT_ID_KEYS = {
    "user_id",
    "subject_user_id",
    "customer_reference",
    "customer_id",
}
_WORKFLOW_CLAIM_KEYS = {
    "reported_result",
    "reported_status",
    "workflow_status",
    "operation_result",
}
_FLOW_EVENT_KEYS = {"event_type", "flow_type", "process_type"}
_FLOW_EVENT_VALUES = {
    "backup",
    "export",
    "import",
    "index",
    "replication",
    "restore",
    "sync",
    "synchronization",
}


def reconcile_request(
    request: DeletionRequest,
    evidence_index: EvidenceIndex,
    subject_user_id: Optional[str] = None,
    subject_identifiers: Optional[Mapping[str, Iterable[str]]] = None,
    identity_links: Iterable[IdentityLink] = (),
    expected_scopes: Iterable[ExpectedResourceScope] = (),
) -> RequestCoverageLedger:
    """Build a conservative ledger without treating coverage gaps as absence.

    Subject associations use only explicit stable-user-reference fields,
    typed email/phone/hash fields, or sibling events sharing a trace ID in the
    same source file. Name and free-text matches are intentionally excluded.
    """

    identifiers = _normalize_subject_identifiers(subject_identifiers or {})
    for link in identity_links:
        if (
            link.confidence == IdentityLinkConfidence.STRONG
            and link.is_known_at(request.audit_at)
        ):
            identifiers.setdefault(link.identifier_type.value, set()).add(
                link.normalized_value
            )
    direct_related_records = tuple(
        record
        for record in evidence_index.for_subject(
            subject_user_id, identifiers
        )
        if _record_matches_subject(record, subject_user_id, identifiers)
    )
    eligible_anchors = _partition_records(
        direct_related_records, request.audit_at
    ).eligible
    trace_contexts = {
        (record.source_path, trace_id)
        for record in eligible_anchors
        for trace_id in _record_trace_ids(record)
    }
    # Evidence IDs identify files; multiple records from one file share the ID.
    related_record_map = {
        id(record): record for record in direct_related_records
    }
    for source_path, trace_id in trace_contexts:
        for record in evidence_index.for_source_trace(source_path, trace_id):
            related_record_map[id(record)] = record
    related_records = evidence_index.ordered_subset(related_record_map.values())
    temporal = _partition_records(related_records, request.audit_at)
    eligible = tuple(
        _observation(record, TemporalDisposition.ELIGIBLE)
        for record in temporal.eligible
    )
    excluded = tuple(
        _observation(record, TemporalDisposition.EXCLUDED)
        for record in temporal.excluded
    )
    unresolved = tuple(
        _observation(record, TemporalDisposition.UNRESOLVED)
        for record in temporal.unresolved
    )

    reports_by_id: Dict[str, FileExtractionReport] = {
        report.evidence_id: report for report in evidence_index.report
    }
    complete_report_ids = {
        report.evidence_id
        for report in evidence_index.report
        if report.status == ExtractionStatus.SUCCESS
        and _parse_report_time(report.captured_at) <= request.audit_at
    }
    available_report_ids = {
        report.evidence_id
        for report in evidence_index.report
        if _parse_report_time(report.captured_at) <= request.audit_at
    }
    filtered_scopes = tuple(
        ExpectedResourceScope(
            system_id=scope.system_id,
            resource_id=scope.resource_id,
            data_category=scope.data_category,
            complete_evidence_ids=tuple(
                evidence_id
                for evidence_id in scope.complete_evidence_ids
                if evidence_id in complete_report_ids
            ),
            evidence_ids=tuple(
                evidence_id
                for evidence_id in scope.evidence_ids
                if evidence_id in available_report_ids
            ),
        )
        for scope in expected_scopes
    )
    scopes_by_key: Dict[
        Tuple[str, str, Optional[str]], Tuple[set, set]
    ] = {}
    for scope in filtered_scopes:
        key = (scope.system_id, scope.resource_id, scope.data_category)
        complete_ids, evidence_ids = scopes_by_key.setdefault(key, (set(), set()))
        complete_ids.update(scope.complete_evidence_ids)
        evidence_ids.update(scope.evidence_ids)
    scopes = tuple(
        ExpectedResourceScope(
            system_id=key[0],
            resource_id=key[1],
            data_category=key[2],
            complete_evidence_ids=tuple(sorted(complete_ids)),
            evidence_ids=tuple(sorted(evidence_ids)),
        )
        for key, (complete_ids, evidence_ids) in sorted(
            scopes_by_key.items(),
            key=lambda item: tuple(value or "" for value in item[0]),
        )
    )
    groups = _build_groups(
        eligible + excluded + unresolved,
        scopes,
        reports_by_id,
    )
    sources = _build_source_inspections(
        evidence_index,
        related_records,
        request.audit_at,
    )
    return RequestCoverageLedger(
        case_id=request.case_id,
        audit_at=request.audit_at,
        subject_user_id=subject_user_id,
        eligible=eligible,
        excluded=excluded,
        unresolved=unresolved,
        groups=groups,
        source_inspections=sources,
    )


def _normalize_subject_identifiers(
    identifiers: Mapping[str, Iterable[str]],
) -> Dict[str, set]:
    normalized: Dict[str, set] = {}
    for identifier_type, values in identifiers.items():
        key = str(identifier_type).strip().casefold()
        if key not in _IDENTIFIER_KEYS:
            continue
        normalized[key] = {
            _normalize_identifier(key, value)
            for value in values
            if isinstance(value, str) and _normalize_identifier(key, value)
        }
    return normalized


def _normalize_identifier(identifier_type: str, value: str) -> str:
    return _normalize_indexed_identifier(identifier_type, value)


def _record_matches_subject(
    record: IndexedEvidence,
    subject_user_id: Optional[str],
    identifiers: Mapping[str, set],
) -> bool:
    attributes = record.attributes
    if subject_user_id:
        if record.fact.subject_user_id == subject_user_id:
            return True
        if any(
            key.strip().casefold() in _SUBJECT_ID_KEYS
            and isinstance(value, (str, int))
            and not isinstance(value, bool)
            and str(value).strip() == subject_user_id
            for key, value in attributes.items()
        ):
            return True
    for key, value in attributes.items():
        if not isinstance(value, str):
            continue
        normalized_key = key.strip().casefold()
        if normalized_key == "lookup_key" and (
            record.metadata.get("readback_export_complete") is not True
        ):
            continue
        if normalized_key in {
            "subject_reference",
            "subject_key",
            "lookup_key",
            "correlation_key",
        }:
            if _matches_subject_reference(
                value, subject_user_id, identifiers
            ):
                return True
            continue
        identifier_type = next(
            (
                item_type
                for item_type in _IDENTIFIER_KEYS
                if normalized_key == item_type
                or normalized_key.endswith("_" + item_type)
            ),
            None,
        )
        if (
            identifier_type is not None
            and _normalize_identifier(identifier_type, value)
            in identifiers.get(identifier_type, set())
        ):
            return True
    return False


def _record_trace_ids(record: IndexedEvidence) -> Tuple[str, ...]:
    return tuple(
        value.strip()
        for key, value in record.attributes.items()
        if key.strip().casefold() == "trace_id"
        and isinstance(value, str)
        and value.strip()
    )


def _matches_subject_reference(
    value: str,
    subject_user_id: Optional[str],
    identifiers: Mapping[str, set],
) -> bool:
    reference = value.strip()
    if subject_user_id and reference == subject_user_id:
        return True
    identifier_type = _reference_identifier_type(reference)
    if identifier_type is None:
        return False
    return (
        _normalize_identifier(identifier_type, reference)
        in identifiers.get(identifier_type, set())
    )


def _partition_records(
    records: Iterable[IndexedEvidence], audit_at: datetime
) -> TemporalEvidencePartition:
    eligible = []
    excluded = []
    unresolved = []
    for record in records:
        available_at = record.fact.provenance.available_at
        observed_at = record.fact.observed_at
        if available_at is None or available_at > audit_at:
            excluded.append(record)
        elif observed_at is not None and observed_at > audit_at:
            excluded.append(record)
        elif observed_at is None:
            unresolved.append(record)
        else:
            eligible.append(record)
    return TemporalEvidencePartition(
        eligible=tuple(eligible),
        unresolved=tuple(unresolved),
        excluded=tuple(excluded),
    )


def _observation(
    record: IndexedEvidence, disposition: TemporalDisposition
) -> ReconciledObservation:
    return ReconciledObservation(
        record=record,
        kind=_observation_kind(record.fact, record.attributes),
        temporal_disposition=disposition,
    )


def _observation_kind(
    fact: EvidenceFact, attributes: Mapping[str, Any]
) -> ObservationKind:
    if (
        fact.inspection_status == InspectionStatus.CONFIRMED
        and fact.observed_state in {"PRESENT", "ABSENT"}
    ):
        return ObservationKind.DIRECT_RESOURCE_STATE
    keys = {str(key).strip().casefold() for key in attributes}
    if keys.intersection(_WORKFLOW_CLAIM_KEYS):
        return ObservationKind.WORKFLOW_CLAIM
    for key, value in attributes.items():
        if (
            str(key).strip().casefold() in _FLOW_EVENT_KEYS
            and isinstance(value, str)
            and value.strip().casefold() in _FLOW_EVENT_VALUES
        ):
            return ObservationKind.DATA_FLOW
    return ObservationKind.UNCLASSIFIED


def _build_groups(
    observations: Tuple[ReconciledObservation, ...],
    expected_scopes: Tuple[ExpectedResourceScope, ...],
    reports_by_id: Mapping[str, FileExtractionReport],
) -> Tuple[ResourceCoverage, ...]:
    grouped: Dict[Tuple[Optional[str], Optional[str], Optional[str]], list] = {}
    ungrouped = []
    for observation in observations:
        fact = observation.record.fact
        if fact.system_id is None or fact.resource_id is None:
            ungrouped.append(observation)
            continue
        key = (fact.system_id, fact.resource_id, fact.data_category)
        grouped.setdefault(key, []).append(observation)

    for scope in expected_scopes:
        key = (scope.system_id, scope.resource_id, scope.data_category)
        grouped.setdefault(key, [])

    results = []
    scope_by_key = {
        (scope.system_id, scope.resource_id, scope.data_category): scope
        for scope in expected_scopes
    }
    for key, items in sorted(
        grouped.items(),
        key=lambda item: tuple(value or "" for value in item[0]),
    ):
        scope = scope_by_key.get(key)
        results.append(
            _resource_coverage(
                key[0],
                key[1],
                key[2],
                tuple(sorted(items, key=_observation_sort_key)),
                scope,
                reports_by_id,
            )
        )
    for observation in sorted(ungrouped, key=_observation_sort_key):
        fact = observation.record.fact
        results.append(
            _resource_coverage(
                fact.system_id,
                fact.resource_id,
                fact.data_category,
                (observation,),
                None,
                reports_by_id,
            )
        )
    return tuple(results)


def _resource_coverage(
    system_id: Optional[str],
    resource_id: Optional[str],
    data_category: Optional[str],
    observations: Tuple[ReconciledObservation, ...],
    expected_scope: Optional[ExpectedResourceScope],
    reports_by_id: Mapping[str, FileExtractionReport],
) -> ResourceCoverage:
    eligible_direct = [
        item
        for item in observations
        if item.temporal_disposition == TemporalDisposition.ELIGIBLE
        and item.kind == ObservationKind.DIRECT_RESOURCE_STATE
    ]
    present = [
        item
        for item in eligible_direct
        if item.record.fact.confirms_presence
    ]
    absent = [
        item
        for item in eligible_direct
        if item.record.fact.confirms_absence
    ]
    contradictory = bool(present and absent)
    if contradictory:
        status = CoverageStatus.INCONCLUSIVE
    elif present:
        status = CoverageStatus.CONFIRMED_PRESENT
    elif absent:
        complete_ids = (
            set(expected_scope.complete_evidence_ids)
            if expected_scope is not None
            else set()
        )
        sufficient_absence = any(
            item.evidence_id in complete_ids
            or item.record.metadata.get("complete_scoped_inspection") is True
            for item in absent
        )
        status = (
            CoverageStatus.CONFIRMED_ABSENT
            if sufficient_absence
            else CoverageStatus.INCONCLUSIVE
        )
    elif any(
        item.temporal_disposition == TemporalDisposition.ELIGIBLE
        and item.record.fact.inspection_status == InspectionStatus.FAILED
        for item in observations
    ):
        status = CoverageStatus.INSPECTION_FAILED
    elif expected_scope is not None and any(
        evidence_id in reports_by_id
        and reports_by_id[evidence_id].status
        in {ExtractionStatus.UNREADABLE, ExtractionStatus.UNSUPPORTED}
        for evidence_id in expected_scope.evidence_ids
    ):
        status = CoverageStatus.INSPECTION_FAILED
    elif observations:
        status = CoverageStatus.INCONCLUSIVE
    else:
        status = CoverageStatus.NOT_INSPECTED
    return ResourceCoverage(
        system_id=system_id,
        resource_id=resource_id,
        data_category=data_category,
        observations=observations,
        status=status,
        contradictory=contradictory,
    )


def _observation_sort_key(
    observation: ReconciledObservation,
) -> Tuple[str, str, str]:
    return (
        observation.evidence_id,
        observation.record.fact.provenance.record_locator or "",
        observation.kind.value,
    )


def _build_source_inspections(
    evidence_index: EvidenceIndex,
    related_records: Tuple[IndexedEvidence, ...],
    audit_at: datetime,
) -> Tuple[SourceInspection, ...]:
    related_by_evidence: Dict[str, int] = {}
    for record in related_records:
        related_by_evidence[record.evidence_id] = (
            related_by_evidence.get(record.evidence_id, 0) + 1
        )
    inspections = []
    for report in evidence_index.report:
        captured_at = _parse_report_time(report.captured_at).astimezone(
            audit_at.tzinfo
        )
        if captured_at > audit_at:
            status = InspectionSourceStatus.NOT_INSPECTED
        elif report.status in {
            ExtractionStatus.UNREADABLE,
            ExtractionStatus.UNSUPPORTED,
        }:
            status = InspectionSourceStatus.INSPECTION_FAILED
        elif report.status == ExtractionStatus.PARTIAL:
            status = InspectionSourceStatus.INCONCLUSIVE
        elif related_by_evidence.get(report.evidence_id, 0):
            status = InspectionSourceStatus.INCONCLUSIVE
        else:
            status = InspectionSourceStatus.NOT_INSPECTED
        inspections.append(
            SourceInspection(
                evidence_id=report.evidence_id,
                source_path=report.source_path,
                extraction_status=report.status,
                status=status,
                captured_at=captured_at,
                related_observation_count=related_by_evidence.get(
                    report.evidence_id, 0
                ),
                error=report.error,
            )
        )
    return tuple(inspections)


def _parse_report_time(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("evidence report timestamp must be timezone-aware")
    return timestamp
