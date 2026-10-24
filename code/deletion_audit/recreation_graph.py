"""Build a cutoff-aware graph of subject-linked copies and recreation paths."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple

from .coverage_grounding import (
    ActivityKind,
    GroundedRequestEvidence,
)
from .evidence_reconciliation import TemporalDisposition
from .models import Provenance


class RecreationEdgeKind(str, Enum):
    SYNC = "SYNC"
    INDEX = "INDEX"
    EXPORT = "EXPORT"
    CACHE_REFRESH = "CACHE_REFRESH"
    EMAIL = "EMAIL"
    RESTORE = "RESTORE"
    REPLICA = "REPLICA"
    CONNECTOR = "CONNECTOR"
    OPERATIONAL = "OPERATIONAL"


class RecreationRiskState(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, order=True)
class ResourceNode:
    system_id: str
    resource_id: str
    data_category: str = ""


@dataclass(frozen=True)
class RecreationEdge:
    source: ResourceNode
    target: Optional[ResourceNode]
    kind: RecreationEdgeKind
    risk_state: RecreationRiskState
    temporal_disposition: TemporalDisposition
    evidence_ids: Tuple[str, ...]
    supporting_evidence_ids: Tuple[str, ...]
    provenance: Tuple[Provenance, ...]


@dataclass(frozen=True)
class RecreationGraph:
    nodes: Tuple[ResourceNode, ...]
    edges: Tuple[RecreationEdge, ...]

    def paths_between(
        self,
        source: ResourceNode,
        target: ResourceNode,
        max_depth: Optional[int] = None,
    ) -> Tuple[Tuple[RecreationEdge, ...], ...]:
        """Return deterministic simple paths without resolving conflicting edges."""

        limit = max_depth if max_depth is not None else max(1, len(self.nodes))
        adjacency: Dict[ResourceNode, List[RecreationEdge]] = {}
        for edge in self.edges:
            if edge.target is not None:
                adjacency.setdefault(edge.source, []).append(edge)
        for edges in adjacency.values():
            edges.sort(
                key=lambda item: (
                    item.target or ResourceNode("", ""),
                    item.kind.value,
                    item.evidence_ids,
                )
            )

        paths: List[Tuple[RecreationEdge, ...]] = []

        def visit(
            node: ResourceNode,
            visited: frozenset,
            path: Tuple[RecreationEdge, ...],
        ) -> None:
            if len(path) >= limit:
                return
            for edge in adjacency.get(node, ()):
                next_node = edge.target
                if next_node is None or next_node in visited:
                    continue
                next_path = path + (edge,)
                if next_node == target:
                    paths.append(next_path)
                else:
                    visit(next_node, visited | {next_node}, next_path)

        visit(source, frozenset({source}), tuple())
        return tuple(paths)


_EVENT_EDGE_KINDS = {
    "SYNC_RECORD": RecreationEdgeKind.SYNC,
    "INDEX_RECORD": RecreationEdgeKind.INDEX,
    "CREATE_EXPORT": RecreationEdgeKind.EXPORT,
    "REFRESH_CACHE": RecreationEdgeKind.CACHE_REFRESH,
    "SEND_EMAIL": RecreationEdgeKind.EMAIL,
    "RESTORE_BACKUP": RecreationEdgeKind.RESTORE,
}
_FLOW_EDGE_TYPES = {
    ActivityKind.DATA_FLOW,
    ActivityKind.RESTORE_RISK,
}


def build_recreation_graph(
    grounded: GroundedRequestEvidence,
) -> RecreationGraph:
    """Preserve observed and unresolved edges; activity alone never proves active state."""

    nodes = set()
    edges = []
    for observation in (
        grounded.ledger.eligible
        + grounded.ledger.unresolved
        + grounded.ledger.excluded
    ):
        fact = observation.record.fact
        if fact.system_id and fact.resource_id:
            nodes.add(
                ResourceNode(
                    fact.system_id,
                    fact.resource_id,
                    fact.data_category or "",
                )
            )

    for activity in grounded.activity:
        if activity.kind not in _FLOW_EDGE_TYPES:
            continue
        row = activity.activity
        kind = _EVENT_EDGE_KINDS.get(
            row.event_type, RecreationEdgeKind.OPERATIONAL
        )
        source = ResourceNode(row.source_system, row.resource_id)
        if activity.related_system_id and activity.related_resource_id:
            target = ResourceNode(
                activity.related_system_id,
                activity.related_resource_id,
            )
        else:
            target = ResourceNode(row.target_system, row.resource_id)
        nodes.update((source, target))
        disposition = activity.temporal_disposition
        edges.append(
            RecreationEdge(
                source=source,
                target=target,
                kind=kind,
                risk_state=RecreationRiskState.UNKNOWN,
                temporal_disposition=disposition,
                evidence_ids=(row.activity_id,),
                supporting_evidence_ids=activity.supporting_evidence_ids,
                provenance=tuple(),
            )
        )

    for observation in (
        grounded.ledger.eligible
        + grounded.ledger.unresolved
        + grounded.ledger.excluded
    ):
        record = observation.record
        fact = record.fact
        attributes = record.attributes
        if not fact.system_id or not fact.resource_id:
            continue
        category = fact.data_category or ""
        is_connector = category == "DATA_FLOW_CONFIGURATION"
        is_backup = category == "BACKUP_ARCHIVE"
        if not (is_connector or is_backup):
            continue
        field = "enabled" if is_connector else "restore_allowed"
        enabled = _explicit_boolean(attributes, field)
        corroborated_restore_candidate = (
            is_backup
            and _restore_candidate_is_unblocked(attributes)
            and any(
                activity.kind == ActivityKind.RESTORE_RISK
                and activity.temporal_disposition == TemporalDisposition.ELIGIBLE
                and activity.activity.event_type == "CHECK_RESTORE_ACCESS"
                and activity.activity.reported_result == "SUCCESS"
                and activity.system_id == fact.system_id
                and activity.resource_id == fact.resource_id
                and record.evidence_id in activity.supporting_evidence_ids
                for activity in grounded.activity
            )
        )
        state = (
            RecreationRiskState.ACTIVE
            if (
                (
                    enabled is True
                    and fact.inspection_status.value == "CONFIRMED"
                )
                or corroborated_restore_candidate
            )
            else RecreationRiskState.INACTIVE
            if enabled is False
            and fact.inspection_status.value == "CONFIRMED"
            else RecreationRiskState.UNKNOWN
        )
        if observation.temporal_disposition != TemporalDisposition.ELIGIBLE:
            state = RecreationRiskState.UNKNOWN
        source = ResourceNode(fact.system_id, fact.resource_id, category)
        target_system = _attribute_value(
            attributes, ("target_system", "destination_system")
        )
        target_resource = _attribute_value(
            attributes,
            ("target_resource_id", "destination_resource_id", "downstream_resource_id"),
        )
        target = (
            ResourceNode(target_system, target_resource)
            if target_system and target_resource
            else None
        )
        if target is not None:
            nodes.add(target)
        kind = (
            RecreationEdgeKind.CONNECTOR
            if is_connector
            else RecreationEdgeKind.RESTORE
        )
        edges.append(
            RecreationEdge(
                source=source,
                target=target,
                kind=kind,
                risk_state=state,
                temporal_disposition=observation.temporal_disposition,
                evidence_ids=(record.evidence_id,),
                supporting_evidence_ids=tuple(),
                provenance=(fact.provenance,),
            )
        )

    for observation in (
        grounded.ledger.eligible
        + grounded.ledger.unresolved
        + grounded.ledger.excluded
    ):
        record = observation.record
        fact = record.fact
        if not fact.system_id or not fact.resource_id:
            continue
        attributes = record.attributes
        source_resource = _attribute_value(attributes, ("source_resource_id",))
        if not source_resource or source_resource == fact.resource_id:
            continue
        table_name = str(record.metadata.get("table_name", "")).casefold()
        category = (fact.data_category or "").upper()
        if "replica" in table_name:
            kind = RecreationEdgeKind.REPLICA
        elif category == "SEARCH_INDEX_ENTRY":
            kind = RecreationEdgeKind.INDEX
        elif category == "USER_EXPORT":
            kind = RecreationEdgeKind.EXPORT
        elif category == "BACKUP_ARCHIVE":
            kind = RecreationEdgeKind.RESTORE
        else:
            continue
        source_system = _attribute_value(attributes, ("source_system",)) or fact.system_id
        target_system = _attribute_value(attributes, ("target_system",)) or fact.system_id
        source = ResourceNode(source_system, source_resource)
        target = ResourceNode(target_system, fact.resource_id, category)
        nodes.update((source, target))
        edges.append(
            RecreationEdge(
                source=source,
                target=target,
                kind=kind,
                risk_state=RecreationRiskState.UNKNOWN,
                temporal_disposition=observation.temporal_disposition,
                evidence_ids=(record.evidence_id,),
                supporting_evidence_ids=tuple(),
                provenance=(fact.provenance,),
            )
        )

    return RecreationGraph(
        nodes=tuple(sorted(nodes)),
        edges=tuple(
            sorted(
                edges,
                key=lambda item: (
                    item.kind.value,
                    item.source,
                    item.target or ResourceNode("", ""),
                    item.temporal_disposition.value,
                    item.risk_state.value,
                    item.evidence_ids,
                ),
            )
        ),
    )


def _attribute_value(
    attributes, keys: Iterable[str]
) -> Optional[str]:
    normalized = {str(key).casefold(): value for key, value in attributes.items()}
    for expected in keys:
        expected_key = expected.casefold()
        value = normalized.get(expected_key)
        if value is None:
            for key, candidate in normalized.items():
                if key.endswith("_" + expected_key):
                    value = candidate
                    break
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            text = str(value).strip()
            if text:
                return text
    return None


def _explicit_boolean(attributes, key: str) -> Optional[bool]:
    normalized = {str(name).casefold(): item for name, item in attributes.items()}
    candidate = normalized.get(key.casefold())
    if candidate is None:
        candidate = next(
            (
                value
                for name, value in normalized.items()
                if name.endswith("_" + key.casefold())
            ),
            None,
        )
    if isinstance(candidate, bool):
        return candidate
    if isinstance(candidate, int):
        return candidate != 0
    if isinstance(candidate, str):
        text = candidate.strip().casefold()
        if text in {"1", "true", "yes", "enabled", "allowed", "active"}:
            return True
        if text in {"0", "false", "no", "disabled", "blocked", "inactive"}:
            return False
    return None


def _restore_candidate_is_unblocked(attributes) -> bool:
    event = str(attributes.get("event", "")).strip().casefold()
    return (
        event == "restore_candidate_evaluated"
        and _explicit_boolean(attributes, "eligible") is True
        and _explicit_boolean(attributes, "deletion_block") is False
    )
