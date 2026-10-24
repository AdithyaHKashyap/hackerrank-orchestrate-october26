"""Map supported evidence assessments into challenge decisions and ordered steps."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Mapping, Optional, Tuple

from .coverage_grounding import GroundedRequestEvidence
from .identity_links import IdentityLinkResolutionStatus
from .policy_assessment import (
    PolicyAssessmentBatch,
    PolicyAssessmentStatus,
)
from .recreation_graph import (
    RecreationGraph,
    RecreationRiskState,
)
from .request_classifier import (
    AuthorizationStatus,
    RequestClassification,
)
from .models import DeletionRequest
from .evidence_reconciliation import TemporalDisposition


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class CaseDecision:
    case_id: str
    status: Optional[DeletionStatus]
    steps: Tuple[Mapping[str, object], ...]
    unresolved_reasons: Tuple[str, ...]


_FINDING_PLAN = {
    "REPORT_ACTIVE_DATA_FLOW": ("DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    "REPORT_RESTORE_RISK": ("BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
}
_OPERATION_STATES = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
_PHASES = {
    "FINDING": 0,
    "REMEDIATION": 1,
    "VERIFICATION": 2,
}
_OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def decide_request(
    request: DeletionRequest,
    classification: RequestClassification,
    grounded: GroundedRequestEvidence,
    assessments: PolicyAssessmentBatch,
    graph: RecreationGraph,
) -> CaseDecision:
    if classification.authorization == AuthorizationStatus.NOT_AUTHORIZED:
        return CaseDecision(
            request.case_id, DeletionStatus.NOT_APPLICABLE, tuple(), tuple()
        )
    if classification.authorization != AuthorizationStatus.AUTHORIZED:
        return _blocked(request.case_id, "Deletion authorization is unresolved.")
    if (
        grounded.identity_status != IdentityLinkResolutionStatus.RESOLVED
        or grounded.subject_user_id is None
    ):
        return _blocked(request.case_id, "Subject identity is unresolved or ambiguous.")

    findings: Dict[Tuple[str, str, str], str] = {}
    finding_evidence: Dict[Tuple[str, str, str], str] = {}
    remediation: Dict[Tuple[str, str, str], str] = {}
    verification: Dict[Tuple[str, str, str], str] = {}
    blockers: List[str] = []
    groups = {
        (item.system_id, item.resource_id, item.data_category): item
        for item in grounded.ledger.groups
    }

    for assessment in assessments.assessments:
        key = (
            assessment.system_id or "",
            assessment.resource_id or "",
            assessment.data_category or "",
        )
        if assessment.status == PolicyAssessmentStatus.UNKNOWN:
            blockers.append(
                "Policy state is unknown for {}/{}/{}.".format(*key)
            )
            continue
        if assessment.status == PolicyAssessmentStatus.SATISFIED:
            if assessment.applicable is False:
                continue
            operation = _verification_for(assessment.required_action)
            if operation is None or not assessment.evidence_ids:
                blockers.append(
                    "No evidence-backed verification is available for {}/{}/{}.".format(
                        *key
                    )
                )
                continue
            verification[(key[0], key[1], key[2])] = operation
            finding_evidence[(key[0], key[1], key[2])] = assessment.evidence_ids[0]
            continue

        group = groups.get(key)
        if group is None or not assessment.evidence_ids:
            blockers.append(
                "A policy violation lacks a grounded resource and evidence for {}/{}/{}.".format(
                    *key
                )
            )
            continue
        finding = _finding_for(assessment.required_action, assessment.potential_exposed_fields)
        if finding is None:
            blockers.append(
                "The policy violation has no matching allowed finding operation for {}/{}/{}.".format(
                    *key
                )
            )
            continue
        plan = _record_action_plan(assessment.required_action)
        if plan is None:
            blockers.append(
                "No permitted remediation plan exists for {}/{}/{}.".format(*key)
            )
            continue
        findings[(key[0], key[1], finding)] = finding
        finding_evidence[(key[0], key[1], finding)] = assessment.evidence_ids[0]
        remediation[(key[0], key[1], finding)] = plan[0]
        verification[(key[0], key[1], finding)] = plan[1]

    for edge in graph.edges:
        if (
            edge.temporal_disposition != TemporalDisposition.ELIGIBLE
            or edge.risk_state != RecreationRiskState.ACTIVE
        ):
            continue
        operation = (
            "REPORT_RESTORE_RISK"
            if edge.kind.value == "RESTORE"
            else "REPORT_ACTIVE_DATA_FLOW"
        )
        if not edge.evidence_ids:
            blockers.append(
                "An active recreation path lacks a citeable evidence ID."
            )
            continue
        key = (edge.source.system_id, edge.source.resource_id, operation)
        findings[key] = operation
        finding_evidence[key] = edge.evidence_ids[0]
        plan = _FINDING_PLAN[operation]
        remediation[key] = plan[0]
        verification[key] = plan[1]

    for edge in graph.edges:
        if (
            edge.temporal_disposition != TemporalDisposition.ELIGIBLE
            or edge.risk_state != RecreationRiskState.INACTIVE
            or not edge.evidence_ids
        ):
            continue
        operation = (
            "VERIFY_RESTORE_BLOCKED"
            if edge.kind.value == "RESTORE"
            else "VERIFY_DATA_FLOW_DISABLED"
        )
        verification[
            (edge.source.system_id, edge.source.resource_id, operation)
        ] = operation
        finding_evidence[
            (edge.source.system_id, edge.source.resource_id, operation)
        ] = edge.evidence_ids[0]

    active_findings = bool(findings)
    if active_findings:
        steps = _steps_for_findings(
            findings, finding_evidence, remediation, verification
        )
        return CaseDecision(
            request.case_id,
            DeletionStatus.INCOMPLETE,
            steps,
            tuple(sorted(set(blockers))),
        )

    if blockers:
        return CaseDecision(
            request.case_id,
            None,
            tuple(),
            tuple(sorted(set(blockers))),
        )

    if any(
        edge.temporal_disposition == TemporalDisposition.ELIGIBLE
        and edge.risk_state == RecreationRiskState.UNKNOWN
        for edge in graph.edges
    ):
        return _blocked(
            request.case_id,
            "An eligible data-flow or restore observation has unresolved current state.",
        )
    if grounded.ledger.unresolved:
        return _blocked(
            request.case_id,
            "Subject-linked evidence has unresolved observation timestamps.",
        )
    if not verification:
        return _blocked(
            request.case_id,
            "No evidence-backed verification steps can establish completion.",
        )
    steps = _steps_from_operations(
        (
            "VERIFICATION",
            system_id,
            resource_id,
            operation,
            _OPERATION_STATES[operation],
            finding_evidence[(system_id, resource_id, _category)],
        )
        for (system_id, resource_id, _category), operation in verification.items()
    )
    return CaseDecision(
        request.case_id, DeletionStatus.COMPLETE, steps, tuple()
    )


def _finding_for(
    required_action: Optional[str], exposed_fields: Tuple[str, ...]
) -> Optional[str]:
    action = (required_action or "").strip().upper()
    if action == "DELETE":
        return "REPORT_REMAINING_RECORD"
    if action in {"REDACT", "ANONYMIZE"}:
        return "REPORT_EXPOSED_PII" if exposed_fields or action == "ANONYMIZE" else None
    return None


def _record_action_plan(
    required_action: Optional[str],
) -> Optional[Tuple[str, str]]:
    return {
        "DELETE": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
        "REDACT": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
        "ANONYMIZE": ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    }.get((required_action or "").strip().upper())


def _verification_for(required_action: Optional[str]) -> Optional[str]:
    return {
        "DELETE": "VERIFY_RECORD_ABSENT",
        "RETAIN": "VERIFY_RECORD_PRESENT",
        "REDACT": "VERIFY_RECORD_REDACTED",
        "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
    }.get((required_action or "").strip().upper())


def _steps_for_findings(
    findings: Mapping[Tuple[str, str, str], str],
    finding_evidence: Mapping[Tuple[str, str, str], str],
    remediation: Mapping[Tuple[str, str, str], str],
    verification: Mapping[Tuple[str, str, str], str],
) -> Tuple[Mapping[str, object], ...]:
    operations = []
    planned_verifications = set()
    for key, finding_operation in findings.items():
        system_id, resource_id, _ = key
        operations.extend(
            (
                (
                    "FINDING",
                    system_id,
                    resource_id,
                    finding_operation,
                    _OPERATION_STATES[finding_operation],
                    finding_evidence[key],
                ),
                (
                    "REMEDIATION",
                    system_id,
                    resource_id,
                    remediation[key],
                    _OPERATION_STATES[remediation[key]],
                    "",
                ),
                (
                    "VERIFICATION",
                    system_id,
                    resource_id,
                    verification[key],
                    _OPERATION_STATES[verification[key]],
                    "",
                ),
            )
        )
        planned_verifications.add((system_id, resource_id, verification[key]))
    for key, operation in verification.items():
        system_id, resource_id, _ = key
        if operation in _OPERATION_STATES and operation.startswith("VERIFY_"):
            verify_key = (system_id, resource_id, operation)
            if verify_key in planned_verifications:
                continue
            operations.append(
                (
                    "VERIFICATION",
                    system_id,
                    resource_id,
                    operation,
                    _OPERATION_STATES[operation],
                    "",
                )
            )
    return _steps_from_operations(operations)


def _steps_from_operations(operations):
    unique = {}
    for item in operations:
        phase, system_id, resource_id, operation = item[:4]
        evidence_id = item[5]
        key = (phase, operation, system_id, resource_id)
        previous = unique.get(key)
        if previous is None or evidence_id < previous[-1]:
            unique[key] = item
    ordered = sorted(
        unique.values(),
        key=lambda item: (
            _PHASES[item[0]],
            _OPERATION_ORDER[item[3]],
            item[1],
            item[2],
        ),
    )
    return tuple(
        {
            "step_no": index,
            "phase": phase,
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id,
        }
        for index, (
            phase,
            system_id,
            resource_id,
            operation,
            state,
            evidence_id,
        ) in enumerate(ordered, start=1)
    )


def _blocked(case_id: str, reason: str) -> CaseDecision:
    return CaseDecision(case_id, None, tuple(), (reason,))
