"""Conservative, provenance-preserving application of deletion policy rules."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Mapping, Optional, Tuple

from .coverage_grounding import GroundedRequestEvidence
from .evidence_reconciliation import (
    CoverageStatus,
    ResourceCoverage,
    TemporalDisposition,
)
from .models import DeletionRule, Provenance
from .temporal import parse_timestamp


class PolicyAssessmentStatus(str, Enum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class PolicyAssessment:
    case_id: str
    system_id: Optional[str]
    resource_id: Optional[str]
    data_category: Optional[str]
    rule_id: Optional[str]
    required_action: Optional[str]
    applicable: Optional[bool]
    status: PolicyAssessmentStatus
    evidence_ids: Tuple[str, ...]
    unresolved_evidence_ids: Tuple[str, ...]
    excluded_evidence_ids: Tuple[str, ...]
    potential_exposed_fields: Tuple[str, ...]
    provenance: Tuple[Provenance, ...]
    explanation: str


@dataclass(frozen=True)
class ActivityRiskAssessment:
    activity_id: str
    system_id: str
    resource_id: str
    event_type: str
    status: PolicyAssessmentStatus
    evidence_ids: Tuple[str, ...]
    excluded_evidence_ids: Tuple[str, ...]
    supporting_evidence_ids: Tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class PolicyAssessmentBatch:
    case_id: str
    assessments: Tuple[PolicyAssessment, ...]
    activity_risks: Tuple[ActivityRiskAssessment, ...]
    unmapped_scope_count: int


def assess_request_policy(
    grounded: GroundedRequestEvidence,
    rules: Iterable[DeletionRule],
    subject_identifiers: Optional[Mapping[str, Iterable[str]]] = None,
    subject_names: Iterable[str] = (),
) -> PolicyAssessmentBatch:
    """Assess known policy scopes without producing a case-level deletion status."""

    rules_by_category = {rule.data_category: rule for rule in rules}
    identifiers = _normalize_subject_values(subject_identifiers or {})
    names = {name.strip().casefold() for name in subject_names if name.strip()}
    assessments = []
    unmapped_scope_count = 0
    for group in grounded.ledger.groups:
        if group.data_category == "DATA_FLOW_CONFIGURATION":
            continue
        rule = (
            rules_by_category.get(group.data_category)
            if group.data_category
            else None
        )
        if rule is None:
            unmapped_scope_count += 1
            assessments.append(
                _unknown_scope(
                    grounded.case_id,
                    group,
                    identifiers,
                    names,
                    "No supplied deletion rule can be tied to this evidence scope.",
                )
            )
            continue
        assessments.append(
            _assess_group(
                grounded.case_id,
                grounded.ledger.subject_user_id,
                group,
                rule,
                identifiers,
                names,
                grounded.ledger.audit_at,
            )
        )
    return PolicyAssessmentBatch(
        case_id=grounded.case_id,
        assessments=tuple(assessments),
        activity_risks=tuple(
            _assess_activity_risk(item)
            for item in grounded.activity
            if item.kind.value in {"DATA_FLOW", "RESTORE_RISK"}
        ),
        unmapped_scope_count=unmapped_scope_count,
    )


def _unknown_scope(
    case_id,
    group: ResourceCoverage,
    identifiers: Mapping[str, set],
    subject_names: set,
    explanation: str,
) -> PolicyAssessment:
    eligible = tuple(
        item
        for item in group.observations
        if item.temporal_disposition == TemporalDisposition.ELIGIBLE
    )
    unresolved = tuple(
        item
        for item in group.observations
        if item.temporal_disposition == TemporalDisposition.UNRESOLVED
    )
    excluded = tuple(
        item
        for item in group.observations
        if item.temporal_disposition == TemporalDisposition.EXCLUDED
    )
    exposed = tuple(
        sorted(
            {
                field
                for item in eligible
                for field in _exposed_fields(
                    item.record.attributes,
                    identifiers,
                    subject_names,
                    group.data_category or "",
                )
            }
        )
    )
    provenance = tuple(
        sorted(
            {item.record.fact.provenance for item in eligible},
            key=lambda item: (
                item.source_type,
                item.source_id,
                item.record_locator or "",
            ),
        )
    )
    return PolicyAssessment(
        case_id=case_id,
        system_id=group.system_id,
        resource_id=group.resource_id,
        data_category=group.data_category,
        rule_id=None,
        required_action=None,
        applicable=None,
        status=PolicyAssessmentStatus.UNKNOWN,
        evidence_ids=tuple(sorted({item.evidence_id for item in eligible})),
        unresolved_evidence_ids=tuple(
            sorted({item.evidence_id for item in unresolved})
        ),
        excluded_evidence_ids=tuple(
            sorted({item.evidence_id for item in excluded})
        ),
        potential_exposed_fields=exposed,
        provenance=provenance,
        explanation=explanation,
    )


def _assess_activity_risk(activity) -> ActivityRiskAssessment:
    eligible = activity.temporal_disposition == TemporalDisposition.ELIGIBLE
    return ActivityRiskAssessment(
        activity_id=activity.activity.activity_id,
        system_id=activity.system_id,
        resource_id=activity.resource_id,
        event_type=activity.activity.event_type,
        status=PolicyAssessmentStatus.UNKNOWN,
        evidence_ids=(activity.activity.activity_id,) if eligible else tuple(),
        excluded_evidence_ids=(
            tuple() if eligible else (activity.activity.activity_id,)
        ),
        supporting_evidence_ids=activity.supporting_evidence_ids,
        explanation=(
            "Activity is explicitly subject-linked but remains a workflow claim, not direct proof of process state."
        ),
    )


def _assess_group(
    case_id: str,
    subject_user_id: Optional[str],
    group: ResourceCoverage,
    rule: DeletionRule,
    identifiers: Mapping[str, set],
    subject_names: set,
    audit_at,
) -> PolicyAssessment:
    eligible = tuple(
        item
        for item in group.observations
        if item.temporal_disposition == TemporalDisposition.ELIGIBLE
    )
    unresolved = tuple(
        item
        for item in group.observations
        if item.temporal_disposition == TemporalDisposition.UNRESOLVED
    )
    excluded = tuple(
        item
        for item in group.observations
        if item.temporal_disposition == TemporalDisposition.EXCLUDED
    )
    evidence_ids = tuple(sorted({item.evidence_id for item in eligible}))
    unresolved_ids = tuple(sorted({item.evidence_id for item in unresolved}))
    excluded_ids = tuple(sorted({item.evidence_id for item in excluded}))
    provenance = tuple(
        sorted(
            {item.record.fact.provenance for item in eligible},
            key=lambda item: (
                item.source_type,
                item.source_id,
                item.record_locator or "",
            ),
        )
    )
    potential_exposed_fields = tuple(
        sorted(
            {
                field
                for item in eligible
                for field in _exposed_fields(
                    item.record.attributes,
                    identifiers,
                    subject_names,
                    group.data_category,
                )
            }
        )
    )

    applicability = _condition_applies(
        rule.condition,
        eligible,
        subject_user_id,
        identifiers,
        group.data_category,
        audit_at,
    )
    if applicability is False:
        status = PolicyAssessmentStatus.SATISFIED
        explanation = "The documented rule condition does not apply at audit_at."
    elif applicability is None:
        status = PolicyAssessmentStatus.UNKNOWN
        explanation = "Available evidence does not establish whether the rule condition applies."
    else:
        status, explanation = _assess_action(
            group,
            rule.required_action,
            eligible,
            subject_user_id,
            identifiers,
            subject_names,
            potential_exposed_fields,
        )

    if group.contradictory:
        status = PolicyAssessmentStatus.UNKNOWN
        explanation = "Conflicting eligible direct resource-state observations remain unresolved."
    return PolicyAssessment(
        case_id=case_id,
        system_id=group.system_id,
        resource_id=group.resource_id,
        data_category=group.data_category or "",
        rule_id=rule.rule_id,
        required_action=rule.required_action,
        applicable=applicability,
        status=status,
        evidence_ids=evidence_ids,
        unresolved_evidence_ids=unresolved_ids,
        excluded_evidence_ids=excluded_ids,
        potential_exposed_fields=potential_exposed_fields,
        provenance=provenance,
        explanation=explanation,
    )


def _assess_action(
    group: ResourceCoverage,
    required_action: str,
    eligible,
    subject_user_id: Optional[str],
    identifiers: Mapping[str, set],
    subject_names: set,
    potential_exposed_fields: Tuple[str, ...],
):
    action = required_action.strip().upper()
    if group.status == CoverageStatus.CONFIRMED_ABSENT:
        if action == "DELETE":
            return PolicyAssessmentStatus.SATISFIED, "A complete scoped inspection confirms absence."
        if action == "ANONYMIZE":
            return PolicyAssessmentStatus.SATISFIED, "The resource is absent and cannot remain attributable."
        if action in {"REDACT", "RETAIN"}:
            return PolicyAssessmentStatus.VIOLATED, "The policy requires this record to remain available."
        return PolicyAssessmentStatus.UNKNOWN, "The required action is not recognized."
    if group.status != CoverageStatus.CONFIRMED_PRESENT:
        return PolicyAssessmentStatus.UNKNOWN, "Resource state is not sufficiently established."
    if action == "DELETE":
        return PolicyAssessmentStatus.VIOLATED, "A direct eligible observation confirms the record is present."
    if action == "RETAIN":
        if potential_exposed_fields:
            return (
                PolicyAssessmentStatus.UNKNOWN,
                "The retention obligation is met, but the supplied rule does not establish whether exposed identifiers may be retained.",
            )
        return PolicyAssessmentStatus.SATISFIED, "A direct eligible observation confirms the required record is present."
    if action == "REDACT":
        return _assess_redaction(
            group.data_category or "",
            eligible,
            subject_user_id,
            potential_exposed_fields,
        )
    if action == "ANONYMIZE":
        return _assess_anonymization(
            eligible, subject_user_id, identifiers, subject_names
        )
    return PolicyAssessmentStatus.UNKNOWN, "The required action is not recognized."


def _assess_redaction(
    data_category: str,
    eligible,
    subject_user_id: Optional[str],
    potential_exposed_fields: Tuple[str, ...],
):
    attributes = _merge_attributes(eligible)
    if data_category == "ACCOUNT_TOMBSTONE":
        forbidden = {
            key
            for key in (
                "name",
                "full_name",
                "display_name",
                "email",
                "phone",
                "email_hash",
            )
            if _nonempty_value(attributes.get(key))
        }
        stable_reference = (
            attributes.get("user_id")
            or attributes.get("subject_reference")
            or attributes.get("customer_reference")
        )
        if forbidden:
            return (
                PolicyAssessmentStatus.VIOLATED,
                "The tombstone still exposes prohibited direct identifiers: {}.".format(
                    ", ".join(sorted(forbidden))
                ),
            )
        if subject_user_id and str(stable_reference or "").strip() != subject_user_id:
            return (
                PolicyAssessmentStatus.VIOLATED,
                "The tombstone does not preserve the required stable subject reference.",
            )
        present_keys = {str(key).casefold() for key in attributes}
        inspected = _explicitly_inspected_fields(attributes)
        inspected_or_present = present_keys | inspected
        fields_proven = (
            bool(
                inspected_or_present.intersection(
                    {"name", "full_name", "display_name"}
                )
            )
            and {"email", "phone", "email_hash"}.issubset(inspected_or_present)
        )
        if fields_proven and stable_reference:
            return (
                PolicyAssessmentStatus.SATISFIED,
                "The stable subject reference remains and inspected direct-identifier fields are empty.",
            )
        return (
            PolicyAssessmentStatus.UNKNOWN,
            "The evidence does not prove the tombstone's full redaction field set.",
        )

    if potential_exposed_fields:
        return (
            PolicyAssessmentStatus.VIOLATED,
            "The retained record exposes identifiers that match the subject.",
        )
    inspected = _explicitly_inspected_fields(attributes)
    required_fields = _required_redaction_fields(data_category, attributes)
    if required_fields and required_fields.issubset(inspected):
        return (
            PolicyAssessmentStatus.SATISFIED,
            "All policy-relevant identifier fields were explicitly inspected and no subject identifier remains.",
        )
    return (
        PolicyAssessmentStatus.UNKNOWN,
        "No matching identifier was found, but the inspected field scope is incomplete or undocumented.",
    )


def _assess_anonymization(
    eligible,
    subject_user_id: Optional[str],
    identifiers: Mapping[str, set],
    subject_names: set,
):
    attributes = _merge_attributes(eligible)
    linkable = bool(
        subject_user_id
        and any(
            item.record.fact.subject_user_id == subject_user_id
            or _contains_subject_reference(item.record.attributes, subject_user_id)
            for item in eligible
        )
    )
    linkable = linkable or bool(_exposed_fields(attributes, identifiers, subject_names, ""))
    if linkable:
        return (
            PolicyAssessmentStatus.VIOLATED,
            "A direct eligible observation still links the record to the subject.",
        )
    if _truthy(attributes.get("anonymized")) or (
        attributes.get("identity_linkable") is False
        or str(attributes.get("identity_linkable", "")).casefold() == "false"
    ):
        return (
            PolicyAssessmentStatus.SATISFIED,
            "The source explicitly marks the record as anonymized or not identity-linkable.",
        )
    return (
        PolicyAssessmentStatus.UNKNOWN,
        "The evidence does not prove irreversible unlinking from the subject.",
    )


def _condition_applies(
    condition: str,
    observations,
    subject_user_id: Optional[str],
    identifiers: Mapping[str, set],
    data_category: str,
    audit_at,
) -> Optional[bool]:
    text = " ".join(condition.casefold().split())
    if text == "always":
        return True
    attributes = _merge_attributes(observations)
    if text == "record is still attributable to a user":
        if not observations or not subject_user_id:
            return None
        return any(
            item.record.fact.subject_user_id == subject_user_id
            or _contains_subject_reference(item.record.attributes, subject_user_id)
            or bool(
                _exposed_fields(
                    item.record.attributes, identifiers, set(), data_category
                )
            )
            for item in observations
        )
    if text == "log contains a user email address":
        has_inspected_email = False
        for field, value in _attribute_pairs(observations):
            if not field.endswith("email"):
                continue
            has_inspected_email = True
            if _identifier_matches("email", value, identifiers):
                return True
        has_inspected_email = has_inspected_email or bool(
            {
                item.casefold()
                for item in _explicitly_inspected_fields(attributes)
            }.intersection({"email", "email_address", "user_email"})
        )
        return False if has_inspected_email else None
    if text == "conversation contains shared customer, agent, or order context that must be retained":
        for key in ("shared_context", "contains_shared_context", "shared_order_context"):
            if key in attributes:
                return _truthy(attributes[key])
        return None
    if text == "attachment belongs only to the deletion subject":
        for key in ("belongs_only_to_subject", "exclusive_owner"):
            if key in attributes:
                return _truthy(attributes[key])
        if "other_subject_count" in attributes:
            try:
                return int(attributes["other_subject_count"]) == 0
            except (TypeError, ValueError):
                return None
        if _truthy(attributes.get("shared_attachment")):
            return False
        return None
    if text == "record is within the supplied retention period":
        raw = attributes.get("retention_until")
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return parse_timestamp(raw, "retention_until") > audit_at
        except ValueError:
            return None
    if text == "a supplied legal hold is active":
        if "legal_hold_active" in attributes:
            return _truthy(attributes["legal_hold_active"])
        if "hold_status" in attributes:
            value = str(attributes["hold_status"]).strip().casefold()
            if value in {"active", "released", "inactive", "expired"}:
                return value == "active"
        return None
    if text == "restore access can be blocked":
        if "restore_allowed" not in attributes:
            return None
        return _truthy(attributes["restore_allowed"])
    if text.startswith("account is deleted and only a stable internal user_id"):
        status = str(attributes.get("account_status", "")).strip().casefold()
        stable_reference = (
            attributes.get("user_id")
            or attributes.get("subject_reference")
            or attributes.get("customer_reference")
        )
        if status and stable_reference:
            return status in {"deleted", "tombstone", "closed"}
        return None
    return None


def _required_redaction_fields(
    data_category: str, attributes: Mapping[str, object]
) -> set:
    if data_category == "EMAIL_DELIVERY_LOG":
        return {
            key
            for key in _explicitly_inspected_fields(attributes)
            if key.endswith("email")
        }
    if data_category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"}:
        return {
            key
            for key in _explicitly_inspected_fields(attributes)
            if key.endswith(("email", "phone", "email_hash", "name", "full_name"))
        }
    return {
        key
        for key in _explicitly_inspected_fields(attributes)
        if key.endswith(("email", "phone", "email_hash", "name", "full_name"))
    }


def _explicitly_inspected_fields(attributes: Mapping[str, object]) -> set:
    result = set()
    for key in ("inspected_fields", "redacted_fields", "fields_verified"):
        values = attributes.get(key)
        if isinstance(values, (tuple, list, set)):
            result.update(str(value).strip().casefold() for value in values)
        elif isinstance(values, str):
            result.update(
                part.strip().casefold()
                for part in values.replace(";", ",").split(",")
                if part.strip()
            )
    return result


def _exposed_fields(
    attributes: Mapping[str, object],
    identifiers: Mapping[str, set],
    subject_names: set,
    data_category: str,
) -> set:
    exposed = set()
    for field, value in attributes.items():
        key = str(field).casefold()
        if not _nonempty_value(value):
            continue
        identifier_type = _identifier_type_for_field(key)
        if identifier_type and _identifier_matches(
            identifier_type, value, identifiers
        ):
            exposed.add(str(field))
        elif key.endswith(("name", "full_name", "display_name")):
            normalized = str(value).strip().casefold()
            if normalized in subject_names:
                exposed.add(str(field))
        elif data_category == "ACCOUNT_TOMBSTONE" and key in {
            "name",
            "full_name",
            "display_name",
            "email",
            "phone",
            "email_hash",
        }:
            exposed.add(str(field))
    return exposed


def _identifier_type_for_field(field: str) -> Optional[str]:
    if field == "email" or field.endswith("_email"):
        return "email"
    if field == "phone" or field.endswith("_phone"):
        return "phone"
    if field == "email_hash" or field.endswith("_email_hash"):
        return "email_hash"
    return None


def _identifier_matches(
    identifier_type: str,
    value: object,
    identifiers: Mapping[str, set],
) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().casefold()
    if identifier_type == "phone":
        normalized = ("+" if normalized.startswith("+") else "") + "".join(
            character for character in normalized if character.isdigit()
        )
    return normalized in identifiers.get(identifier_type, set())


def _contains_subject_reference(
    attributes: Mapping[str, object], subject_user_id: str
) -> bool:
    keys = {
        "user_id",
        "subject_user_id",
        "subject_reference",
        "customer_reference",
        "customer_id",
    }
    return any(
        str(key).casefold() in keys
        and str(value).strip() == subject_user_id
        for key, value in attributes.items()
        if value is not None
    )


def _attribute_pairs(observations):
    for observation in observations:
        for field, value in observation.record.attributes.items():
            if isinstance(value, str):
                yield str(field).casefold(), value


def _merge_attributes(observations) -> Dict[str, object]:
    merged = {}
    for observation in observations:
        for key, value in observation.record.attributes.items():
            merged.setdefault(str(key).casefold(), value)
    return merged


def _normalize_subject_values(
    values: Mapping[str, Iterable[str]],
) -> Dict[str, set]:
    normalized = {}
    for key, candidates in values.items():
        identifier_type = str(key).strip().casefold()
        if identifier_type not in {"email", "phone", "email_hash"}:
            continue
        result = set()
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate.strip():
                continue
            value = candidate.strip().casefold()
            if identifier_type == "phone":
                value = ("+" if value.startswith("+") else "") + "".join(
                    character for character in value if character.isdigit()
                )
            result.add(value)
        normalized[identifier_type] = result
    return normalized


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "active", "enabled"}
    return False


def _nonempty_value(value: object) -> bool:
    return value is not None and (not isinstance(value, str) or bool(value.strip()))
