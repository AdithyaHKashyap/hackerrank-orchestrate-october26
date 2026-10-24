import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Set, Tuple

from deletion_audit.csv_loader import (
    CSV_SCHEMAS,
    load_evidence_files,
    load_identity_events,
    load_requests,
    load_system_activity,
)
from deletion_audit.request_classifier import (
    AuthorizationStatus,
    classify_request,
)


OUTPUT_COLUMNS = CSV_SCHEMAS["output.csv"]
STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

OPERATIONS_BY_PHASE = {
    "FINDING": (
        ("REPORT_REMAINING_RECORD", "PRESENT"),
        ("REPORT_EXPOSED_PII", "PRESENT"),
        ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
        ("REPORT_RESTORE_RISK", "ACTIVE"),
    ),
    "REMEDIATION": (
        ("DISABLE_DATA_FLOW", "DISABLED"),
        ("BLOCK_RESTORE", "BLOCKED"),
        ("DELETE_RECORD", "ABSENT"),
        ("REDACT_RECORD", "REDACTED"),
        ("ANONYMIZE_RECORD", "ANONYMIZED"),
    ),
    "VERIFICATION": (
        ("VERIFY_RECORD_ABSENT", "ABSENT"),
        ("VERIFY_RECORD_PRESENT", "PRESENT"),
        ("VERIFY_RECORD_REDACTED", "REDACTED"),
        ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
        ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    ),
}

PHASE_ORDER = {phase: index for index, phase in enumerate(OPERATIONS_BY_PHASE)}
OPERATION_ORDER = {
    phase: {operation: index for index, (operation, _) in enumerate(operations)}
    for phase, operations in OPERATIONS_BY_PHASE.items()
}
OPERATION_STATES = {
    phase: dict(operations) for phase, operations in OPERATIONS_BY_PHASE.items()
}


@dataclass(frozen=True)
class ValidationIssue:
    row_number: Optional[int]
    case_id: Optional[str]
    message: str


@dataclass(frozen=True)
class ValidationReport:
    issues: Tuple[ValidationIssue, ...]
    row_count: int

    @property
    def is_valid(self) -> bool:
        return not self.issues


def load_allowed_evidence_ids(dataset_dir: Path) -> Set[str]:
    """Collect only participant-visible IDs allowed in output evidence_id fields."""
    dataset_dir = Path(dataset_dir)
    file_ids = load_evidence_files(dataset_dir / "evidence_files.csv")
    activity_ids = load_system_activity(dataset_dir / "system_activity.csv")
    audit_ids = load_identity_events(dataset_dir / "user_audit_log.csv")
    return (
        {item.file_id for item in file_ids}
        | {item.activity_id for item in activity_ids}
        | {item.audit_id for item in audit_ids}
    )


def load_evidence_reference_timestamps(dataset_dir: Path) -> Mapping[str, datetime]:
    """Return the participant-recorded time associated with each citeable ID."""
    dataset_dir = Path(dataset_dir)
    file_ids = load_evidence_files(dataset_dir / "evidence_files.csv")
    activity_ids = load_system_activity(dataset_dir / "system_activity.csv")
    audit_ids = load_identity_events(dataset_dir / "user_audit_log.csv")
    timestamps = {
        item.file_id: item.captured_at for item in file_ids
    }
    timestamps.update(
        {item.activity_id: item.event_time for item in activity_ids}
    )
    timestamps.update({item.audit_id: item.event_time for item in audit_ids})
    return timestamps


def validate_challenge_output(
    output_path: Path, dataset_dir: Path
) -> ValidationReport:
    dataset_dir = Path(dataset_dir)
    requests = load_requests(dataset_dir / "deletion_requests.csv")
    request_ids = [request.case_id for request in requests]
    report = validate_output(
        output_path,
        allowed_evidence_ids=load_allowed_evidence_ids(dataset_dir),
        expected_case_ids=request_ids,
        evidence_timestamps=load_evidence_reference_timestamps(dataset_dir),
        case_audit_at={request.case_id: request.audit_at for request in requests},
    )
    unauthorized_ids = {
        request.case_id
        for request in requests
        if classify_request(request.request_text).authorization
        == AuthorizationStatus.NOT_AUTHORIZED
    }
    issues = list(report.issues)
    try:
        with Path(output_path).open("r", encoding="utf-8-sig", newline="") as source:
            rows = csv.DictReader(source)
            for row_number, row in enumerate(rows, start=2):
                if (
                    row.get("deletion_status") == "NOT_APPLICABLE"
                    and row.get("case_id") not in unauthorized_ids
                ):
                    issues.append(
                        ValidationIssue(
                            row_number,
                            row.get("case_id"),
                            "NOT_APPLICABLE requires an explicitly unauthorized deletion request",
                        )
                    )
    except OSError as error:
        issues.append(
            ValidationIssue(
                None,
                None,
                "cannot verify request authorization in {}: {}".format(
                    output_path, error
                ),
            )
        )
    return ValidationReport(tuple(issues), report.row_count)


def validate_output(
    output_path: Path,
    allowed_evidence_ids: Iterable[str],
    expected_case_ids: Optional[Iterable[str]] = None,
    evidence_timestamps: Optional[Mapping[str, datetime]] = None,
    case_audit_at: Optional[Mapping[str, datetime]] = None,
) -> ValidationReport:
    path = Path(output_path)
    issues: List[ValidationIssue] = []
    evidence_ids = set(allowed_evidence_ids)

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if tuple(reader.fieldnames or ()) != OUTPUT_COLUMNS:
                return ValidationReport(
                    (
                        ValidationIssue(
                            None,
                            None,
                            "CSV header must be exactly {}".format(
                                ",".join(OUTPUT_COLUMNS)
                            ),
                        ),
                    ),
                    0,
                )
            rows = []
            for row_number, row in enumerate(reader, start=2):
                if None in row or any(value is None for value in row.values()):
                    issues.append(
                        ValidationIssue(
                            row_number,
                            row.get("case_id"),
                            "CSV row field count does not match the header",
                        )
                    )
                    continue
                rows.append((row_number, row))
    except OSError as error:
        return ValidationReport(
            (ValidationIssue(None, None, "cannot read {}: {}".format(path, error)),),
            0,
        )

    case_ids = [row.get("case_id", "") for _, row in rows]
    seen_cases = set()
    duplicate_cases = set()
    for case_id in case_ids:
        if not case_id:
            issues.append(ValidationIssue(None, None, "case_id must not be empty"))
        elif case_id in seen_cases:
            duplicate_cases.add(case_id)
            issues.append(
                ValidationIssue(None, case_id, "duplicate case_id")
            )
        seen_cases.add(case_id)

    if case_ids != sorted(case_ids):
        issues.append(
            ValidationIssue(None, None, "rows must be sorted by case_id")
        )

    if expected_case_ids is not None:
        expected = list(expected_case_ids)
        expected_set = set(expected)
        actual_set = set(case_ids)
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        if missing:
            issues.append(
                ValidationIssue(
                    None, None, "missing case_ids: {}".format(", ".join(missing))
                )
            )
        if extra:
            issues.append(
                ValidationIssue(
                    None, None, "unexpected case_ids: {}".format(", ".join(extra))
                )
            )
        if len(rows) != len(expected):
            issues.append(
                ValidationIssue(
                    None,
                    None,
                    "expected {} rows, found {}".format(len(expected), len(rows)),
                )
            )

    for row_number, row in rows:
        case_id = row.get("case_id")
        status = row.get("deletion_status")
        if status not in STATUSES:
            issues.append(
                ValidationIssue(
                    row_number,
                    case_id,
                    "deletion_status must be one of {}".format(
                        ", ".join(sorted(STATUSES))
                    ),
                )
            )

        try:
            steps = json.loads(
                row.get("steps_json", ""),
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError("invalid JSON constant {}".format(value))
                ),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            issues.append(
                ValidationIssue(
                    row_number, case_id, "steps_json is not valid JSON: {}".format(error)
                )
            )
            continue

        if not isinstance(steps, list):
            issues.append(
                ValidationIssue(row_number, case_id, "steps_json must be a JSON array")
            )
            continue

        if status == "NOT_APPLICABLE" and steps:
            issues.append(
                ValidationIssue(
                    row_number,
                    case_id,
                    "NOT_APPLICABLE rows must have an empty steps array",
                )
            )
        if status == "COMPLETE" and any(
            not isinstance(step, dict) or step.get("phase") != "VERIFICATION"
            for step in steps
        ):
            issues.append(
                ValidationIssue(
                    row_number,
                    case_id,
                    "COMPLETE rows may contain only VERIFICATION steps",
                )
            )
        if status == "COMPLETE" and not steps:
            issues.append(
                ValidationIssue(
                    row_number,
                    case_id,
                    "COMPLETE rows must include evidence-backed verification steps",
                )
            )

        if status == "INCOMPLETE":
            phases = {
                step.get("phase")
                for step in steps
                if isinstance(step, dict) and step.get("phase") in PHASE_ORDER
            }
            required_phases = {"FINDING", "REMEDIATION", "VERIFICATION"}
            if not required_phases.issubset(phases):
                issues.append(
                    ValidationIssue(
                        row_number,
                        case_id,
                        "INCOMPLETE rows must include FINDING, REMEDIATION, and VERIFICATION phases",
                    )
                )

        order_keys = []
        logical_steps = set()
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                issues.append(
                    ValidationIssue(
                        row_number, case_id, "step {} must be a JSON object".format(index)
                    )
                )
                continue

            actual_fields = set(step)
            expected_fields = set(STEP_FIELDS)
            if actual_fields != expected_fields:
                missing = sorted(expected_fields - actual_fields)
                extra = sorted(actual_fields - expected_fields)
                details = []
                if missing:
                    details.append("missing fields {}".format(", ".join(missing)))
                if extra:
                    details.append("unexpected fields {}".format(", ".join(extra)))
                issues.append(
                    ValidationIssue(
                        row_number,
                        case_id,
                        "step {} must have exactly seven fields ({})".format(
                            index, "; ".join(details)
                        ),
                    )
                )

            step_no = step.get("step_no")
            if isinstance(step_no, bool) or not isinstance(step_no, int) or step_no != index:
                issues.append(
                    ValidationIssue(
                        row_number,
                        case_id,
                        "step_no values must be consecutive starting at 1",
                    )
                )

            phase = step.get("phase")
            operation = step.get("operation")
            if not isinstance(phase, str) or phase not in OPERATIONS_BY_PHASE:
                issues.append(
                    ValidationIssue(
                        row_number, case_id, "step {} has invalid phase".format(index)
                    )
                )
                continue
            if (
                not isinstance(operation, str)
                or operation not in OPERATION_STATES[phase]
            ):
                issues.append(
                    ValidationIssue(
                        row_number,
                        case_id,
                        "step {} has an operation not allowed in {}".format(
                            index, phase
                        ),
                    )
                )
                continue
            if step.get("state") != OPERATION_STATES[phase][operation]:
                issues.append(
                    ValidationIssue(
                        row_number,
                        case_id,
                        "step {} state does not match its operation".format(index),
                    )
                )

            for field in ("system_id", "resource_id"):
                if not isinstance(step.get(field), str) or not step[field].strip():
                    issues.append(
                        ValidationIssue(
                            row_number,
                            case_id,
                            "step {} {} must be a non-empty string".format(index, field),
                        )
                    )

            evidence_id = step.get("evidence_id")
            if not isinstance(evidence_id, str):
                issues.append(
                    ValidationIssue(
                        row_number,
                        case_id,
                        "step {} evidence_id must be a string".format(index),
                    )
                )
            elif phase == "FINDING" or status == "COMPLETE":
                if evidence_id not in evidence_ids:
                    issues.append(
                        ValidationIssue(
                            row_number,
                            case_id,
                            "step {} must cite a valid participant evidence ID".format(
                                index
                            ),
                        )
                    )
                elif evidence_timestamps is not None and case_audit_at is not None:
                    evidence_time = evidence_timestamps.get(evidence_id)
                    audit_time = case_audit_at.get(case_id)
                    if evidence_time is None or audit_time is None:
                        issues.append(
                            ValidationIssue(
                                row_number,
                                case_id,
                                "step {} evidence or case has no verifiable timestamp".format(
                                    index
                                ),
                            )
                        )
                    elif evidence_time > audit_time:
                        issues.append(
                            ValidationIssue(
                                row_number,
                                case_id,
                                "step {} cites evidence created after audit_at".format(
                                    index
                                ),
                            )
                        )
            elif evidence_id != "":
                issues.append(
                    ValidationIssue(
                        row_number,
                        case_id,
                        "INCOMPLETE remediation and future verification evidence_id must be empty",
                    )
                )

            if phase in PHASE_ORDER and operation in OPERATION_ORDER[phase]:
                system_id = step.get("system_id")
                resource_id = step.get("resource_id")
                order_keys.append(
                    (
                        PHASE_ORDER[phase],
                        OPERATION_ORDER[phase][operation],
                        system_id if isinstance(system_id, str) else "",
                        resource_id if isinstance(resource_id, str) else "",
                    )
                )
                logical_key = (
                    phase,
                    operation,
                    system_id if isinstance(system_id, str) else None,
                    resource_id if isinstance(resource_id, str) else None,
                )
                if logical_key in logical_steps:
                    issues.append(
                        ValidationIssue(
                            row_number,
                            case_id,
                            "duplicate logical step at position {}".format(index),
                        )
                    )
                logical_steps.add(logical_key)

        if order_keys != sorted(order_keys):
            issues.append(
                ValidationIssue(
                    row_number,
                    case_id,
                    "steps must follow phase, operation, system_id, and resource_id ordering",
                )
            )

    return ValidationReport(tuple(issues), len(rows))
