import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple, TypeVar

from .errors import DataValidationError
from .models import (
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    Identity,
    IdentityEvent,
    SystemActivity,
)
from .temporal import parse_timestamp


CSV_SCHEMAS = {
    "deletion_requests.csv": (
        "case_id",
        "email",
        "requested_at",
        "reported_status",
        "reported_at",
        "audit_at",
        "request_text",
    ),
    "sample_deletion_requests.csv": (
        "case_id",
        "email",
        "requested_at",
        "reported_status",
        "reported_at",
        "audit_at",
        "request_text",
    ),
    "user_identities.csv": (
        "user_id",
        "name",
        "email",
        "phone",
        "email_hash",
        "updated_at",
    ),
    "user_audit_log.csv": (
        "audit_id",
        "user_id",
        "event_time",
        "field_name",
        "old_value",
        "new_value",
    ),
    "system_activity.csv": (
        "activity_id",
        "event_time",
        "event_type",
        "source_system",
        "target_system",
        "resource_id",
        "reported_result",
        "details",
    ),
    "deletion_rules.csv": (
        "rule_id",
        "data_category",
        "condition",
        "required_action",
    ),
    "evidence_files.csv": ("file_id", "file_path", "origin", "captured_at"),
    "sample_output.csv": ("case_id", "deletion_status", "steps_json"),
    "output.csv": ("case_id", "deletion_status", "steps_json"),
}

T = TypeVar("T")


@dataclass(frozen=True)
class DatasetInputs:
    requests: Tuple[DeletionRequest, ...]
    identities: Tuple[Identity, ...]
    identity_events: Tuple[IdentityEvent, ...]
    system_activity: Tuple[SystemActivity, ...]
    deletion_rules: Tuple[DeletionRule, ...]
    evidence_files: Tuple[EvidenceFile, ...]


def _read_rows(path: Path, expected_columns: Sequence[str]) -> List[Dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            actual_columns = reader.fieldnames
            if actual_columns is None:
                raise DataValidationError("{} has no CSV header".format(path))
            if tuple(actual_columns) != tuple(expected_columns):
                raise DataValidationError(
                    "{} has columns {}; expected {}".format(
                        path, actual_columns, list(expected_columns)
                    )
                )

            rows = []
            for line_number, row in enumerate(reader, start=2):
                if None in row:
                    raise DataValidationError(
                        "{}:{} has more fields than its header".format(
                            path, line_number
                        )
                    )
                if any(value is None for value in row.values()):
                    raise DataValidationError(
                        "{}:{} has fewer fields than its header".format(
                            path, line_number
                        )
                    )
                rows.append(row)
            return rows
    except OSError as error:
        raise DataValidationError("cannot read {}: {}".format(path, error)) from error


def validate_dataset_csv_schemas(dataset_dir: Path) -> None:
    for filename, columns in CSV_SCHEMAS.items():
        _read_rows(Path(dataset_dir) / filename, columns)


def _required(
    row: Mapping[str, str], column: str, path: Path, line_number: int
) -> str:
    value = row.get(column)
    if value is None or not value.strip():
        raise DataValidationError(
            "{}:{} has an empty required value in {!r}".format(
                path, line_number, column
            )
        )
    return value.strip()


def _timestamp(
    row: Mapping[str, str], column: str, path: Path, line_number: int
):
    value = _required(row, column, path, line_number)
    return parse_timestamp(
        value, "{}:{} column {!r}".format(path, line_number, column)
    )


def _unique(items: Iterable[T], key, label: str) -> Tuple[T, ...]:
    result = tuple(items)
    seen = set()
    for item in result:
        value = key(item)
        if value in seen:
            raise DataValidationError(
                "{} contains duplicate identifier {!r}".format(label, value)
            )
        seen.add(value)
    return result


def load_requests(path: Path) -> Tuple[DeletionRequest, ...]:
    rows = _read_rows(path, CSV_SCHEMAS["deletion_requests.csv"])
    items = []
    for line_number, row in enumerate(rows, start=2):
        reported_status = _required(row, "reported_status", path, line_number)
        if reported_status not in {
            "COMPLETE",
            "PARTIALLY_COMPLETE",
            "NOT_STARTED",
        }:
            raise DataValidationError(
                "{}:{} has unsupported reported_status {!r}".format(
                    path, line_number, reported_status
                )
            )
        items.append(
            DeletionRequest(
                case_id=_required(row, "case_id", path, line_number),
                email=_required(row, "email", path, line_number),
                requested_at=_timestamp(row, "requested_at", path, line_number),
                reported_status=reported_status,
                reported_at=_timestamp(row, "reported_at", path, line_number),
                audit_at=_timestamp(row, "audit_at", path, line_number),
                request_text=_required(row, "request_text", path, line_number),
            )
        )
    return _unique(items, lambda item: item.case_id, str(path))


def load_identities(path: Path) -> Tuple[Identity, ...]:
    rows = _read_rows(path, CSV_SCHEMAS["user_identities.csv"])
    items = []
    for line_number, row in enumerate(rows, start=2):
        items.append(
            Identity(
                user_id=_required(row, "user_id", path, line_number),
                name=_required(row, "name", path, line_number),
                email=_required(row, "email", path, line_number),
                phone=_required(row, "phone", path, line_number),
                email_hash=_required(row, "email_hash", path, line_number),
                updated_at=_timestamp(row, "updated_at", path, line_number),
            )
        )
    return _unique(items, lambda item: item.user_id, str(path))


def load_identity_events(path: Path) -> Tuple[IdentityEvent, ...]:
    rows = _read_rows(path, CSV_SCHEMAS["user_audit_log.csv"])
    items = []
    for line_number, row in enumerate(rows, start=2):
        items.append(
            IdentityEvent(
                audit_id=_required(row, "audit_id", path, line_number),
                user_id=_required(row, "user_id", path, line_number),
                event_time=_timestamp(row, "event_time", path, line_number),
                field_name=_required(row, "field_name", path, line_number),
                old_value=_required(row, "old_value", path, line_number),
                new_value=_required(row, "new_value", path, line_number),
            )
        )
    return _unique(items, lambda item: item.audit_id, str(path))


def load_evidence_files(path: Path) -> Tuple[EvidenceFile, ...]:
    rows = _read_rows(path, CSV_SCHEMAS["evidence_files.csv"])
    items = []
    for line_number, row in enumerate(rows, start=2):
        items.append(
            EvidenceFile(
                file_id=_required(row, "file_id", path, line_number),
                file_path=_required(row, "file_path", path, line_number),
                origin=_required(row, "origin", path, line_number),
                captured_at=_timestamp(row, "captured_at", path, line_number),
            )
        )
    return _unique(items, lambda item: item.file_id, str(path))


def load_system_activity(path: Path) -> Tuple[SystemActivity, ...]:
    rows = _read_rows(path, CSV_SCHEMAS["system_activity.csv"])
    items = []
    for line_number, row in enumerate(rows, start=2):
        items.append(
            SystemActivity(
                activity_id=_required(row, "activity_id", path, line_number),
                event_time=_timestamp(row, "event_time", path, line_number),
                event_type=_required(row, "event_type", path, line_number),
                source_system=_required(row, "source_system", path, line_number),
                target_system=_required(row, "target_system", path, line_number),
                resource_id=_required(row, "resource_id", path, line_number),
                reported_result=_required(row, "reported_result", path, line_number),
                details=_required(row, "details", path, line_number),
            )
        )
    return _unique(items, lambda item: item.activity_id, str(path))


def load_deletion_rules(path: Path) -> Tuple[DeletionRule, ...]:
    rows = _read_rows(path, CSV_SCHEMAS["deletion_rules.csv"])
    items = []
    for line_number, row in enumerate(rows, start=2):
        items.append(
            DeletionRule(
                rule_id=_required(row, "rule_id", path, line_number),
                data_category=_required(row, "data_category", path, line_number),
                condition=_required(row, "condition", path, line_number),
                required_action=_required(row, "required_action", path, line_number),
            )
        )
    _unique(items, lambda item: item.rule_id, str(path))
    return _unique(items, lambda item: item.data_category, str(path))


def load_dataset(dataset_dir: Path) -> DatasetInputs:
    dataset_dir = Path(dataset_dir)
    validate_dataset_csv_schemas(dataset_dir)
    return DatasetInputs(
        requests=load_requests(dataset_dir / "deletion_requests.csv"),
        identities=load_identities(dataset_dir / "user_identities.csv"),
        identity_events=load_identity_events(dataset_dir / "user_audit_log.csv"),
        system_activity=load_system_activity(dataset_dir / "system_activity.csv"),
        deletion_rules=load_deletion_rules(dataset_dir / "deletion_rules.csv"),
        evidence_files=load_evidence_files(dataset_dir / "evidence_files.csv"),
    )
