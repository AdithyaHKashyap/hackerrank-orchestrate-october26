import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

from .output_validator import (
    STEP_FIELDS,
    ValidationReport,
    validate_output,
)


@dataclass(frozen=True)
class SampleScore:
    case_count: int
    status_correct: int
    status_accuracy: float
    field_correct: int
    field_count: int
    field_accuracy: float
    field_accuracy_by_name: Mapping[str, float]
    step_correct: int
    step_count: int
    step_accuracy: float
    sequence_correct: int
    sequence_accuracy: float
    validation: ValidationReport


def _read_rows(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def _load_prediction_map(
    rows: Iterable[Mapping[str, str]],
) -> Dict[str, Mapping[str, object]]:
    candidates: Dict[str, Mapping[str, object]] = {}
    duplicates = set()
    for row in rows:
        case_id = row.get("case_id", "")
        if not case_id:
            continue
        if case_id in candidates:
            duplicates.add(case_id)
            continue
        try:
            steps = json.loads(row.get("steps_json", ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            steps = None
        candidates[case_id] = {
            "deletion_status": row.get("deletion_status"),
            "steps": steps if isinstance(steps, list) else None,
        }
    for case_id in duplicates:
        candidates.pop(case_id, None)
    return candidates


def score_sample(
    candidate_path: Path,
    sample_output_path: Path,
    allowed_evidence_ids: Iterable[str],
    evidence_timestamps: Optional[Mapping[str, datetime]] = None,
    case_audit_at: Optional[Mapping[str, datetime]] = None,
) -> SampleScore:
    expected_rows = _read_rows(sample_output_path)
    candidate_rows = _read_rows(candidate_path)
    expected_ids = [row["case_id"] for row in expected_rows]
    validation = validate_output(
        candidate_path,
        allowed_evidence_ids=allowed_evidence_ids,
        expected_case_ids=expected_ids,
        evidence_timestamps=evidence_timestamps,
        case_audit_at=case_audit_at,
    )
    expected_by_id = {row["case_id"]: row for row in expected_rows}
    candidate_by_id = _load_prediction_map(candidate_rows)

    status_correct = 0
    sequence_correct = 0
    field_correct_by_name = {field: 0 for field in STEP_FIELDS}
    field_count_by_name = {field: 0 for field in STEP_FIELDS}
    step_correct = 0
    step_count = 0

    for case_id, expected in expected_by_id.items():
        candidate = candidate_by_id.get(case_id)
        if (
            candidate is not None
            and candidate["deletion_status"] == expected["deletion_status"]
        ):
            status_correct += 1

        expected_steps = json.loads(expected["steps_json"])
        candidate_steps = candidate["steps"] if candidate is not None else None
        if candidate_steps is None:
            candidate_steps_for_score = []
            sequence_exact = False
        else:
            candidate_steps_for_score = candidate_steps
            sequence_exact = candidate_steps == expected_steps
        if sequence_exact:
            sequence_correct += 1

        aligned_count = max(len(expected_steps), len(candidate_steps_for_score))
        for index in range(aligned_count):
            expected_step = (
                expected_steps[index] if index < len(expected_steps) else None
            )
            candidate_step = (
                candidate_steps_for_score[index]
                if index < len(candidate_steps_for_score)
                else None
            )
            step_count += 1
            if (
                isinstance(expected_step, dict)
                and isinstance(candidate_step, dict)
                and candidate_step == expected_step
            ):
                step_correct += 1
            for field in STEP_FIELDS:
                field_count_by_name[field] += 1
                if (
                    isinstance(expected_step, dict)
                    and isinstance(candidate_step, dict)
                    and candidate_step.get(field) == expected_step.get(field)
                ):
                    field_correct_by_name[field] += 1

    expected_case_count = len(expected_by_id)
    expected_field_count = sum(field_count_by_name.values())
    expected_step_count = step_count
    return SampleScore(
        case_count=expected_case_count,
        status_correct=status_correct,
        status_accuracy=_ratio(status_correct, expected_case_count),
        field_correct=sum(field_correct_by_name.values()),
        field_count=expected_field_count,
        field_accuracy_by_name={
            field: _ratio(field_correct_by_name[field], field_count_by_name[field])
            for field in STEP_FIELDS
        },
        field_accuracy=_ratio(
            sum(field_correct_by_name.values()), expected_field_count
        ),
        step_correct=step_correct,
        step_count=expected_step_count,
        step_accuracy=_ratio(step_correct, expected_step_count),
        sequence_correct=sequence_correct,
        sequence_accuracy=_ratio(sequence_correct, expected_case_count),
        validation=validation,
    )


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0
