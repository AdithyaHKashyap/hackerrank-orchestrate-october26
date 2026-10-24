"""Run the evidence-grounded deletion audit from the repository root."""

import argparse
import csv
import json
import os
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple

from deletion_audit.coverage_grounding import EvidenceGrounder, normalize_evidence_index
from deletion_audit.csv_loader import load_dataset, load_requests
from deletion_audit.decision_engine import CaseDecision, decide_request
from deletion_audit.evidence_index import EvidenceIndex
from deletion_audit.identity_links import build_identity_link_resolver
from deletion_audit.policy_assessment import assess_request_policy
from deletion_audit.recreation_graph import build_recreation_graph
from deletion_audit.request_classifier import classify_request
from evaluation.output_validator import (
    load_allowed_evidence_ids,
    load_evidence_reference_timestamps,
    validate_challenge_output,
)
from evaluation.sample_scorer import score_sample


@dataclass(frozen=True)
class DatasetRunSummary:
    request_count: int
    status_counts: Mapping[str, int]
    blocked_count: int
    undecidable_case_ids: Tuple[str, ...]
    unresolved_case_count: int
    blocked_reason_counts: Mapping[str, int]
    blocked_detail_counts: Mapping[str, int]
    policy_assessment_counts: Mapping[str, int]
    assessment_counts_by_category: Mapping[str, int]
    unknown_assessment_reason_counts: Mapping[str, int]
    unmapped_scope_system_counts: Mapping[str, int]
    unmapped_scope_source_counts: Mapping[str, int]
    unmapped_scope_count: int
    evidence_file_status_counts: Mapping[str, int]
    evidence_record_count: int
    temporally_unresolved_record_count: int
    output_path: Optional[Path]
    output_valid: Optional[bool]
    sample_status_accuracy: Optional[float]
    sample_metrics: Optional[Mapping[str, object]]


def run_dataset(
    dataset_dir: Path,
    output_path: Path,
    request_path: Optional[Path] = None,
    sample_only: bool = False,
) -> DatasetRunSummary:
    dataset_dir = Path(dataset_dir).resolve()
    output_path = Path(output_path).resolve()
    inputs = load_dataset(dataset_dir)
    if sample_only and request_path is None:
        request_path = dataset_dir / "sample_deletion_requests.csv"
    if request_path is not None:
        request_path = Path(request_path).resolve()
        if sample_only and output_path == dataset_dir.parent / "output.csv":
            raise ValueError("sample-only predictions cannot overwrite root output.csv")
        requests = load_requests(request_path)
    else:
        requests = inputs.requests

    raw_index = EvidenceIndex.build(dataset_dir)
    evidence_index = normalize_evidence_index(raw_index)
    identity_resolver = build_identity_link_resolver(
        inputs.identities, inputs.identity_events, evidence_index
    )
    grounder = EvidenceGrounder(
        dataset_dir,
        evidence_index,
        identity_resolver,
        inputs.system_activity,
    )

    decisions = []
    sample_diagnostics = []
    policy_counts = Counter()
    category_counts = Counter()
    unknown_reasons = Counter()
    unmapped_systems = Counter()
    unmapped_sources = Counter()
    unmapped_scope_count = 0
    report_by_id = {
        report.evidence_id: report for report in evidence_index.report
    }
    for request in requests:
        classification = classify_request(request.request_text)
        resolution = identity_resolver.resolve_request(request)
        grounded = grounder.ground(request, resolution)
        links = (
            identity_resolver.links_for_user(grounded.subject_user_id)
            if grounded.subject_user_id
            else tuple()
        )
        identifiers = {}
        for link in links:
            if link.confidence.value == "STRONG" and link.is_known_at(request.audit_at):
                identifiers.setdefault(link.identifier_type.value, set()).add(
                    link.normalized_value
                )
        assessment = assess_request_policy(
            grounded,
            inputs.deletion_rules,
            subject_identifiers=identifiers,
        )
        for item in assessment.assessments:
            policy_counts[item.status.value] += 1
            category_counts[
                item.data_category or "UNMAPPED"
            ] += 1
            if item.status.value == "UNKNOWN":
                unknown_reasons[_assessment_reason(item)] += 1
            if item.rule_id is None:
                unmapped_systems[item.system_id or "<unknown-system>"] += 1
                source_labels = {
                    _evidence_source_label(report_by_id.get(evidence_id))
                    for evidence_id in (
                        item.evidence_ids + item.unresolved_evidence_ids
                    )
                }
                if not source_labels:
                    source_labels = {"<no-evidence-reference>"}
                for label in source_labels:
                    unmapped_sources[label] += 1
        unmapped_scope_count += assessment.unmapped_scope_count
        graph = build_recreation_graph(grounded)
        decision = decide_request(
            request, classification, grounded, assessment, graph
        )
        decisions.append(decision)
        if sample_only and decision.status is None:
            sample_diagnostics.append(
                _case_diagnostic(
                    request,
                    classification,
                    grounded,
                    assessment,
                    graph,
                    decision,
                    report_by_id,
                )
            )

    status_counts = Counter(
        decision.status.value for decision in decisions if decision.status is not None
    )
    blocked = [decision for decision in decisions if decision.status is None]
    undecidable_case_ids = tuple(
        sorted(decision.case_id for decision in blocked)
    )
    blocked_reasons = Counter(
        _reason_category(reason)
        for decision in decisions
        for reason in decision.unresolved_reasons
    )
    blocked_details = Counter(
        _reason_detail(reason)
        for decision in decisions
        for reason in decision.unresolved_reasons
    )
    unresolved_case_count = sum(
        bool(decision.unresolved_reasons) for decision in decisions
    )
    evidence_status_counts = Counter(item.status.value for item in evidence_index.report)
    unresolved_record_count = sum(
        item.temporally_unresolved_count for item in evidence_index.report
    )

    written_path = None
    output_valid = None
    sample_status_accuracy = None
    sample_metrics = None
    if sample_only:
        written_path = _write_candidate(decisions, output_path)
        diagnostics_path = (
            Path(__file__).resolve().parent
            / "evaluation"
            / "sample_case_diagnostics.csv"
        )
        _write_sample_diagnostics(diagnostics_path, sample_diagnostics)
        sample_score = _score_public_sample(
            written_path,
            dataset_dir,
            requests,
        )
        output_valid = sample_score.validation.is_valid
        sample_status_accuracy = sample_score.status_accuracy
        sample_metrics = {
            "case_count": sample_score.case_count,
            "candidate_row_count": sum(
                decision.status is not None for decision in decisions
            ),
            "missing_case_ids": list(undecidable_case_ids),
            "status_accuracy": sample_score.status_accuracy,
            "field_accuracy": sample_score.field_accuracy,
            "field_accuracy_by_name": dict(
                sample_score.field_accuracy_by_name
            ),
            "step_accuracy": sample_score.step_accuracy,
            "sequence_accuracy": sample_score.sequence_accuracy,
            "validation_is_valid": sample_score.validation.is_valid,
            "validation_error_count": len(sample_score.validation.issues),
            "validation_errors": [
                issue.message for issue in sample_score.validation.issues
            ],
            "diagnostics_path": str(diagnostics_path),
        }
    elif not blocked:
        written_path = _write_and_validate(
            decisions, output_path, dataset_dir
        )
        output_valid = True
        sample_requests = load_requests(dataset_dir / "sample_deletion_requests.csv")
        sample_score = _score_public_sample(
            written_path,
            dataset_dir,
            sample_requests,
        )
        sample_status_accuracy = sample_score.status_accuracy
        sample_metrics = {
            "case_count": sample_score.case_count,
            "status_accuracy": sample_score.status_accuracy,
            "field_accuracy": sample_score.field_accuracy,
            "step_accuracy": sample_score.step_accuracy,
            "sequence_accuracy": sample_score.sequence_accuracy,
            "validation_is_valid": sample_score.validation.is_valid,
        }

    return DatasetRunSummary(
        request_count=len(requests),
        status_counts=dict(sorted(status_counts.items())),
        blocked_count=len(blocked),
        undecidable_case_ids=undecidable_case_ids,
        unresolved_case_count=unresolved_case_count,
        blocked_reason_counts=dict(sorted(blocked_reasons.items())),
        blocked_detail_counts=dict(sorted(blocked_details.items())),
        policy_assessment_counts=dict(sorted(policy_counts.items())),
        assessment_counts_by_category=dict(sorted(category_counts.items())),
        unknown_assessment_reason_counts=dict(sorted(unknown_reasons.items())),
        unmapped_scope_system_counts=dict(sorted(unmapped_systems.items())),
        unmapped_scope_source_counts=dict(sorted(unmapped_sources.items())),
        unmapped_scope_count=unmapped_scope_count,
        evidence_file_status_counts=dict(sorted(evidence_status_counts.items())),
        evidence_record_count=len(evidence_index.records),
        temporally_unresolved_record_count=unresolved_record_count,
        output_path=written_path,
        output_valid=output_valid,
        sample_status_accuracy=sample_status_accuracy,
        sample_metrics=sample_metrics,
    )


def _write_and_validate(
    decisions: Tuple[CaseDecision, ...],
    output_path: Path,
    dataset_dir: Path,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".output-", suffix=".csv", dir=str(output_path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as destination:
            writer = csv.writer(destination)
            writer.writerow(("case_id", "deletion_status", "steps_json"))
            for decision in sorted(decisions, key=lambda item: item.case_id):
                if decision.status is None:
                    raise ValueError(
                        "cannot serialize unresolved decision for {}".format(
                            decision.case_id
                        )
                    )
                writer.writerow(
                    (
                        decision.case_id,
                        decision.status.value,
                        json.dumps(
                            list(decision.steps),
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    )
                )
        report = validate_challenge_output(temporary_path, dataset_dir)
        if not report.is_valid:
            details = "; ".join(issue.message for issue in report.issues[:10])
            raise ValueError(
                "generated output failed validation: {}".format(details)
            )
        os.replace(str(temporary_path), str(output_path))
        return output_path
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _write_candidate(
    decisions: Tuple[CaseDecision, ...], output_path: Path
) -> Path:
    """Write independently derived, decidable sample rows for scoring."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".sample-candidate-", suffix=".csv", dir=str(output_path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as destination:
            writer = csv.writer(destination)
            writer.writerow(("case_id", "deletion_status", "steps_json"))
            for decision in sorted(decisions, key=lambda item: item.case_id):
                if decision.status is None:
                    continue
                writer.writerow(
                    (
                        decision.case_id,
                        decision.status.value,
                        json.dumps(
                            list(decision.steps),
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    )
                )
        os.replace(str(temporary_path), str(output_path))
        return output_path
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _score_public_sample(output_path: Path, dataset_dir: Path, sample_requests):
    sample_ids = {request.case_id for request in sample_requests}
    with tempfile.TemporaryDirectory(prefix="deletion-audit-sample-") as temp_dir:
        candidate_path = Path(temp_dir) / "sample_predictions.csv"
        with Path(output_path).open(
            "r", encoding="utf-8-sig", newline=""
        ) as source, candidate_path.open(
            "w", encoding="utf-8", newline=""
        ) as destination:
            reader = csv.DictReader(source)
            writer = csv.DictWriter(
                destination,
                fieldnames=("case_id", "deletion_status", "steps_json"),
            )
            writer.writeheader()
            for row in reader:
                if row["case_id"] in sample_ids:
                    writer.writerow(row)
        return score_sample(
            candidate_path,
            dataset_dir / "sample_output.csv",
            allowed_evidence_ids=load_allowed_evidence_ids(dataset_dir),
            evidence_timestamps=load_evidence_reference_timestamps(dataset_dir),
            case_audit_at={
                request.case_id: request.audit_at for request in sample_requests
            },
        )


def _case_diagnostic(
    request,
    classification,
    grounded,
    assessment,
    graph,
    decision,
    reports_by_id,
):
    blocker_types = set()
    details = []
    if classification.authorization.value == "UNCERTAIN":
        blocker_types.add("authorization")
    if grounded.identity_status.value != "RESOLVED":
        blocker_types.add("identity")
    if not grounded.ledger.groups or any(
        item.system_id is None or item.resource_id is None
        for item in assessment.assessments
    ):
        blocker_types.add("missing_resource_evidence")
        if not grounded.ledger.groups:
            details.append(
                "No identity-linked, system/resource-scoped evidence was available by audit_at."
            )
    if any(item.rule_id is None for item in assessment.assessments):
        blocker_types.add("unmapped_policy_category")
    if any(
        item.status.value == "UNKNOWN" and item.rule_id is not None
        for item in assessment.assessments
    ):
        blocker_types.add("unknown_state")
    if any(
        reason.startswith("No evidence-backed verification")
        for reason in decision.unresolved_reasons
    ):
        blocker_types.add("missing_verification")
    if any(
        edge.risk_state.value == "UNKNOWN"
        and edge.temporal_disposition.value == "ELIGIBLE"
        for edge in graph.edges
    ):
        blocker_types.add("unknown_recreation_risk")

    details.extend(decision.unresolved_reasons)
    for item in assessment.assessments:
        if item.status.value == "UNKNOWN":
            details.append(
                "Policy scope {}/{}/{}: {}".format(
                    item.system_id or "<missing-system>",
                    item.resource_id or "<missing-resource>",
                    item.data_category or "<unmapped>",
                    item.explanation,
                )
            )

    evidence_trace = []
    observations = (
        grounded.ledger.eligible
        + grounded.ledger.excluded
        + grounded.ledger.unresolved
    )
    for observation in observations:
        record = observation.record
        report = reports_by_id.get(record.evidence_id)
        evidence_trace.append(
            {
                "evidence_id": record.evidence_id,
                "source_path": record.source_path,
                "extraction_status": (
                    report.status.value if report is not None else "REPORT_MISSING"
                ),
                "extraction_method": record.extraction_method,
                "record_locator": record.fact.provenance.record_locator,
                "temporal_disposition": observation.temporal_disposition.value,
                "observed_at": (
                    record.fact.observed_at.isoformat()
                    if record.fact.observed_at
                    else None
                ),
                "available_at": (
                    record.fact.provenance.available_at.isoformat()
                    if record.fact.provenance.available_at
                    else None
                ),
                "system_id": record.fact.system_id,
                "resource_id": record.fact.resource_id,
                "data_category": record.fact.data_category,
                "observation_kind": observation.kind.value,
                "inspection_status": record.fact.inspection_status.value,
                "observed_state": record.fact.observed_state,
            }
        )
    for item in grounded.activity:
        evidence_trace.append(
            {
                "evidence_id": item.activity.activity_id,
                "source_path": "dataset/system_activity.csv",
                "extraction_status": "STRUCTURED_CSV",
                "extraction_method": "system_activity",
                "record_locator": item.activity.activity_id,
                "temporal_disposition": item.temporal_disposition.value,
                "observed_at": item.activity.event_time.isoformat(),
                "available_at": item.activity.event_time.isoformat(),
                "system_id": item.system_id,
                "resource_id": item.resource_id,
                "data_category": None,
                "observation_kind": item.kind.value,
                "inspection_status": "INCONCLUSIVE",
                "observed_state": None,
                "supporting_evidence_ids": list(item.supporting_evidence_ids),
            }
        )

    assessment_details = [
        {
            "system_id": item.system_id,
            "resource_id": item.resource_id,
            "data_category": item.data_category,
            "rule_id": item.rule_id,
            "required_action": item.required_action,
            "applicable": item.applicable,
            "status": item.status.value,
            "evidence_ids": list(item.evidence_ids),
            "unresolved_evidence_ids": list(item.unresolved_evidence_ids),
            "excluded_evidence_ids": list(item.excluded_evidence_ids),
            "explanation": item.explanation,
        }
        for item in assessment.assessments
    ]
    return {
        "case_id": request.case_id,
        "authorization_status": classification.authorization.value,
        "identity_status": grounded.identity_status.value,
        "blocker_types": sorted(blocker_types),
        "blocker_details_json": json.dumps(
            sorted(set(details)), ensure_ascii=False, sort_keys=True
        ),
        "assessments_json": json.dumps(
            assessment_details, ensure_ascii=False, sort_keys=True
        ),
        "evidence_trace_json": json.dumps(
            sorted(
                evidence_trace,
                key=lambda item: (
                    item["evidence_id"],
                    item["record_locator"] or "",
                    item["temporal_disposition"],
                ),
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    }


def _write_sample_diagnostics(path: Path, diagnostics) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as destination:
        fieldnames = (
            "case_id",
            "authorization_status",
            "identity_status",
            "blocker_types",
            "blocker_details_json",
            "assessments_json",
            "evidence_trace_json",
        )
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(diagnostics, key=lambda value: value["case_id"]):
            row = dict(item)
            row["blocker_types"] = json.dumps(row["blocker_types"])
            writer.writerow(row)
    return path


def _reason_category(reason: str) -> str:
    if "authorization" in reason.casefold():
        return "authorization_unresolved"
    if "identity" in reason.casefold():
        return "identity_unresolved"
    if "unknown" in reason.casefold() or "unresolved" in reason.casefold():
        return "evidence_or_policy_unknown"
    if "no permitted" in reason.casefold() or "no matching allowed" in reason.casefold():
        return "unrepresentable_policy_violation"
    if "verification" in reason.casefold():
        return "verification_unsupported"
    return "other"


def _assessment_reason(assessment) -> str:
    explanation = assessment.explanation.casefold()
    if assessment.rule_id is None:
        return "no_supported_category_rule"
    if "condition" in explanation or "whether the rule condition" in explanation:
        return "rule_condition_unknown"
    if "tombstone" in explanation or "redaction" in explanation:
        return "redaction_state_unknown"
    if "anonym" in explanation or "unlink" in explanation:
        return "anonymization_state_unknown"
    if "resource state" in explanation or "inspection" in explanation:
        return "resource_state_unknown"
    return "other_policy_unknown"


def _evidence_source_label(report) -> str:
    if report is None:
        return "<missing-extraction-report>"
    suffix = Path(report.source_path).suffix.casefold() or "<no-extension>"
    return "{}:{}".format(suffix, report.status.value)


def _reason_detail(reason: str) -> str:
    if reason.startswith("No evidence-backed verification"):
        return "no_evidence_backed_verification"
    if reason.startswith("No permitted remediation"):
        return "no_permitted_remediation"
    if reason.startswith("The policy violation has no matching allowed finding"):
        return "no_allowed_finding_for_violation"
    if reason.startswith("A policy violation lacks a grounded resource"):
        return "violation_missing_grounded_resource_or_evidence"
    if reason.startswith("Policy state is unknown"):
        return "policy_state_unknown"
    if reason.startswith("Deletion authorization"):
        return "authorization_unresolved"
    if reason.startswith("Subject identity"):
        return "identity_unresolved"
    if reason.startswith("An active recreation path"):
        return "recreation_path_missing_citation"
    if reason.startswith("An eligible data-flow"):
        return "recreation_state_unknown"
    if reason.startswith("Subject-linked evidence"):
        return "temporally_unresolved_evidence"
    if reason.startswith("No evidence-backed verification steps"):
        return "no_verification_steps"
    return "other"


def main() -> int:
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=repository_root / "dataset",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--sample-only",
        action="store_true",
        help="audit sample_deletion_requests.csv and score a separate candidate",
    )
    arguments = parser.parse_args()

    output_path = arguments.output
    request_path = None
    if arguments.sample_only:
        request_path = arguments.dataset / "sample_deletion_requests.csv"
        if output_path is None:
            output_path = (
                repository_root / "code" / "evaluation" / "sample_predictions.csv"
            )
    elif output_path is None:
        output_path = repository_root / "output.csv"

    summary = run_dataset(
        arguments.dataset,
        output_path,
        request_path=request_path,
        sample_only=arguments.sample_only,
    )
    print(
        json.dumps(
            {
                "request_count": summary.request_count,
                "status_counts": summary.status_counts,
                "blocked_count": summary.blocked_count,
                "undecidable_case_ids": summary.undecidable_case_ids,
                "unresolved_case_count": summary.unresolved_case_count,
                "blocked_reason_counts": summary.blocked_reason_counts,
                "blocked_detail_counts": summary.blocked_detail_counts,
                "policy_assessment_counts": summary.policy_assessment_counts,
                "assessment_counts_by_category": (
                    summary.assessment_counts_by_category
                ),
                "unknown_assessment_reason_counts": (
                    summary.unknown_assessment_reason_counts
                ),
                "unmapped_scope_system_counts": (
                    summary.unmapped_scope_system_counts
                ),
                "unmapped_scope_source_counts": (
                    summary.unmapped_scope_source_counts
                ),
                "unmapped_scope_count": summary.unmapped_scope_count,
                "evidence_file_status_counts": summary.evidence_file_status_counts,
                "evidence_record_count": summary.evidence_record_count,
                "temporally_unresolved_record_count": (
                    summary.temporally_unresolved_record_count
                ),
                "output_path": (
                    str(summary.output_path) if summary.output_path else None
                ),
                "output_valid": summary.output_valid,
                "sample_status_accuracy": summary.sample_status_accuracy,
                "sample_metrics": summary.sample_metrics,
            },
            sort_keys=True,
        )
    )
    return 0 if summary.blocked_count == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
