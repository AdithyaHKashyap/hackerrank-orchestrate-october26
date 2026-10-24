from datetime import datetime, timezone
from typing import Iterable, List, Optional

from .errors import DataValidationError
from .models import DeletionRequest, EvidenceFact


def parse_timestamp(value: str, context: str = "timestamp") -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    text = value.strip()
    if not text:
        raise DataValidationError("{} is empty".format(context))

    if text[-1:] in {"Z", "z"}:
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise DataValidationError(
            "{} is not a valid ISO-8601 timestamp: {!r}".format(context, value)
        ) from error

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DataValidationError(
            "{} must include a timezone offset: {!r}".format(context, value)
        )
    return parsed.astimezone(timezone.utc)


def is_at_or_before(
    timestamp: Optional[datetime], cutoff: datetime
) -> bool:
    if timestamp is None:
        return False
    return timestamp <= cutoff


def evidence_available_for_request(
    fact: EvidenceFact, request: DeletionRequest
) -> bool:
    available_at = fact.provenance.available_at
    if not is_at_or_before(available_at, request.audit_at):
        return False
    if fact.observed_at is not None and not is_at_or_before(
        fact.observed_at, request.audit_at
    ):
        return False
    return True


def filter_evidence_for_request(
    facts: Iterable[EvidenceFact], request: DeletionRequest
) -> List[EvidenceFact]:
    return [
        fact for fact in facts if evidence_available_for_request(fact, request)
    ]
