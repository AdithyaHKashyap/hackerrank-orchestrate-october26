from collections import defaultdict
from datetime import datetime
from typing import DefaultDict, Iterable, List

from .models import (
    Identity,
    IdentityEvent,
    IdentityMatch,
    IdentityResolution,
    MatchSource,
    Provenance,
    ResolutionStatus,
)


def normalize_email(email: str) -> str:
    return email.strip().casefold()


class IdentityResolver:
    """Resolve an exact email against cutoff-valid current and audit records."""

    def __init__(
        self,
        identities: Iterable[Identity],
        identity_events: Iterable[IdentityEvent],
    ) -> None:
        self._current_by_email: DefaultDict[str, List[Identity]] = defaultdict(list)
        for identity in identities:
            self._current_by_email[normalize_email(identity.email)].append(identity)

        self._events_by_email: DefaultDict[str, List[IdentityEvent]] = defaultdict(list)
        for event in identity_events:
            if event.field_name.strip().casefold() != "email":
                continue
            for value in (event.old_value, event.new_value):
                normalized = normalize_email(value)
                if normalized:
                    self._events_by_email[normalized].append(event)

    def resolve(self, email: str, audit_at: datetime) -> IdentityResolution:
        normalized_email = normalize_email(email)
        if not normalized_email:
            return IdentityResolution(ResolutionStatus.UNMATCHED, tuple())

        matches = []
        for identity in self._current_by_email.get(normalized_email, ()):
            if identity.updated_at > audit_at:
                continue
            matches.append(
                IdentityMatch(
                    user_id=identity.user_id,
                    identifier_type="email",
                    matched_value=normalized_email,
                    source=MatchSource.CURRENT,
                    provenance=Provenance(
                        source_type="current_identity",
                        source_id=identity.user_id,
                        source_path="user_identities.csv",
                        available_at=identity.updated_at,
                    ),
                )
            )

        for event in self._events_by_email.get(normalized_email, ()):
            if event.event_time > audit_at:
                continue
            matches.append(
                IdentityMatch(
                    user_id=event.user_id,
                    identifier_type="email",
                    matched_value=normalized_email,
                    source=MatchSource.HISTORICAL,
                    provenance=Provenance(
                        source_type="audit_id",
                        source_id=event.audit_id,
                        source_path="user_audit_log.csv",
                        record_locator="user_id={}".format(event.user_id),
                        available_at=event.event_time,
                    ),
                )
            )

        unique_matches = {}
        for match in matches:
            key = (
                match.user_id,
                match.source,
                match.provenance.source_id,
            )
            unique_matches[key] = match
        ordered_matches = tuple(
            sorted(
                unique_matches.values(),
                key=lambda item: (
                    item.user_id,
                    item.source.value,
                    item.provenance.source_id,
                ),
            )
        )

        user_ids = {match.user_id for match in ordered_matches}
        if not user_ids:
            status = ResolutionStatus.UNMATCHED
        elif len(user_ids) == 1:
            status = ResolutionStatus.RESOLVED
        else:
            status = ResolutionStatus.AMBIGUOUS
        return IdentityResolution(status, ordered_matches)
