"""Time-bounded identity links assembled from identities, history, and evidence."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import DefaultDict, Dict, Iterable, List, Optional, Tuple

from .evidence_index import EvidenceIndex, IndexedEvidence
from .identity import normalize_email
from .models import DeletionRequest, Identity, IdentityEvent, Provenance


class IdentifierType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    EMAIL_HASH = "email_hash"


class IdentityLinkSource(str, Enum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    EVIDENCE = "EVIDENCE"


class IdentityLinkConfidence(str, Enum):
    STRONG = "STRONG"
    CANDIDATE = "CANDIDATE"


class IdentityLinkResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    UNMATCHED = "UNMATCHED"
    AMBIGUOUS = "AMBIGUOUS"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class IdentityLink:
    user_id: str
    identifier_type: IdentifierType
    normalized_value: str
    source: IdentityLinkSource
    confidence: IdentityLinkConfidence
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    provenance: Provenance
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.user_id.strip():
            raise ValueError("identity link user_id must not be empty")
        if not self.normalized_value:
            raise ValueError("identity link value must not be empty")
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and self.valid_from > self.valid_until
        ):
            raise ValueError("identity link validity interval is reversed")

    def is_valid_at(self, value: datetime) -> bool:
        return (
            (self.valid_from is None or self.valid_from <= value)
            and (self.valid_until is None or value < self.valid_until)
        )

    def is_known_at(self, cutoff: datetime) -> bool:
        return (
            self.provenance.available_at is not None
            and self.provenance.available_at <= cutoff
        )


@dataclass(frozen=True)
class IdentityLinkResolution:
    status: IdentityLinkResolutionStatus
    user_id: Optional[str]
    links: Tuple[IdentityLink, ...]
    candidates: Tuple[IdentityLink, ...]


_IDENTITY_FIELDS = {
    "email": IdentifierType.EMAIL,
    "phone": IdentifierType.PHONE,
    "email_hash": IdentifierType.EMAIL_HASH,
}
_EVIDENCE_USER_ID_KEYS = {
    "user_id",
    "subject_user_id",
    "customer_reference",
    "customer_id",
}


def normalize_identifier(identifier_type: IdentifierType, value: str) -> str:
    text = value.strip()
    if identifier_type == IdentifierType.EMAIL:
        return normalize_email(text)
    if identifier_type == IdentifierType.PHONE:
        digits = "".join(character for character in text if character.isdigit())
        return ("+" if text.startswith("+") else "") + digits
    return text.casefold()


class IdentityLinkResolver:
    """Resolve typed aliases without selecting among conflicting subjects."""

    def __init__(
        self,
        identities: Iterable[Identity],
        identity_events: Iterable[IdentityEvent],
        evidence_index: Optional[EvidenceIndex] = None,
    ) -> None:
        self._identities = tuple(identities)
        self._identity_events = tuple(identity_events)
        self._known_user_ids = {identity.user_id for identity in self._identities}
        self.links = self._build_links(evidence_index)
        by_identifier: DefaultDict[
            Tuple[IdentifierType, str], List[IdentityLink]
        ] = defaultdict(list)
        by_user: DefaultDict[str, List[IdentityLink]] = defaultdict(list)
        for link in self.links:
            by_identifier[(link.identifier_type, link.normalized_value)].append(link)
            by_user[link.user_id].append(link)
        self._by_identifier = {
            key: tuple(
                sorted(
                    items,
                    key=lambda item: (
                        item.valid_from.isoformat() if item.valid_from else "",
                        item.user_id,
                        item.source.value,
                        item.provenance.source_id,
                    ),
                )
            )
            for key, items in by_identifier.items()
        }
        self._by_user = {
            key: tuple(
                sorted(
                    items,
                    key=lambda item: (
                        item.identifier_type.value,
                        item.normalized_value,
                        item.valid_from.isoformat() if item.valid_from else "",
                        item.source.value,
                        item.provenance.source_id,
                    ),
                )
            )
            for key, items in by_user.items()
        }

    def links_for_user(self, user_id: str) -> Tuple[IdentityLink, ...]:
        return self._by_user.get(user_id, tuple())

    def resolve_request(self, request: DeletionRequest) -> IdentityLinkResolution:
        return self.resolve(
            IdentifierType.EMAIL,
            request.email,
            audit_at=request.audit_at,
            valid_at=request.requested_at,
        )

    def resolve(
        self,
        identifier_type: IdentifierType,
        value: str,
        audit_at: datetime,
        valid_at: Optional[datetime] = None,
    ) -> IdentityLinkResolution:
        normalized = normalize_identifier(identifier_type, value)
        if not normalized:
            return IdentityLinkResolution(
                IdentityLinkResolutionStatus.UNMATCHED, None, tuple(), tuple()
            )
        assertion_time = valid_at or audit_at
        known_links = tuple(
            link
            for link in self._by_identifier.get((identifier_type, normalized), ())
            if link.is_known_at(audit_at)
        )
        active_strong = tuple(
            link
            for link in known_links
            if link.confidence == IdentityLinkConfidence.STRONG
            and link.is_valid_at(assertion_time)
        )
        historical_fallback = tuple(
            link
            for link in known_links
            if not active_strong
            and link.confidence == IdentityLinkConfidence.STRONG
            and link.source == IdentityLinkSource.HISTORICAL
            and (link.valid_from is None or link.valid_from <= assertion_time)
            and link.valid_until is not None
            and link.valid_until <= assertion_time
        )
        strong = active_strong or historical_fallback
        candidates = tuple(
            link
            for link in known_links
            if link.confidence == IdentityLinkConfidence.CANDIDATE
            and (
                link.valid_from is None
                or link.valid_until is None
                or link.is_valid_at(assertion_time)
            )
        )
        strong_users = {link.user_id for link in strong}
        possible_users = strong_users | {link.user_id for link in candidates}
        if len(possible_users) > 1:
            status = IdentityLinkResolutionStatus.AMBIGUOUS
            user_id = None
        elif len(strong_users) == 1:
            status = IdentityLinkResolutionStatus.RESOLVED
            user_id = next(iter(strong_users))
        elif candidates:
            status = IdentityLinkResolutionStatus.UNCERTAIN
            user_id = None
        else:
            status = IdentityLinkResolutionStatus.UNMATCHED
            user_id = None
        return IdentityLinkResolution(status, user_id, strong, candidates)

    def _build_links(
        self, evidence_index: Optional[EvidenceIndex]
    ) -> Tuple[IdentityLink, ...]:
        links = self._build_history_links()
        links.extend(self._build_current_links())
        if evidence_index is not None:
            links.extend(self._build_evidence_links(evidence_index))
        return tuple(
            sorted(
                set(links),
                key=lambda item: (
                    item.identifier_type.value,
                    item.normalized_value,
                    item.valid_from.isoformat() if item.valid_from else "",
                    item.valid_until.isoformat() if item.valid_until else "",
                    item.user_id,
                    item.source.value,
                    item.provenance.source_id,
                    item.provenance.record_locator or "",
                ),
            )
        )

    def _build_history_links(self) -> List[IdentityLink]:
        events_by_field: DefaultDict[
            Tuple[str, IdentifierType], List[IdentityEvent]
        ] = defaultdict(list)
        for event in self._identity_events:
            identifier_type = _IDENTITY_FIELDS.get(event.field_name.strip().casefold())
            if identifier_type is not None and event.user_id in self._known_user_ids:
                events_by_field[(event.user_id, identifier_type)].append(event)

        links = []
        for (user_id, identifier_type), events in events_by_field.items():
            ordered = sorted(events, key=lambda event: (event.event_time, event.audit_id))
            active_value = ordered[0].old_value
            active_start = None
            active_source = ordered[0]
            for event in ordered:
                old_value = normalize_identifier(identifier_type, event.old_value)
                current_value = normalize_identifier(identifier_type, active_value)
                if old_value != current_value:
                    links.append(
                        self._history_link(
                            user_id,
                            identifier_type,
                            active_value,
                            active_start,
                            event.event_time,
                            active_source,
                            IdentityLinkConfidence.CANDIDATE,
                            "audit history transition does not continue the prior value",
                        )
                    )
                    active_value = event.new_value
                    active_start = event.event_time
                    active_source = event
                    continue
                links.append(
                    self._history_link(
                        user_id,
                        identifier_type,
                        active_value,
                        active_start,
                        event.event_time,
                        event,
                    )
                )
                active_value = event.new_value
                active_start = event.event_time
                active_source = event
            identity = next(
                item for item in self._identities if item.user_id == user_id
            )
            snapshot_value = getattr(identity, identifier_type.value)
            if normalize_identifier(identifier_type, snapshot_value) != normalize_identifier(
                identifier_type, active_value
            ):
                links.append(
                    self._history_link(
                        user_id,
                        identifier_type,
                        active_value,
                        active_start,
                        None,
                        active_source,
                        IdentityLinkConfidence.CANDIDATE,
                        "latest audit value conflicts with the current identity snapshot",
                    )
                )
            else:
                provenance = self._current_provenance(identity, identifier_type)
                links.append(
                    IdentityLink(
                        user_id=user_id,
                        identifier_type=identifier_type,
                        normalized_value=normalize_identifier(
                            identifier_type, snapshot_value
                        ),
                        source=IdentityLinkSource.CURRENT,
                        confidence=IdentityLinkConfidence.STRONG,
                        valid_from=active_start or identity.updated_at,
                        valid_until=None,
                        provenance=provenance,
                    )
                )
        return links

    def _build_current_links(self) -> List[IdentityLink]:
        links = []
        history_fields = {
            (event.user_id, _IDENTITY_FIELDS[event.field_name.strip().casefold()])
            for event in self._identity_events
            if event.user_id in self._known_user_ids
            and event.field_name.strip().casefold() in _IDENTITY_FIELDS
        }
        for identity in self._identities:
            for field_name, identifier_type in _IDENTITY_FIELDS.items():
                if (identity.user_id, identifier_type) in history_fields:
                    continue
                value = normalize_identifier(
                    identifier_type, getattr(identity, field_name)
                )
                if not value:
                    continue
                links.append(
                    IdentityLink(
                        user_id=identity.user_id,
                        identifier_type=identifier_type,
                        normalized_value=value,
                        source=IdentityLinkSource.CURRENT,
                        confidence=IdentityLinkConfidence.STRONG,
                        valid_from=identity.updated_at,
                        valid_until=None,
                        provenance=self._current_provenance(
                            identity, identifier_type
                        ),
                    )
                )
        return links

    def _current_provenance(
        self, identity: Identity, identifier_type: IdentifierType
    ) -> Provenance:
        return Provenance(
            source_type="current_identity",
            source_id=identity.user_id,
            source_path="user_identities.csv",
            record_locator="field={}".format(identifier_type.value),
            available_at=identity.updated_at,
        )

    def _history_link(
        self,
        user_id: str,
        identifier_type: IdentifierType,
        value: str,
        valid_from: Optional[datetime],
        valid_until: Optional[datetime],
        event: IdentityEvent,
        confidence: IdentityLinkConfidence = IdentityLinkConfidence.STRONG,
        reason: Optional[str] = None,
    ) -> IdentityLink:
        return IdentityLink(
            user_id=user_id,
            identifier_type=identifier_type,
            normalized_value=normalize_identifier(identifier_type, value),
            source=IdentityLinkSource.HISTORICAL,
            confidence=confidence,
            valid_from=valid_from,
            valid_until=valid_until,
            provenance=Provenance(
                source_type="audit_id",
                source_id=event.audit_id,
                source_path="user_audit_log.csv",
                record_locator="user_id={};field={}".format(
                    user_id, identifier_type.value
                ),
                available_at=event.event_time,
            ),
            reason=reason,
        )

    def _build_evidence_links(
        self, evidence_index: EvidenceIndex
    ) -> List[IdentityLink]:
        links = []
        for record in evidence_index.records:
            if record.fact.provenance.available_at is None:
                continue
            user_ids = self._evidence_user_ids(record)
            if not user_ids:
                continue
            aliases = self._evidence_aliases(record)
            if not aliases:
                continue
            uncertain_reasons = []
            if record.fact.observed_at is None:
                uncertain_reasons.append("evidence observation time is unresolved")
            if record.extraction_method == "tesseract-ocr":
                uncertain_reasons.append("OCR-extracted identifier is uncertain")
            confidence = (
                IdentityLinkConfidence.CANDIDATE
                if uncertain_reasons
                else IdentityLinkConfidence.STRONG
            )
            for user_id in user_ids:
                for identifier_type, value in aliases:
                    normalized_value = normalize_identifier(identifier_type, value)
                    if not normalized_value:
                        continue
                    observed_at = record.fact.observed_at
                    links.append(
                        IdentityLink(
                            user_id=user_id,
                            identifier_type=identifier_type,
                            normalized_value=normalized_value,
                            source=IdentityLinkSource.EVIDENCE,
                            confidence=confidence,
                            valid_from=observed_at,
                            valid_until=(
                                observed_at + timedelta(microseconds=1)
                                if observed_at is not None
                                else None
                            ),
                            provenance=record.fact.provenance,
                            reason="; ".join(uncertain_reasons) or None,
                        )
                    )
        return links

    def _evidence_user_ids(self, record: IndexedEvidence) -> Tuple[str, ...]:
        attributes = record.attributes
        values = []
        if record.fact.subject_user_id:
            values.append(record.fact.subject_user_id)
        for key, value in attributes.items():
            if (
                key.strip().casefold() in _EVIDENCE_USER_ID_KEYS
                and isinstance(value, (str, int))
                and not isinstance(value, bool)
            ):
                values.append(str(value).strip())
        return tuple(sorted({value for value in values if value in self._known_user_ids}))

    @staticmethod
    def _evidence_aliases(
        record: IndexedEvidence,
    ) -> Tuple[Tuple[IdentifierType, str], ...]:
        aliases = []
        for key, value in record.attributes.items():
            if not isinstance(value, str) or not value.strip():
                continue
            normalized_key = key.strip().casefold()
            identifier_type = None
            if normalized_key == "email" or normalized_key.endswith("_email"):
                identifier_type = IdentifierType.EMAIL
            elif normalized_key == "phone" or normalized_key.endswith("_phone"):
                identifier_type = IdentifierType.PHONE
            elif normalized_key == "email_hash" or normalized_key.endswith(
                "_email_hash"
            ):
                identifier_type = IdentifierType.EMAIL_HASH
            if identifier_type is not None:
                aliases.append((identifier_type, value))
        return tuple(sorted(set(aliases), key=lambda item: (item[0].value, item[1])))


def build_identity_link_resolver(
    identities: Iterable[Identity],
    identity_events: Iterable[IdentityEvent],
    evidence_index: Optional[EvidenceIndex] = None,
) -> IdentityLinkResolver:
    return IdentityLinkResolver(identities, identity_events, evidence_index)
