from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Tuple


class MatchSource(str, Enum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"


class ResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    UNMATCHED = "UNMATCHED"
    AMBIGUOUS = "AMBIGUOUS"


class InspectionStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"


@dataclass(frozen=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass(frozen=True)
class Identity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime


@dataclass(frozen=True)
class IdentityEvent:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class Provenance:
    source_type: str
    source_id: str
    source_path: Optional[str] = None
    record_locator: Optional[str] = None
    available_at: Optional[datetime] = None


@dataclass(frozen=True)
class EvidenceFile:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime


@dataclass(frozen=True)
class EvidenceFact:
    system_id: Optional[str]
    resource_id: Optional[str]
    data_category: Optional[str]
    observed_state: Optional[str]
    inspection_status: InspectionStatus
    provenance: Provenance
    subject_user_id: Optional[str] = None
    observed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.provenance.source_type.strip():
            raise ValueError("evidence provenance source_type must not be empty")
        if not self.provenance.source_id.strip():
            raise ValueError("evidence provenance source_id must not be empty")
        if (
            self.inspection_status == InspectionStatus.CONFIRMED
            and (self.observed_state is None or not self.observed_state.strip())
        ):
            raise ValueError("confirmed evidence must include an observed state")

    @property
    def confirms_presence(self) -> bool:
        return (
            self.inspection_status == InspectionStatus.CONFIRMED
            and self.observed_state == "PRESENT"
        )

    @property
    def confirms_absence(self) -> bool:
        return (
            self.inspection_status == InspectionStatus.CONFIRMED
            and self.observed_state == "ABSENT"
        )


@dataclass(frozen=True)
class SystemActivity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True)
class IdentityMatch:
    user_id: str
    identifier_type: str
    matched_value: str
    source: MatchSource
    provenance: Provenance


@dataclass(frozen=True)
class IdentityResolution:
    status: ResolutionStatus
    matches: Tuple[IdentityMatch, ...]

    @property
    def user_id(self) -> Optional[str]:
        user_ids = {match.user_id for match in self.matches}
        if self.status != ResolutionStatus.RESOLVED or len(user_ids) != 1:
            return None
        return next(iter(user_ids))
