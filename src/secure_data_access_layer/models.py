from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, StrEnum


class Action(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


class Classification(IntEnum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4


@dataclass(frozen=True)
class Subject:
    """The person or service requesting access."""
    user_id: str
    role: str
    tenant_id: str
    clearance: Classification


@dataclass(frozen=True)
class Resource:
    """The data being requested."""
    resource_id: str
    tenant_id: str
    classification: Classification


@dataclass(frozen=True)
class Environment:
    """Conditions at the time of the request."""
    requested_at: datetime
    mfa_verified: bool


@dataclass(frozen=True)
class AccessRequest:
    """All attributes the policy engine needs to evaluate."""
    subject: Subject
    resource: Resource
    action: Action
    environment: Environment