from dataclasses import dataclass

from .models import Action, AccessRequest, Classification


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


ROLE_ACTIONS = {
    "analyst": {Action.READ},
    "engineer": {Action.READ, Action.WRITE},
    "admin": {Action.READ, Action.WRITE, Action.DELETE},
}


def evaluate_access(request: AccessRequest) -> Decision:
    """Evaluate a request and deny access by default when a rule fails."""

    if request.subject.tenant_id != request.resource.tenant_id:
        return Decision(False, "Subject and resource belong to different tenants.")

    allowed_actions = ROLE_ACTIONS.get(request.subject.role.lower(), set())
    if request.action not in allowed_actions:
        return Decision(False, "This role is not allowed to perform this action.")

    if request.subject.clearance < request.resource.classification:
        return Decision(False, "Subject clearance is below the resource classification.")

    if (
        request.resource.classification >= Classification.CONFIDENTIAL
        and not request.environment.mfa_verified
    ):
        return Decision(False, "MFA is required for confidential or restricted data.")

    return Decision(True, "Access granted.")