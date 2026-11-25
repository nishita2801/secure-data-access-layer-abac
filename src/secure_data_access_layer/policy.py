from dataclasses import dataclass

from .models import Action, AccessRequest, Classification


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def evaluate_access(request: AccessRequest) -> Decision:
    """Evaluate access using subject, resource, action, and environment attributes."""

    # Tenant isolation: users can only request data from their own tenant.
    if request.subject.tenant_id != request.resource.tenant_id:
        return Decision(False, "Subject and resource belong to different tenants.")

    # The subject's clearance must meet the resource's classification.
    if request.subject.clearance < request.resource.classification:
        return Decision(
            False,
            "Subject clearance is below the resource classification.",
        )

    # Sensitive data requires MFA.
    if (
        request.resource.classification >= Classification.CONFIDENTIAL
        and not request.environment.mfa_verified
    ):
        return Decision(
            False,
            "MFA is required for confidential or restricted data.",
        )

    # The current data service implements reads only.
    if request.action != Action.READ:
        return Decision(
            False,
            "Write and delete operations are not implemented by this demo.",
        )

    return Decision(True, "Access granted.")