import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .models import AccessRequest


LOG_PATH = Path(__file__).resolve().parents[2] / "logs" / "access.log"

_logger = logging.getLogger("abac.audit")
_logger.setLevel(logging.INFO)
_logger.propagate = False

if not _logger.handlers:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)


def record_access(request: AccessRequest, allowed: bool, reason: str) -> None:
    """Write one JSON audit entry for an access decision."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": request.subject.user_id,
        "subject_tenant": request.subject.tenant_id,
        "resource_id": request.resource.resource_id,
        "resource_tenant": request.resource.tenant_id,
        "action": request.action.value,
        "decision": "ALLOW" if allowed else "DENY",
        "reason": reason,
    }
    _logger.info(json.dumps(entry))