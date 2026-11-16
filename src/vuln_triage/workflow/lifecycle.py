from __future__ import annotations

from enum import Enum


class ReassessmentCause(str, Enum):
    DEPLOYMENT_CHANGED = "deployment_changed"
    ADVISORY_UPDATED = "advisory_updated"
    THREAT_INTEL_UPDATED = "threat_intel_updated"
    SUPPRESSION_EXPIRED = "suppression_expired"
    MANUAL_REVOCATION = "manual_revocation"
