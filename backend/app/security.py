from datetime import datetime, timezone
from typing import Any
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import get_settings
from app.services.redaction import redaction_service


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def mask_value(value: str) -> str:
    return redaction_service.mask_value(value)


def redact_sensitive(text: str, limit: int = 12000) -> str:
    return redaction_service.redact_text(text, limit)


def redact_url(url: str) -> str:
    return redaction_service.redact_url(url)


def redact_payload(value: Any) -> Any:
    return redaction_service.redact_payload(value)


# Encryption for sensitive data storage
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        settings = get_settings()
        if not settings.secret_key:
            raise RuntimeError(
                "SECRET_KEY is not configured. Set the SECRET_KEY environment variable "
                "before using encryption features."
            )
        # Derive key from secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"phantomscan-salt-v1",  # TODO: Move to env-configurable per-deployment salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(settings.secret_key.encode()))
        _fernet = Fernet(key)
    return _fernet


def encrypt_data(data: str) -> str:
    """Encrypt sensitive data for storage."""
    if not data:
        return ""
    fernet = _get_fernet()
    return fernet.encrypt(data.encode()).decode()


def decrypt_data(encrypted: str) -> str:
    """Decrypt sensitive data from storage."""
    if not encrypted:
        return ""
    fernet = _get_fernet()
    return fernet.decrypt(encrypted.encode()).decode()


def build_finding(
    *,
    title: str,
    category: str,
    severity: str,
    confidence: str,
    target: str,
    endpoint: str,
    evidence: str,
    impact: str,
    recommendation: str,
    verification: str,
    agent: str,
    cve_id: str | None = None,
    cvss_score: float | None = None,
    parameter: str | None = None,
    module: str | None = None,
    recommended_fix: str | None = None,
    remediation_status: str = "OPEN",
    verification_status: str = "NOT_VERIFIED",
    risk_status: str = "ACTIVE",
) -> dict[str, Any]:
    return {
        "title": title,
        "category": category,
        "severity": severity.upper(),
        "confidence": confidence.upper(),
        "target": target,
        "endpoint": endpoint,
        "evidence": redact_sensitive(evidence),
        "impact": impact,
        "recommendation": recommendation,
        "verification": verification,
        "agent": agent,
        "timestamp": utc_timestamp(),
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "parameter": parameter,
        "module": module,
        "recommended_fix": recommended_fix,
        "remediation_status": remediation_status,
        "verification_status": verification_status,
        "risk_status": risk_status,
    }
