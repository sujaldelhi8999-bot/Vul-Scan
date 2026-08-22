from dataclasses import dataclass

from app.config import get_settings
from app.models import ScanRequest
from app.services.active_gate import ActiveTargetGate
from app.services.authorization import TargetAuthorizationService, VerifiedTarget, canonicalize_target

settings = get_settings()


class ScanPolicyError(ValueError):
    def __init__(self, message: str, code: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class ScanAdmission:
    target_url: str
    verified_target: VerifiedTarget | None
    authorization_context: dict[str, object]


class ScanPolicy:
    def __init__(self, authorization_service: TargetAuthorizationService) -> None:
        self.authorization_service = authorization_service
        self.active_gate = ActiveTargetGate(authorization_service)

    async def admit(self, request: ScanRequest, user_id: str, user_role: str = "user") -> ScanAdmission:
        target = canonicalize_target(request.target_url)
        if request.mode == "defend":
            if request.selected_tests or request.business_logic_tests:
                raise ScanPolicyError(
                    "Defend mode cannot execute active test modules.",
                    "ACTIVE_MODULES_FORBIDDEN_IN_DEFEND",
                )
            if request.enable_exploitation:
                raise ScanPolicyError(
                    "Exploitation is only allowed in pentest mode.",
                    "EXPLOITATION_FORBIDDEN_IN_MODE",
                )
            if request.authorization_confirmed or request.authorization_id is not None:
                raise ScanPolicyError(
                    "Defend mode does not accept Pentest authorization state.",
                    "PENTEST_STATE_FORBIDDEN_IN_DEFEND",
                )
            return ScanAdmission(
                target_url=target.url,
                verified_target=None,
                authorization_context={
                    "allowed": True,
                    "target_url": target.url,
                    "target_origin": target.origin,
                    "authorization_status": "NOT_REQUIRED",
                    "reason": "Passive defend scan",
                    "authorization_id": None,
                    "is_lab": False,
                },
            )

        if not request.selected_tests:
            raise ScanPolicyError("Pentest mode requires at least one selected test module.", "TEST_SELECTION_REQUIRED")
        if request.enable_exploitation and request.mode != "pentest":
            raise ScanPolicyError(
                "Exploitation is only allowed in pentest mode.",
                "EXPLOITATION_FORBIDDEN_IN_MODE",
            )
        if request.enable_exploitation and not settings.exploitation_enabled:
            raise ScanPolicyError(
                "Exploitation engine is disabled globally (EXPLOITATION_ENABLED=false).",
                "EXPLOITATION_DISABLED",
                403,
            )
        if "business_logic" not in request.selected_tests and request.business_logic_tests:
            raise ScanPolicyError(
                "Business logic definitions require the business_logic module to be selected.",
                "BUSINESS_LOGIC_SCOPE_MISMATCH",
            )
        decision = await self.active_gate.admit(target.url, user_id, request.authorization_id, user_role=user_role)
        if not decision.allowed:
            raise ScanPolicyError(decision.reason, "TARGET_NOT_VERIFIED", 403)
        if decision.authorization_status == "VERIFIED" and not request.authorization_confirmed:
            raise ScanPolicyError(
                "Verified external pentest targets still require manual authorization confirmation.",
                "AUTHORIZATION_CONFIRMATION_REQUIRED",
            )
        return ScanAdmission(
            target_url=decision.target_url,
            verified_target=decision.verified_target,
            authorization_context=decision.to_context(),
        )
