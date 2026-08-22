from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.services.enterprise_access import filter_findings_for_user, require_scan_access, severity_allowed


def test_severity_ceiling_filters_enterprise_findings() -> None:
    user = {"enterprise_id": "ent-1", "enterprise_role": "employee", "max_severity": "MEDIUM"}
    rows = [{"severity": "LOW"}, {"severity": "MEDIUM"}, {"severity": "HIGH"}]

    assert severity_allowed("INFO", "LOW") is True
    assert filter_findings_for_user(rows, user) == rows


@pytest.mark.asyncio
async def test_scan_access_is_limited_to_enterprise_tenant() -> None:
    scan = {"id": 7, "user_id": "employee-a", "enterprise_id": "ent-1"}
    with patch("app.services.enterprise_access.get_scan", AsyncMock(return_value=scan)):
        assert await require_scan_access(7, {"id": "employee-b", "enterprise_id": "ent-1"}) == scan
        with pytest.raises(HTTPException) as exc:
            await require_scan_access(7, {"id": "employee-c", "enterprise_id": "ent-2"})
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_personal_scan_is_not_shared_between_users() -> None:
    scan = {"id": 9, "user_id": "user-a", "enterprise_id": None}
    with patch("app.services.enterprise_access.get_scan", AsyncMock(return_value=scan)):
        with pytest.raises(HTTPException) as exc:
            await require_scan_access(9, {"id": "user-b", "role": "user"})
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_platform_admin_access_does_not_apply_to_enterprise_owner() -> None:
    scan = {"id": 11, "user_id": "user-a", "enterprise_id": None}
    enterprise_owner = {"id": "owner", "role": "admin", "enterprise_id": "ent-1", "enterprise_role": "owner"}
    with patch("app.services.enterprise_access.get_scan", AsyncMock(return_value=scan)):
        with pytest.raises(HTTPException) as exc:
            await require_scan_access(11, enterprise_owner)
    assert exc.value.status_code == 404
