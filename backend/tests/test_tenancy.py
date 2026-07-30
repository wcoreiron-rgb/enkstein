import pytest
from fastapi import HTTPException

from app.core.tenancy import assert_tenant_visible, caller_tenant


def test_tenant_bound_identity_uses_its_claim() -> None:
    assert caller_tenant({"sub": "user-a", "role": "viewer", "tenant_id": "tenant-a"}) == "tenant-a"


def test_unscoped_non_admin_is_rejected() -> None:
    with pytest.raises(HTTPException) as error:
        caller_tenant({"sub": "user-a", "role": "viewer"})
    assert error.value.status_code == 403


def test_cross_tenant_record_is_not_discoverable() -> None:
    with pytest.raises(HTTPException) as error:
        assert_tenant_visible({"sub": "user-b", "role": "viewer", "tenant_id": "tenant-b"}, "tenant-a")
    assert error.value.status_code == 404


def test_unscoped_admin_can_operate_legacy_records() -> None:
    assert caller_tenant({"sub": "admin", "role": "admin"}) is None
    assert_tenant_visible({"sub": "admin", "role": "admin"}, None)
