"""
Mission Control listed every mission by decrypting each objective inline, so a
single row written under a previous runtime key raised and returned 500 for the
whole page. The row must degrade to an explicit unreadable marker instead.
"""
import uuid
from datetime import datetime, timezone

import pytest

from app.core.marcellus.missions import _UNREADABLE, _mission_read
from app.models.marcellus import CortexMission
from app.core.marcellus.crypto import encrypt_json


def _mission(ciphertext: str, digest: str) -> CortexMission:
    return CortexMission(
        id=uuid.uuid4(),
        tenant_id="default",
        owner_id="owner",
        name="Continuous Identity Risk Watch",
        objective_ciphertext=ciphertext,
        objective_digest=digest,
        status="active",
        cadence="daily",
        autonomy_mode="assist",
        profile="incident_response",
        classification="internal",
        participants_json="[]",
        parallelism=2,
        model_profile=None,
        run_count=0,
        created_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
        updated_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
    )


def test_a_readable_mission_still_returns_its_objective():
    ciphertext, digest = encrypt_json({"objective": "Watch privileged identity drift"})
    read = _mission_read(_mission(ciphertext, digest))
    assert read.readable is True
    assert read.objective == "Watch privileged identity drift"


def test_a_mission_from_an_old_key_is_flagged_not_fatal():
    # Ciphertext that cannot be authenticated with the current runtime key.
    read = _mission_read(_mission("gAAAAABmb2d1cw==", "0" * 64))
    assert read.readable is False
    assert read.objective == _UNREADABLE
    # The row is still listable so an operator can find and remove it.
    assert read.name == "Continuous Identity Risk Watch"
