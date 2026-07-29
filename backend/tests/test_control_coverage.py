from __future__ import annotations

from app.core.zero_trust import NODE_DEFAULT_PILLAR
from app.services.control_packs import baseline_controls
from app.services.oscal_sync import _flatten_groups


def test_every_capability_node_has_a_control_pack():
    controls = baseline_controls()
    nodes = {row["claw"] for row in controls}
    assert set(NODE_DEFAULT_PILLAR).issubset(nodes)
    assert len(nodes) == len(NODE_DEFAULT_PILLAR)


def test_pack_marks_unsupported_evaluation_as_recommendation_only():
    controls = baseline_controls()
    recommendation = [row for row in controls if row["recommendation_only"]]
    automated = [row for row in controls if row["automated"]]
    assert recommendation
    assert automated
    assert all(row["remediation_mode"] for row in controls)
    assert all(row["evidence_method"] for row in controls)


def test_oscal_nested_groups_are_flattened():
    rows = _flatten_groups([
        {"controls": [{"id": "AC-1"}], "groups": [{"controls": [{"id": "AC-2"}]}]},
    ])
    assert [row["id"] for row in rows] == ["AC-1", "AC-2"]
