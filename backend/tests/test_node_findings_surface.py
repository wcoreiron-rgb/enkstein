"""
A Capability Node must show the findings its own scan created.

Identity Security ran a scan, wrote two live Entra findings to the shared
Finding table, and then reported none -- because its ``/findings`` endpoint
read the identity registry instead. An operator with a correctly connected
directory saw an empty node and concluded the connector was broken.
"""
from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[1]
_CLAWS = _BACKEND / "app" / "claws"

# Nodes whose findings live in a purpose-built table rather than the shared
# Finding model, or which expose no findings surface at all.
_EXEMPT = {"modelclaw"}


def _node_dirs():
    for path in sorted(_CLAWS.iterdir()):
        if path.is_dir() and (path / "routes.py").exists():
            yield path.name, (path / "routes.py").read_text()


@pytest.mark.parametrize("node,source", list(_node_dirs()))
def test_node_findings_endpoint_reads_the_scanned_table(node, source):
    """If a node can scan, its findings endpoint must read what the scan wrote."""
    if node in _EXEMPT:
        pytest.skip(f"{node} has no shared-table findings surface")
    if "run_claw_scan" not in source:
        pytest.skip(f"{node} does not use the shared scan path")

    assert '"/findings"' in source or "'/findings'" in source, (
        f"{node} runs a connector scan but exposes no findings endpoint"
    )

    # The findings handler must query the Finding model, which is where
    # run_claw_scan persists everything it ingests.
    match = re.search(
        r"@router\.get\(\s*[\"']/findings[\"'].*?(?=\n@router\.)",
        source,
        re.DOTALL,
    )
    assert match, f"could not locate the /findings handler in {node}"
    assert "select(Finding)" in match.group(0), (
        f"{node}'s /findings endpoint never queries the Finding table, so a "
        f"scan can create findings the node will not display"
    )
