"""The remediation console must read the assessment's failing controls.

The page fetched only the governed action queue, so a node reporting open
violations still showed an empty Autonomous Remediation page. That reads as
"nothing to remediate" when the opposite is true.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "frontend" / "src" / "app" / "remediation" / "page.tsx"


@pytest.fixture(scope="module")
def page() -> str:
    return PAGE.read_text(encoding="utf-8")


def test_page_fetches_control_remediation_proposals(page: str) -> None:
    assert "getControlRemediationProposals" in page


def test_proposals_are_fetched_with_the_rest_of_the_console(page: str) -> None:
    # Fetched inside the same refresh so the failing set cannot drift from the
    # action queue shown beside it.
    refresh = page[page.index("const refresh") : page.index("useEffect(() =>")]
    assert "getControlRemediationProposals" in refresh


def test_a_proposal_failure_does_not_blank_the_console(page: str) -> None:
    # Controls are advisory context. If that call fails the approval queue and
    # history must still render.
    assert "getControlRemediationProposals().catch(() => null)" in page


def test_operator_can_propose_a_remediation_from_a_failing_control(page: str) -> None:
    assert "remediateControl" in page
    assert "handlePropose" in page


def test_recommendation_only_controls_are_shown_separately(page: str) -> None:
    # A control with no executable action must not offer a button that cannot
    # do anything.
    assert "advisory_only" in page
    assert "Recommendation only" in page
