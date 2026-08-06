"""Submission guarantees for the Browser Companion content script.

A provider can rename a selector at any time, and when that happens the visible
symptom is the worst kind: Enkstein types the prompt into the page, the user
watches it sit there, and nothing is submitted. These pin the properties that
keep a selector change from becoming a dead end.
"""

from pathlib import Path

import pytest

CONTENT = Path(__file__).resolve().parents[2] / "browser-extension" / "content.js"


@pytest.fixture(scope="module")
def source() -> str:
    return CONTENT.read_text(encoding="utf-8")


def _block(source: str, start_marker: str, end_marker: str) -> str:
    start = source.index(start_marker)
    return source[start:source.index(end_marker, start + len(start_marker))]


def _code_only(block: str) -> str:
    """Drops `//` comments so an assertion cannot be satisfied (or broken) by
    prose that merely mentions the thing being checked for."""
    lines = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _function_body(source: str, signature: str) -> str:
    """Returns exactly one function, matched by brace depth, so an assertion
    cannot accidentally read into whatever happens to follow it."""
    start = source.index(signature)
    depth = 0
    for index in range(source.index("{", start), len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return _code_only(source[start:index + 1])
    raise AssertionError(f"unbalanced braces after {signature!r}")


def test_unknown_host_is_not_guessed_as_gemini(source: str) -> None:
    """`provider()` used to return 'gemini' for any host that was not ChatGPT
    or Claude. On an unrelated page that ran Gemini's selectors and reported a
    confusing selector error instead of the real problem."""
    start = source.index("function provider()")
    body = source[start:source.index("}", start)]
    assert "gemini.google.com" in body, "gemini is matched by fallthrough, not by host"
    assert "return null" in body, "an unknown host must be named, not guessed"


def test_send_lookup_is_not_restricted_to_button_elements(source: str) -> None:
    """Gemini's composer is Angular Material custom elements. Requiring
    HTMLButtonElement matched nothing there, so the prompt was inserted and
    never sent."""
    body = _function_body(source, "function findSendButton(")
    assert "HTMLButtonElement" not in body, "send lookup still requires a literal <button>"
    assert '[role="button"]' in body, "send lookup ignores role-based buttons"


def test_enter_fallback_exists(source: str) -> None:
    """Every provider composer submits on Enter. Without this fallback a
    renamed or localised send control leaves the prompt unsent with no
    recovery path."""
    assert "function pressEnterToSubmit(" in source
    body = _function_body(source, "function pressEnterToSubmit(")
    for field in ("keydown", "keypress", "keyup", "keyCode", "bubbles"):
        assert field in body, f"synthetic Enter is missing {field}"


def test_submit_falls_back_to_enter_and_fails_loudly(source: str) -> None:
    body = _function_body(source, "async function submit(")
    assert "pressEnterToSubmit(input)" in body, "submit never tries Enter"
    # A missing button must not abort before the fallback runs.
    assert "if (button)" in body, "submit assumes a button was found"
    assert "throw new Error(" in body, "a wholly failed submission must surface"


def test_wait_for_send_button_returns_rather_than_throws(source: str) -> None:
    """It previously threw on timeout, which aborted before Enter could run."""
    body = _function_body(source, "async function waitForSendButton(")
    assert "throw" not in body, "a missing send button still aborts submission"
    assert "return null" in body


def test_gemini_selectors_tolerate_custom_elements(source: str) -> None:
    # Anchor to SEND_SELECTORS explicitly: 'gemini:' also appears in the input,
    # response, and streaming selector maps earlier in the file.
    send_map = _block(source, "const SEND_SELECTORS", "\n};")
    body = _code_only(_block(send_map, "  gemini: [", "\n  ],"))
    non_button = [
        line for line in body.splitlines()
        if "aria-label" in line and "button[" not in line
    ]
    assert non_button, "every Gemini send selector still demands a <button> tag"
