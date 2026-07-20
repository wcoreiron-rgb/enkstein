from __future__ import annotations

from app.core.marcellus.token_hygiene import (
    MIN_REPEAT_RUN,
    compact_tool_output,
)


def test_short_text_is_left_untouched():
    result = compact_tool_output("ok")
    assert result.text == "ok"
    assert result.technique == "noise_strip"
    assert result.chars_saved == 0


def test_empty_text_is_a_noop():
    result = compact_tool_output("")
    assert result.text == ""
    assert result.original_chars == 0
    assert result.compacted_chars == 0


def test_consecutive_duplicate_lines_collapse_with_repeat_count():
    lines = ["Waiting for container to become healthy..."] * 400 + ["Container healthy."]
    result = compact_tool_output("\n".join(lines))
    assert result.technique == "dedup"
    assert "(repeated 400x)" in result.text
    assert result.text.count("Waiting for container to become healthy...") == 1
    assert "Container healthy." in result.text
    assert result.lines_removed == 399
    assert result.chars_saved > 0


def test_short_duplicate_runs_below_threshold_are_preserved():
    # A run shorter than MIN_REPEAT_RUN is not collapsed, so no information
    # about exact repetition count below the threshold is ever lost.
    lines = ["same line"] * (MIN_REPEAT_RUN - 1) + ["other line"] * 20
    result = compact_tool_output("\n".join(lines))
    assert result.text.count("same line") == MIN_REPEAT_RUN - 1
    assert "(repeated" not in result.text.split("\n")[0]


def test_carriage_return_progress_redraws_are_stripped():
    noisy = ("Progress: [####------] 40%\r" * 3) + "Actual output line\nDone"
    result = compact_tool_output(noisy)
    assert "Progress:" not in result.text
    assert "Actual output line" in result.text
    assert "Done" in result.text


def test_spinner_frames_are_stripped():
    noisy = "\n".join(["|", "/", "-", "\\"] * 5 + ["Real content line 1"] * 10)
    result = compact_tool_output(noisy)
    assert "|" not in result.text.split("\n")
    assert "Real content line 1" in result.text


def test_log_shaped_text_keeps_every_error_and_warn_line_verbatim():
    lines = (
        [f"INFO: processed item {i}" for i in range(50)]
        + ["ERROR: connection refused", "WARNING: retrying with backoff"]
        + [f"INFO: processed item {i}" for i in range(50)]
    )
    result = compact_tool_output("\n".join(lines))
    assert result.technique == "log_summary"
    assert "ERROR: connection refused" in result.text
    assert "WARNING: retrying with backoff" in result.text
    # Every individual INFO line was folded into an omission count instead
    # of being dropped silently or listed in full.
    assert "INFO: processed item 0" not in result.text
    assert "info/debug lines omitted" in result.text
    assert result.lines_removed > 0


def test_log_shaped_detection_requires_a_real_marker_ratio():
    # A handful of files that merely contain the word "error" inside prose
    # must not be treated as a structured log and summarized away.
    prose = "\n".join([
        "The error handling strategy for this module favors early returns.",
        "Most functions here validate input before doing any real work.",
        "A future refactor could centralize the error-formatting logic.",
    ] * 5)
    result = compact_tool_output(prose)
    assert result.technique != "log_summary"
    assert "error handling strategy" in result.text


def test_plain_prose_is_not_treated_as_log_or_duplicate_noise():
    prose = "This is a governed research answer about security posture. " * 20
    result = compact_tool_output(prose)
    assert result.technique == "noise_strip"
    assert result.chars_saved == 0
    assert result.text.strip() == prose.strip()


def test_max_chars_enforces_a_hard_ceiling_with_a_visible_marker():
    # Distinct, non-repeating lines so dedup cannot shrink this below the
    # cap on its own -- this isolates the max_chars ceiling itself.
    huge = "\n".join(f"distinct output line number {i}" for i in range(2000))
    result = compact_tool_output(huge, max_chars=500)
    assert len(result.text) <= 500
    assert result.truncated is True
    assert "truncated" in result.text
    assert "more characters omitted" in result.text


def test_max_chars_is_not_applied_when_compacted_text_already_fits():
    result = compact_tool_output("short output", max_chars=10_000)
    assert result.truncated is False
    assert result.text == "short output"


def test_oversized_input_is_bounded_before_compaction_and_marked_truncated():
    from app.core.marcellus.token_hygiene import MAX_INPUT_CHARS

    oversized = "a" * (MAX_INPUT_CHARS + 5_000)
    result = compact_tool_output(oversized)
    assert result.truncated is True
    assert len(result.text) <= MAX_INPUT_CHARS


def test_blank_line_spacing_is_preserved_through_dedup():
    lines = ["same"] * 5 + ["", "next section"]
    result = compact_tool_output("\n".join(lines))
    assert "\n\nnext section" in result.text


def test_savings_ratio_is_bounded_between_zero_and_one():
    result = compact_tool_output("x" * 10)
    assert 0.0 <= result.savings_ratio <= 1.0
    dedup_result = compact_tool_output("\n".join(["dup"] * 500))
    assert 0.0 <= dedup_result.savings_ratio <= 1.0
