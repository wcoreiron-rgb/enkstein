"""RTK-style token hygiene: compact noisy command/log/tool output before it
enters a Brain's context, the same technique the RTK CLI proxy (rtk log/err)
applies to terminal output ahead of an LLM session.

Pure and deterministic: no randomness, no wall-clock, no I/O. Structural only
-- this never redacts or classifies sensitive content (that remains
``arcclaw.scanner.scan_text``'s job) and is safe to run before or after it.

Three techniques, applied in order:
  1. Strip terminal noise (progress bars, spinner frames, carriage-return
     redraws) that carries no information once flattened to text.
  2. Collapse consecutive duplicate lines into one line plus a repeat count,
     the single highest-value RTK technique on build/install/test output.
  3. If the text looks log-shaped (has recognizable ERROR/WARN/INFO-style
     lines), keep every error/warning line and summarize info-level noise
     into a count instead of listing it -- most of a verbose log is info
     noise, and the failure signal is almost always in the error/warn lines.

Every result carries how much was removed, so a caller (or an operator
reading the manifest) can always see that compaction happened rather than
silently losing content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Bytes-ish cap on how much of the original text this module will even look
# at; larger inputs are truncated before compaction starts so a pathological
# input can never make this pass itself expensive.
MAX_INPUT_CHARS = 200_000

# Below this many lines, compaction is not worth doing: the dedup/log passes
# add overhead and bracket noise for no real benefit on already-short output.
MIN_LINES_TO_COMPACT = 8

# A duplicate run shorter than this is left alone -- collapsing two identical
# lines into "line (x2)" saves nothing readable; the technique earns its
# keep once a run is long enough to matter (e.g. 200 identical download
# lines from a package manager).
MIN_REPEAT_RUN = 3

_SPINNER_CHARS = "|/-\\"
_PROGRESS_BAR = re.compile(r"[#=\-]{10,}|\d{1,3}%\s*(\|+|\[.*?\])?\s*$")

_ERROR_LINE = re.compile(r"^\s*(\[?(error|err|fatal|fail(ed)?)\]?\s*[:\]]|E\d{3,}\b)", re.IGNORECASE)
_WARN_LINE = re.compile(r"^\s*(\[?(warn(ing)?|deprecat\w*)\]?\s*[:\]])", re.IGNORECASE)
_INFO_LINE = re.compile(r"^\s*(\[?(info|debug|trace|verbose)\]?\s*[:\]])", re.IGNORECASE)


@dataclass
class CompactionResult:
    text: str
    original_chars: int
    compacted_chars: int
    lines_removed: int = 0
    truncated: bool = False
    technique: str = "none"

    @property
    def chars_saved(self) -> int:
        return max(0, self.original_chars - self.compacted_chars)

    @property
    def savings_ratio(self) -> float:
        if self.original_chars <= 0:
            return 0.0
        return round(self.chars_saved / self.original_chars, 4)


def _strip_terminal_noise(text: str) -> str:
    """Removes carriage-return progress redraws and standalone progress-bar
    or spinner lines that carry no textual signal once flattened."""
    kept: list[str] = []
    for raw_line in text.split("\n"):
        # A terminal overwrites everything before the last \r on a physical
        # line, so only the segment after the final \r is what would have
        # actually remained visible; everything before it is redraw noise
        # that must not delete real content appearing after it.
        line = raw_line.rsplit("\r", 1)[-1] if "\r" in raw_line else raw_line
        stripped = line.strip()
        if not stripped:
            kept.append(line)
            continue
        if len(stripped) == 1 and stripped in _SPINNER_CHARS:
            continue
        if _PROGRESS_BAR.fullmatch(stripped):
            continue
        kept.append(line)
    return "\n".join(kept)


def _collapse_duplicate_runs(lines: list[str]) -> tuple[list[str], int]:
    """Collapses consecutive identical lines into one line annotated with a
    repeat count. Only non-blank lines participate, so blank-line spacing in
    the original output is preserved untouched."""
    result: list[str] = []
    removed = 0
    index = 0
    while index < len(lines):
        current = lines[index]
        if not current.strip():
            result.append(current)
            index += 1
            continue
        run_end = index + 1
        while run_end < len(lines) and lines[run_end] == current:
            run_end += 1
        run_length = run_end - index
        if run_length >= MIN_REPEAT_RUN:
            result.append(f"{current} (repeated {run_length}x)")
            removed += run_length - 1
        else:
            result.extend(lines[index:run_end])
        index = run_end
    return result, removed


def _classify_log_line(line: str) -> str | None:
    if _ERROR_LINE.match(line):
        return "error"
    if _WARN_LINE.match(line):
        return "warn"
    if _INFO_LINE.match(line):
        return "info"
    return None


def _compact_log_shaped(lines: list[str]) -> tuple[list[str], int] | None:
    """If enough lines carry a recognizable error/warn/info marker, keep
    every error/warn line verbatim and fold consecutive info-level runs into
    a single count. Returns None when the text doesn't look log-shaped, so
    the caller falls back to the plain dedup result instead of forcing this
    technique onto ordinary prose or source code."""
    classified = [_classify_log_line(line) for line in lines]
    marked = sum(1 for item in classified if item is not None)
    if not lines or marked < max(3, len(lines) // 5):
        return None
    result: list[str] = []
    removed = 0
    index = 0
    while index < len(lines):
        kind = classified[index]
        if kind in ("error", "warn") or kind is None:
            result.append(lines[index])
            index += 1
            continue
        run_end = index + 1
        while run_end < len(lines) and classified[run_end] == "info":
            run_end += 1
        run_length = run_end - index
        if run_length == 1:
            result.append(lines[index])
        else:
            result.append(f"[{run_length} info/debug lines omitted]")
            removed += run_length - 1
        index = run_end
    return result, removed


def compact_tool_output(text: str, *, max_chars: int | None = None) -> CompactionResult:
    """Compacts noisy tool/command/log output for Brain context.

    ``max_chars`` applies as a final hard ceiling on the returned text (the
    same role ``_MAX_FIELD_CHARS`` plays for native Codex output today); when
    the compacted text still exceeds it, the excess is truncated with a
    visible marker rather than silently cut.
    """
    original_chars = len(text)
    if original_chars == 0:
        return CompactionResult(text=text, original_chars=0, compacted_chars=0)
    working = text[:MAX_INPUT_CHARS]
    was_input_truncated = original_chars > MAX_INPUT_CHARS
    working = _strip_terminal_noise(working)
    lines = working.split("\n")
    if len(lines) < MIN_LINES_TO_COMPACT:
        compacted_lines, technique = lines, "noise_strip"
        lines_removed = 0
    else:
        log_shaped = _compact_log_shaped(lines)
        if log_shaped is not None:
            compacted_lines, lines_removed = log_shaped
            technique = "log_summary"
        else:
            compacted_lines, lines_removed = _collapse_duplicate_runs(lines)
            technique = "dedup" if lines_removed else "noise_strip"
    compacted = "\n".join(compacted_lines)
    truncated = was_input_truncated
    if max_chars is not None and len(compacted) > max_chars:
        marker = f"\n[truncated, {len(compacted) - max_chars} more characters omitted]"
        keep = max(0, max_chars - len(marker))
        compacted = compacted[:keep] + marker
        truncated = True
    return CompactionResult(
        text=compacted,
        original_chars=original_chars,
        compacted_chars=len(compacted),
        lines_removed=lines_removed,
        truncated=truncated,
        technique=technique,
    )
