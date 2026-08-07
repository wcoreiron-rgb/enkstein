"""Enkstein coding-agent policy pack.
Standalone policy evaluation for AI coding agents. No backend, no database and
no network: a hook has to answer in milliseconds on every tool call, and a
developer should not need Docker running to be protected from committing a
private key.
Secret patterns are ported from ArcClaw's scanner
(backend/app/claws/arcclaw/scanner.py) so a finding here means the same thing it
means in the console. Three of that scanner's patterns are deliberately dropped,
because blocking on them would make a coding agent unusable:
  Email Address   -- appears in package.json author fields, license headers,
                     and test fixtures constantly.
  Credit Card     -- the 13-16 digit run matches ordinary numeric arrays.
  Base64 payload  -- matches minified assets, source maps, and lockfile hashes.
What survives is the set whose presence in source is a genuine problem: live
cloud credentials, private keys, and hardcoded passwords.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Iterable

# Decisions mirror app/models/policy.py:PolicyAction so a rule keeps its meaning
# whether it is evaluated locally or by the Trust Fabric.
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
MASK = "mask"
MONITOR = "monitor"
ALLOW = "allow"


@dataclass
class Finding:
    rule_id: str
    title: str
    decision: str
    detail: str
    line: int | None = None


@dataclass
class Decision:
    decision: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.decision in (DENY, REQUIRE_APPROVAL)

    @property
    def masked(self) -> bool:
        return self.decision == MASK

    def reason(self) -> str:
        parts = []
        for f in self.findings:
            where = f" (line {f.line})" if f.line else ""
            parts.append(f"{f.title}{where}: {f.detail}")
        return "; ".join(parts)


# (rule_id, title, regex, decision)
SECRET_RULES: list[tuple[str, str, str, str]] = [
    ("secret.aws_access_key", "AWS access key",
     r"AKIA[0-9A-Z]{16}", DENY),
    ("secret.private_key", "Private key material",
     r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", DENY),
    ("secret.anthropic_key", "Anthropic API key",
     r"sk-ant-[A-Za-z0-9_\-]{20,}", DENY),
    ("secret.openai_key", "OpenAI API key",
     r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}", DENY),
    ("secret.github_token", "GitHub token",
     r"\bgh[pousr]_[A-Za-z0-9]{36,}", DENY),
    ("secret.slack_token", "Slack token",
     r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", DENY),
    ("secret.google_api_key", "Google API key",
     r"\bAIza[0-9A-Za-z_\-]{35}\b", DENY),
    ("secret.connection_string", "Database connection string with credentials",
     r"(?i)\b(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@", DENY),
    ("secret.hardcoded_password", "Hardcoded password",
     r"(?i)(?:password|passwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", REQUIRE_APPROVAL),
    ("secret.bearer_token", "Bearer token",
     r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{24,}", REQUIRE_APPROVAL),
    ("secret.generic_api_key", "Assigned API key",
     r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", REQUIRE_APPROVAL),
    ("secret.ssn", "US Social Security number",
     r"\b\d{3}-\d{2}-\d{4}\b", REQUIRE_APPROVAL),
]

# Placeholders are the single largest source of false positives. A developer
# writing an .env.example or a docs snippet is doing the right thing, and
# blocking it teaches people to disable the hook.
# Anchored to whole words and template syntax. An earlier version matched the
# bare substring "123456", which silently whitelisted any GitHub or Slack token
# whose random body happened to contain those digits -- a placeholder guard that
# quietly disabled real detection.
PLACEHOLDER = re.compile(
    r"(?i)(?:"
    r"\byour[_\-]|\bmy[_\-]|\bexample[_\-]|[_\-]example\b|\bexample\b|"
    r"\bplaceholder\b|\bdummy\b|\bsample\b|\bredacted\b|\bfake\b|"
    r"\bchange[_\-]?me\b|\btodo\b|\binsert[_\-]|\breplace[_\-]|"
    r"\bxxxx+\b|\.\.\.|<[^>]{1,40}>|\{\{|\$\{|"
    r"\bhere\b|\bgoes[_\-]here\b"
    r")"
)

COMMAND_RULES: list[tuple[str, str, str, str]] = [
    ("command.curl_pipe_shell", "Remote script piped to a shell",
     r"(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b", DENY),
    ("command.disk_overwrite", "Direct write to a block device",
     r"\b(?:dd|mkfs(?:\.\w+)?)\b[^\n]*\bof=/dev/|\bmkfs(?:\.\w+)?\s+/dev/", DENY),
    ("command.history_rewrite_force_push", "Force push rewriting shared history",
     r"\bgit\s+push\b[^\n]*(?:--force(?!-with-lease)|\s-f\b)", REQUIRE_APPROVAL),
    ("command.git_hard_reset", "Discards uncommitted work",
     r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f)", REQUIRE_APPROVAL),
    ("command.credential_exfiltration", "Reads credential material into a network call",
     r"(?:cat|cp|tar|zip|base64)\b[^\n;|&]*(?:\.aws/credentials|\.ssh/id_[a-z0-9]+|\.netrc|\.npmrc|\.docker/config\.json|\.kube/config)", REQUIRE_APPROVAL),
    ("command.privilege_escalation", "Privilege escalation",
     r"(?:^|[\n;|&]\s*)(?:\w[\w.\-]*\s+)?(?:sudo|doas)\s+(?!-n\s+true\b)", REQUIRE_APPROVAL),
    ("command.package_publish", "Publishes a package to a public registry",
     r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b", REQUIRE_APPROVAL),
]

_SECRET_COMPILED = [(rid, t, re.compile(rx), d) for rid, t, rx, d in SECRET_RULES]
_COMMAND_COMPILED = [(rid, t, re.compile(rx), d) for rid, t, rx, d in COMMAND_RULES]

# Mask sits above monitor because it changes what reaches the model, and below
# approval because it resolves the finding without interrupting the developer.
_RANK = {ALLOW: 0, MONITOR: 1, MASK: 2, REQUIRE_APPROVAL: 3, DENY: 4}


def _worst(decisions: Iterable[str]) -> str:
    return max(decisions, key=lambda d: _RANK.get(d, 0), default=ALLOW)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _describe(snippet: str, limit: int = 60) -> str:
    """Summarize a match without echoing a live secret into a transcript."""
    collapsed = " ".join(snippet.split())
    if len(collapsed) > limit:
        collapsed = collapsed[:limit] + "\u2026"
    if len(collapsed) > 12:
        return collapsed[:6] + "\u2026" + collapsed[-4:]
    return collapsed


# Values Apple, AWS, and countless tutorials publish as canonical examples. They
# match the real key shape exactly, so shape alone cannot tell them apart.
KNOWN_EXAMPLE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

# Credentials pointing at a developer's own machine are not a leak. Blocking
# `postgresql://user:pass@localhost/db` in an .env.example is the kind of false
# positive that gets a security tool uninstalled.
LOCAL_HOSTS = re.compile(
    r"@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|host\.docker\.internal|"
    r"[a-z0-9\-]+\.local|db|database|postgres|mysql|redis|mongo)"
    r"(?::\d+)?(?:[/?]|$)",
    re.IGNORECASE,
)


def _is_benign(rule_id: str, snippet: str, line_text: str) -> bool:
    """Filter matches that are structurally real but semantically harmless."""
    if PLACEHOLDER.search(line_text):
        return True
    if any(example in snippet for example in KNOWN_EXAMPLE_VALUES):
        return True
    # The connection-string pattern stops at the "@", so the host lives in the
    # surrounding line rather than the matched snippet.
    if rule_id == "secret.connection_string" and LOCAL_HOSTS.search(line_text):
        return True
    return False


def scan_content(text: str) -> Decision:
    """Scan file content destined for disk."""
    if not text:
        return Decision(ALLOW)

    findings: list[Finding] = []
    for rule_id, title, pattern, decision in _SECRET_COMPILED:
        for match in pattern.finditer(text):
            # Look at the whole line: API_KEY="<your-key-here>" only reads as a
            # placeholder when the surrounding text is visible.
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            line_text = text[start : end if end != -1 else len(text)]
            if _is_benign(rule_id, match.group(0), line_text):
                continue
            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                decision=decision,
                detail=_describe(match.group(0)),
                line=_line_of(text, match.start()),
            ))
            # One finding per rule is enough to decide, but only *after* a real
            # match: continuing past a placebo line is what lets a genuine
            # secret on line 2 be caught when line 1 was a placeholder.
            break

    return combine(
        Decision(_worst(f.decision for f in findings), findings),
        scan_with_packs(text, "content"),
    )


def scan_command(command: str) -> Decision:
    """Scan a shell command line."""
    if not command:
        return Decision(ALLOW)

    findings: list[Finding] = []
    for rule_id, title, pattern, decision in _COMMAND_COMPILED:
        match = pattern.search(command)
        if match:
            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                decision=decision,
                detail=_describe(match.group(0).strip()),
            ))

    destructive = check_destructive_delete(command)
    if destructive:
        findings.append(destructive)

    return combine(
        Decision(_worst(f.decision for f in findings), findings),
        scan_with_packs(command, "command"),
    )


# Destructive-delete detection is done structurally rather than with a regex.
# `rm -rf /` and `rm -rf ~` are only two characters different from `rm -rf build`
# yet mean something completely different, and expressing that gap in one
# expression produced a rule that silently matched neither. Tokenizing the
# command and inspecting the operands is both correct and readable.
# Programs that front another command. Output filters such as RTK rewrite
# `sudo x` into `rtk sudo x`, and a rule anchored to the start of the line then
# sees a wrapper instead of the real program and silently stops matching.
COMMAND_WRAPPERS = {
    "sudo", "doas", "env", "nohup", "time", "nice", "ionice", "xargs",
    "rtk", "stdbuf", "script", "watch", "timeout", "command", "builtin",
}

PROTECTED_ROOTS = {
    "/", "/*", "~", "~/", "$HOME", "${HOME}", "/etc", "/usr", "/var", "/bin",
    "/sbin", "/lib", "/opt", "/boot", "/dev", "/System", "/Library",
    "/Applications", "/Users", "/home", ".", "..", "./", "../", "*",
}


def _is_protected_target(token: str) -> bool:
    cleaned = token.strip().rstrip("/") or "/"
    if token.strip() in PROTECTED_ROOTS or cleaned in PROTECTED_ROOTS:
        return True
    # $HOME/* and ~/* expand to everything the user owns.
    if re.fullmatch(r"(?:~|\$\{?HOME\}?)/?\*?", token.strip()):
        return True
    # A single-level absolute path (/etc, /usr) is a system directory; deeper
    # paths like /var/folders/tmpdir are ordinary working locations.
    if re.fullmatch(r"/[A-Za-z][\w.\-]*/?\*?", token.strip()):
        return True
    return False


def _split_segments(command: str) -> list[str]:
    """Split on shell separators so `safe && dangerous` is still inspected."""
    return [s for s in re.split(r"(?:&&|\|\||[;|&\n])", command) if s.strip()]


def check_destructive_delete(command: str) -> Finding | None:
    for segment in _split_segments(command):
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue

        # Skip a leading `sudo`/`env` wrapper so `sudo rm -rf /` is still seen.
        # Step past wrapper programs and their own arguments -- `timeout 5 sudo`
        # and `nice -n 10 rm` both hide the real program behind an operand.
        idx = 0
        while idx < len(tokens) and tokens[idx] in COMMAND_WRAPPERS:
            idx += 1
            while idx < len(tokens) and (
                tokens[idx].startswith("-") or re.fullmatch(r"[\d.]+[a-z]?", tokens[idx])
            ):
                idx += 1
        if idx >= len(tokens) or tokens[idx] not in ("rm", "/bin/rm"):
            continue

        args = tokens[idx + 1 :]
        recursive = force = False
        operands: list[str] = []
        for arg in args:
            if arg == "--":
                continue
            if arg.startswith("--"):
                recursive |= arg in ("--recursive",)
                force |= arg in ("--force",)
            elif arg.startswith("-") and len(arg) > 1:
                recursive |= "r" in arg.lower()
                force |= "f" in arg
            else:
                operands.append(arg)

        if not recursive:
            continue
        for operand in operands:
            if _is_protected_target(operand):
                return Finding(
                    rule_id="command.recursive_root_delete",
                    title="Recursive delete of a protected location",
                    decision=DENY,
                    detail=f"rm -r{'f' if force else ''} {operand}",
                )
    return None


# ── Prompt governance ─────────────────────────────────────────────────────────
# A secret pasted into chat is already outside your control the moment the turn
# is sent: it lands in the vendor's context, their logs, and often their
# retention. Governing file writes but not prompts leaves the larger hole open,
# since people paste .env files and customer records into chat far more readily
# than they commit them.
#
# The prompt pack is deliberately *not* the same as the file pack. Two reasons:
# a prompt is prose rather than source, so patterns that are noisy in code
# (payment cards, national IDs) are meaningful here; and blocking is far more
# disruptive mid-conversation, so most findings warn rather than deny.

def _luhn_valid(digits: str) -> bool:
    """Payment cards carry a check digit; without it every long number matches."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


PROMPT_RULES: list[tuple[str, str, str, str]] = [
    ("prompt.private_key", "Private key material",
     r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", DENY),
    ("prompt.aws_secret_pair", "AWS key with secret",
     r"(?is)AKIA[0-9A-Z]{16}.{0,200}?(?:secret|sk)[^\n]{0,20}[:=]\s*['\"]?[A-Za-z0-9/+=]{40}", DENY),
    ("prompt.connection_string", "Connection string with credentials",
     r"(?i)\b(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@", DENY),
    ("prompt.aws_access_key", "AWS access key",
     r"AKIA[0-9A-Z]{16}", REQUIRE_APPROVAL),
    ("prompt.provider_token", "AI provider API key",
     r"\b(?:sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-)?[A-Za-z0-9]{32,}|"
     r"gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{35})",
     REQUIRE_APPROVAL),
    # A bare NNN-NN-NNNN also describes ticket ids, part numbers, and version
    # strings, so a nearby mention of what the number *is* is required. Missing a
    # context-free SSN is a better failure than warning on every hyphenated id.
    ("prompt.ssn", "US Social Security number",
     r"(?i)\b(?:ssn|social security(?:\s+(?:number|no\.?|#))?|taxpayer id|tin)\b"
     r"[^\n]{0,40}?\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", REQUIRE_APPROVAL),
    ("prompt.password_assignment", "Password value",
     r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}", REQUIRE_APPROVAL),
    ("prompt.bearer_token", "Bearer token",
     r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{24,}", REQUIRE_APPROVAL),
    ("prompt.private_key_body", "Base64 key body",
     r"(?m)^MII[A-Za-z0-9+/]{40,}", REQUIRE_APPROVAL),
]

_PROMPT_COMPILED = [(rid, t, re.compile(rx), d) for rid, t, rx, d in PROMPT_RULES]

# Prompt rules reuse the file pack's benign filters, but only where the rule
# genuinely means the same thing. Rewriting the "prompt." prefix to "secret."
# and hoping the names matched silently disabled the localhost exemption.
_BENIGN_EQUIVALENT = {
    "prompt.connection_string": "secret.connection_string",
    "prompt.aws_access_key": "secret.aws_access_key",
    "prompt.provider_token": "secret.generic_api_key",
    "prompt.password_assignment": "secret.hardcoded_password",
}

# Long digit runs are common in prose (order numbers, timestamps, IDs), so a
# payment card is only reported when it passes the Luhn check.
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def scan_prompt(text: str) -> Decision:
    """Scan a user prompt before it is sent to a model provider."""
    if not text:
        return Decision(ALLOW)

    findings: list[Finding] = []
    for rule_id, title, pattern, decision in _PROMPT_COMPILED:
        for match in pattern.finditer(text):
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            line_text = text[start : end if end != -1 else len(text)]
            if _is_benign(_BENIGN_EQUIVALENT.get(rule_id, rule_id), match.group(0), line_text):
                continue
            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                decision=decision,
                detail=_describe(match.group(0)),
                line=_line_of(text, match.start()),
            ))
            break

    for match in _CARD.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            findings.append(Finding(
                rule_id="prompt.payment_card",
                title="Payment card number",
                decision=REQUIRE_APPROVAL,
                detail=f"{digits[:4]}\u2026{digits[-4:]}",
                line=_line_of(text, match.start()),
            ))
            break

    # Claude Code exposes `updatedInput` on PreToolUse only, so a prompt can be
    # stopped but not rewritten. A mask rule that fires here would otherwise
    # report "masked" while the raw value still reached the provider, so it is
    # escalated to approval: the developer decides, and nothing leaks silently.
    pack = scan_with_packs(text, "prompt")
    for finding in pack.findings:
        if finding.decision == MASK:
            finding.decision = REQUIRE_APPROVAL
    pack.decision = _worst(f.decision for f in pack.findings)

    return combine(Decision(_worst(f.decision for f in findings), findings), pack)


# ---------------------------------------------------------------------------
# Private policy packs
# ---------------------------------------------------------------------------
# This repository is public, so any rule committed here is readable by anyone,
# and a client-side regex is extractable from an installed plugin no matter how
# it is encoded. Obfuscating a shipped pack would buy the appearance of secrecy
# and none of the substance.
#
# So proprietary detections are never committed. They load at runtime from a
# pack outside the tree -- generated on the operator's own machine from a source
# they already license -- and the loader below is the only public part.
#
# A pack is JSON:
#   {"name": ..., "version": ..., "rules": [
#      {"id": ..., "title": ..., "pattern": ..., "action": ..., "scope": [...]}
#   ]}
# `scope` selects which surfaces a rule applies to: "prompt", "content",
# "command". Unknown actions degrade to MONITOR rather than failing closed on a
# malformed pack, because a broken pack must not brick the developer's editor.

PACK_SCOPES = ("prompt", "content", "command")
_VALID_ACTIONS = {DENY, REQUIRE_APPROVAL, MASK, MONITOR, ALLOW}

# A pack can hold hundreds of rules, and the hook runs on every tool call. On a
# very large file the linear sweep becomes noticeable, so content is truncated
# for pack evaluation. Secrets live in configuration and headers, not a hundred
# kilobytes into a generated file, and the built-in pack still reads the whole
# text: this bounds the imported rules, not the core ones.
PACK_SCAN_LIMIT = 65_536

# Ordered by precedence: an explicit path wins, then the user's Enkstein home.
_PACK_ENV = "ENKSTEIN_POLICY_PACK"
_PACK_DEFAULTS = (
    os.path.join(os.path.expanduser("~"), ".enkstein", "policy-packs"),
)


@dataclass
class PackRule:
    rule_id: str
    title: str
    pattern: "re.Pattern[str]"
    action: str
    scopes: tuple[str, ...]
    pack: str
    # Lowercased literals, at least one of which must appear for the pattern to
    # have any chance of matching. A substring test is far cheaper than a regex
    # sweep, and across hundreds of rules that is the whole cost of the hook.
    anchor: tuple[str, ...] | None = None


# Literals a pattern requires in order to match. Testing for them first is far
# cheaper than running the regex, and across a couple of hundred imported rules
# that prefilter is most of the hook's cost.
#
# Two shapes qualify. A top-level literal outside any group is required
# outright. A leading alternation whose every branch begins with a literal --
# `(?:ABA|routing|RTN)...` -- is required as a set: if none of the branches
# appears, the pattern cannot match. Anything else yields no anchor and the
# rule is always evaluated, because a slower scan is acceptable and a missed
# match is not.
_TOP_LEVEL_LITERAL = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,}")
# Branches may be short country or scheme codes -- `(?:GB|DE|FR|...)` -- which
# are individually weak but collectively selective, so a lower bound applies
# inside an alternation than for a lone literal.
_BRANCH_LITERAL = re.compile(r"[A-Za-z][A-Za-z0-9_]+")
# Branch text may contain escapes such as `\s`, so only the structural
# characters that would end the group are excluded.
_LEADING_GROUP = re.compile(r"^(?:\\b)?\(\?:((?:[^()\[\]]|\\.)+?)\)")


def _anchor_for(pattern: str) -> tuple[str, ...] | None:
    group = _LEADING_GROUP.match(pattern)
    if group:
        branches = group.group(1).split("|")
        literals = []
        for branch in branches:
            token = _BRANCH_LITERAL.match(branch.strip())
            if not token:
                literals = []
                break
            literals.append(token.group(0).lower())
        if literals:
            return tuple(sorted(set(literals)))

    if "|" in pattern.replace(r"\|", ""):
        return None

    best: str | None = None
    depth = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char in "([":
            depth += 1
            index += 1
            continue
        if char in ")]":
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth == 0:
            match = _TOP_LEVEL_LITERAL.match(pattern, index)
            if match:
                token = match.group(0)
                # `abcd?` makes only the final character optional, so the
                # literal minus that character is still required.
                if pattern[match.end():match.end() + 1] in "?*":
                    token = token[:-1]
                if len(token) >= 4 and (best is None or len(token) > len(best)):
                    best = token
                index = match.end()
                continue
        index += 1
    return (best.lower(),) if best else None


def _pack_paths() -> list[str]:
    explicit = os.environ.get(_PACK_ENV, "").strip()
    roots = [explicit] if explicit else list(_PACK_DEFAULTS)
    found: list[str] = []
    for root in roots:
        if not root:
            continue
        if os.path.isfile(root):
            found.append(root)
        elif os.path.isdir(root):
            found.extend(
                os.path.join(root, name)
                for name in sorted(os.listdir(root))
                if name.endswith(".json")
            )
    return found


def _compile_pack(raw: dict, source: str) -> list[PackRule]:
    pack_name = str(raw.get("name") or os.path.basename(source))
    rules: list[PackRule] = []
    for entry in raw.get("rules") or []:
        try:
            pattern = re.compile(entry["pattern"], re.IGNORECASE)
        except (KeyError, TypeError, re.error):
            # One malformed rule must not discard the rest of the pack.
            continue
        action = entry.get("action", MONITOR)
        if action not in _VALID_ACTIONS:
            action = MONITOR
        scopes = tuple(s for s in entry.get("scope", PACK_SCOPES) if s in PACK_SCOPES)
        if not scopes:
            continue
        rules.append(PackRule(
            rule_id=str(entry.get("id") or f"{pack_name}.rule"),
            title=str(entry.get("title") or "Sensitive data"),
            pattern=pattern,
            action=action,
            scopes=scopes,
            pack=pack_name,
            anchor=_anchor_for(entry["pattern"]),
        ))
    return rules


@functools.lru_cache(maxsize=1)
def load_packs() -> tuple[PackRule, ...]:
    """Load private rule packs. Cached: a hook runs on every keystroke-fast call."""
    rules: list[PackRule] = []
    for path in _pack_paths():
        try:
            with open(path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            continue
        if isinstance(raw, dict):
            rules.extend(_compile_pack(raw, path))
    return tuple(rules)


def scan_with_packs(text: str, scope: str) -> Decision:
    """Evaluate private pack rules for one surface."""
    if not text:
        return Decision(ALLOW)
    text = text[:PACK_SCAN_LIMIT]

    findings: list[Finding] = []
    lowered = text.lower()
    for rule in load_packs():
        if scope not in rule.scopes:
            continue
        if rule.anchor and not any(a in lowered for a in rule.anchor):
            continue
        match = rule.pattern.search(text)
        if not match:
            continue
        start = text.rfind("\n", 0, match.start()) + 1
        end = text.find("\n", match.end())
        line_text = text[start : end if end != -1 else len(text)]
        if _is_benign(rule.rule_id, match.group(0), line_text):
            continue
        findings.append(Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            decision=rule.action,
            detail=_describe(match.group(0)),
            line=_line_of(text, match.start()),
        ))

    return Decision(_worst(f.decision for f in findings), findings)


def combine(*decisions: Decision) -> Decision:
    """Merge decisions, strictest wins, keeping every finding for the reason."""
    findings: list[Finding] = []
    for decision in decisions:
        findings.extend(decision.findings)
    return Decision(_worst(d.decision for d in decisions), findings)


def redact(text: str, scope: str) -> tuple[str, list[Finding]]:
    """Replace values from MASK-action rules, leaving the rest of the text intact.

    Masking only makes sense where the surface can be rewritten. Claude Code
    accepts `updatedInput` on PreToolUse, so a file write or command can be
    sanitized in flight; there is no equivalent for a submitted prompt, which is
    why prompt-scope mask rules are treated as approval-required by the caller.
    """
    if not text:
        return text, []

    applied: list[Finding] = []
    result = text
    lowered = text.lower()
    for rule in load_packs():
        if scope not in rule.scopes or rule.action != MASK:
            continue
        if rule.anchor and not any(a in lowered for a in rule.anchor):
            continue

        hits: list[Finding] = []

        def _swap(match: "re.Match[str]") -> str:
            value = match.group(0)
            start = result.rfind("\n", 0, match.start()) + 1
            end = result.find("\n", match.end())
            if _is_benign(rule.rule_id, value, result[start : end if end != -1 else len(result)]):
                return value
            hits.append(Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                decision=MASK,
                detail=_describe(value),
                line=_line_of(result, match.start()),
            ))
            return _mask_value(value)

        result = rule.pattern.sub(_swap, result)
        applied.extend(hits)

    return result, applied


def _mask_value(value: str) -> str:
    """Keep the shape so the model can still reason about the code."""
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:3]}[REDACTED:{len(value)}]{value[-2:]}"
