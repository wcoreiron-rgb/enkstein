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

import re
import shlex
from dataclasses import dataclass, field
from typing import Iterable

# Decisions mirror app/models/policy.py:PolicyAction so a rule keeps its meaning
# whether it is evaluated locally or by the Trust Fabric.
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
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

_RANK = {ALLOW: 0, MONITOR: 1, REQUIRE_APPROVAL: 2, DENY: 3}


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

    return Decision(_worst(f.decision for f in findings), findings)


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

    return Decision(_worst(f.decision for f in findings), findings)


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
