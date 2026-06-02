# NOTE: mirrored from backend/app/claws/arcclaw/scanner.py — keep in sync via scripts/sync_core.sh.
# This module is intentionally dependency-light (stdlib + cryptography) so it
# can run embedded with no RegentClaw server.
"""
ArcClaw — Sensitive Pattern Scanner
Inspects AI prompts and outputs for sensitive data patterns.
Inspired by 1Password's warning: a skill is never just content.
"""
import re
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    is_sensitive: bool
    findings: list[dict] = field(default_factory=list)
    risk_signals: list[str] = field(default_factory=list)
    redacted: str = ""


# Pattern definitions: (name, regex, signal_key)
PATTERNS = [
    ("API Key", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", "ai_sensitive_pattern"),
    ("Password", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?(\S{6,})", "ai_sensitive_pattern"),
    ("Bearer Token", r"(?i)bearer\s+([A-Za-z0-9\-._~+/]{20,})", "ai_sensitive_pattern"),
    ("AWS Key", r"AKIA[0-9A-Z]{16}", "credential_access_attempt"),
    ("Private Key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "credential_access_attempt"),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", "ai_sensitive_pattern"),
    ("Credit Card", r"\b(?:\d[ -]?){13,16}\b", "ai_sensitive_pattern"),
    ("Email Address", r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", "ai_sensitive_pattern"),
    ("Connection String", r"(?i)(Server=|Data Source=|mongodb\+srv://|postgresql://|mysql://)", "credential_access_attempt"),
    ("Secret/Token var", r"(?i)(secret|token|auth_token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{10,})", "ai_sensitive_pattern"),
    ("Shell command", r"(?:bash|sh|cmd|powershell)\s+-c\s+['\"]", "shell_access_attempt"),
    # Base64 payload — require at least one + or / to avoid flagging UUIDs/URLs/
    # normal long alphanumeric strings. Must also end with = padding or a +//.
    ("Base64 payload", r"(?:[A-Za-z0-9+/]{20,}[+/][A-Za-z0-9+/]{10,}={0,2})", "ai_sensitive_pattern"),
]

REDACT_REPLACEMENT = "[REDACTED]"


def scan_text(text: str, redact: bool = True) -> ScanResult:
    """Scan text for sensitive patterns. Optionally redact matches."""
    findings = []
    signals = set()
    redacted_text = text

    for name, pattern, signal in PATTERNS:
        try:
            matches = list(re.finditer(pattern, text))
            if matches:
                findings.append({
                    "pattern": name,
                    "count": len(matches),
                    "signal": signal,
                })
                signals.add(signal)
                if redact:
                    redacted_text = re.sub(pattern, REDACT_REPLACEMENT, redacted_text)
        except re.error:
            continue

    return ScanResult(
        is_sensitive=bool(findings),
        findings=findings,
        risk_signals=list(signals),
        redacted=redacted_text if redact else text,
    )


def classify_prompt(prompt: str) -> dict:
    """Classify the nature and intent of an AI prompt."""
    prompt_lower = prompt.lower()

    categories = []
    if any(w in prompt_lower for w in ["write code", "generate code", "script", "function"]):
        categories.append("code_generation")
    if any(w in prompt_lower for w in ["summarize", "explain", "describe"]):
        categories.append("summarization")
    if any(w in prompt_lower for w in ["delete", "remove", "drop", "wipe"]):
        categories.append("destructive_intent")
    if any(w in prompt_lower for w in ["export", "send", "upload", "share"]):
        categories.append("data_movement")
    if any(w in prompt_lower for w in ["password", "credentials", "secret", "key", "token"]):
        categories.append("credential_reference")

    risk_level = "low"
    if "destructive_intent" in categories or "credential_reference" in categories:
        risk_level = "high"
    elif "data_movement" in categories or "code_generation" in categories:
        risk_level = "medium"

    return {
        "categories": categories,
        "risk_level": risk_level,
        "word_count": len(prompt.split()),
    }
