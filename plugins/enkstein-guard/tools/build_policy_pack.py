#!/usr/bin/env python3
"""Build a private Enkstein Guard policy pack from a licensed detection engine.

Enkstein Guard ships an open engine and no proprietary rules. Detection content
you license separately stays yours: this tool reads an engine already installed
on your own machine and writes a pack into ~/.enkstein/policy-packs, which is
outside the repository and never committed.

The pack is read at runtime by hooks/policy.py. Nothing here uploads, and no
pattern is copied into the source tree.

    python3 tools/build_policy_pack.py --source /path/to/engine.py

Severity maps to an Enkstein action:
    critical -> deny              a live credential must not leave the machine
    high     -> require_approval  a human decides
    medium   -> mask              rewritten in flight where the surface allows
    low      -> monitor           recorded, never interrupts
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path

DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
MASK = "mask"
MONITOR = "monitor"

SEVERITY_ACTION = {
    "critical": DENY,
    "high": REQUIRE_APPROVAL,
    "medium": MASK,
    "low": MONITOR,
}

# Detections that are meaningful in prose but ruinous in source, and the
# reverse. A rule that fires on every file in a repository gets the whole hook
# switched off, which protects nobody.
PROMPT_ONLY = {
    "SSN", "SSN_DOT", "CREDIT_CARD", "IBAN", "SWIFT_BIC", "ROUTING_NUMBER",
    "US_PASSPORT", "UK_PASSPORT", "CA_PASSPORT", "AU_PASSPORT", "EU_PASSPORT",
    "PASSPORT", "DRIVER_LICENSE", "NATIONAL_ID", "MRN", "PATIENT_ID",
    "MEDICARE_ID", "MEDICAID_ID", "INSURANCE_POLICY", "EMAIL", "PHONE",
    "STREET_ADDRESS", "GPS_COORDINATES", "EMPLOYEE_ID",
}

# Measured against this repository's own source: these fire on ordinary code
# because they were written for a proxy reading chat prose, where `password:`
# introduces a value rather than a variable name and `session_id` is a leak
# rather than a parameter. They stay enabled for prompts, where the original
# meaning holds, and are withdrawn from file and command scanning.
#
# Verify with --measure before adding to this list. Guessing which rules are
# noisy is how a guard ends up either useless or uninstalled.
PROSE_ONLY = {
    "HARDCODED_SECRET", "CONFIDENTIAL_DOC", "RBAC", "CREDENTIAL",
    "GROUP_NUMBER", "USERNAME_PASSWORD", "BULK_RECORDS", "PROD_DATA",
    "SENSITIVE_FILENAME", "SESSION_TOKEN", "SECURITY_QUESTION",
    "SUPERADMIN", "WIRE_TRANSFER", "HEALTH_KEYWORD", "PROMPT_INJECTION",
}

# Detections the open pack already covers, and covers *better*, because they
# were tuned against the false positives a coding agent actually produces.
# The proxy versions are context-free: it reads chat prose, where a bare
# NNN-NN-NNNN almost always is an SSN. In a developer's terminal the same shape
# is a ticket id, a version string, or a phone number, so the open pack requires
# a nearby mention of what the number is, and requires a Luhn check on cards.
#
# Importing the cruder form would silently undo that work, so these are never
# imported. Enkstein's own rule stays authoritative.
REDUNDANT = {
    "SSN",          # prompt.ssn requires nearby "ssn"/"social security" context
    "SSN_DOT",      # same rule, dotted form
    "CREDIT_CARD",  # prompt.payment_card verifies the Luhn check digit
    "EMAIL",        # deliberately excluded: license headers, package.json authors
    "PHONE",        # deliberately excluded: test fixtures and sample data
}

# Rules whose match rate in ordinary engineering work is so high that including
# them would train people to disable the guard. Compliance keywords fire on any
# security document; MITRE and CVE identifiers fire on any advisory; SQL fires
# on every migration.
EXCLUDE_PREFIXES = ("COMPLIANCE_", "MITRE_", "IOC_")
EXCLUDE_EXACT = {
    "COMPLIANCE", "CVE", "CWE", "CVSS", "NVD", "SQL_QUERY", "DB_DUMP",
    "SOURCE_CODE", "IP_ADDRESS", "SUBNET", "LOCALHOST_URL", "INTERNAL_URL",
    "MEETING_URL", "EMAIL_SUBJECT", "INTERNAL_COMMS", "REMEDIATION",
    "THREAT_INTEL", "BREACH_DETAILS", "FORENSIC_REPORT", "EXPLOIT_CODE",
    "INCIDENT_ID", "SECURITY_TICKET", "VULN_SCANNER", "SIEM_ALERT",
    "EDR_ALERT", "LEGAL_TERMS", "CASE_NUMBER", "EXPERIMENTAL",
    "RESEARCH_PROJECT", "PAYMENT_TERMS", "VENDOR_CONTRACT", "RESIGNATION",
    "CUSTOMER_MEETING", "SENSITIVE_BUSINESS", "EXECUTIVE_COMMS",
    "FINANCIAL_FORECAST", "LEGAL_STRATEGY", "ATTORNEY_CLIENT",
    "CUSTOM_KEYWORD", "PERSONA", "PATENT", "TRADE_SECRET",
}

# These two private policies are covered by stricter open rules. The private
# SSN expression is context-free and would block ticket/version numbers; the
# card expression lacks the Luhn validation that prevents long-number noise.
# Keeping the policy identity with a `covered_by` marker preserves all 60
# policies without reintroducing known false positives.
BUILT_IN_POLICY_COVERAGE = {
    1: ["prompt.ssn", "secret.ssn"],
    2: ["prompt.payment_card"],
}

# These policy families contain deterministic credential/key expressions that
# remain meaningful in source code without the licensed engine's LLM context
# layer. Other policies still govern prompts, but their regex fallbacks alone
# are too broad for files (`source code`, `internal URL`, `network address`,
# and `R&D` matched 131 of 282 ordinary Python files during measurement).
SAFE_CONTENT_POLICY_IDS = {4, 5, 13, 32}

# Within otherwise code-safe policy families, these regex fallbacks are still
# broader than Enkstein's tuned built-ins: short `sk-*` identifiers, field names
# such as `api_key_type`, function calls containing `password`, and
# `private_key()` all look like values to the raw expression. They remain active
# for prompts but not source or command content.
PROMPT_ONLY_POLICY_RULES = {(4, 1), (4, 2), (32, 4), (32, 6)}


def _dict_node(tree: ast.Module, name: str) -> ast.Dict | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    if isinstance(node.value, ast.Dict):
                        return node.value
    return None


def _extract_patterns(source: str) -> dict[str, str]:
    """Pull `NAME: re.compile(r"...")` literals out without importing anything.

    The engine is a mitmproxy addon: importing it would pull in mitmproxy and
    start its machinery. Parsing the AST reads the same definitions with no
    side effects and no dependency.
    """
    tree = ast.parse(source)
    node = _dict_node(tree, "MASK_PATTERNS")
    if node is None:
        raise SystemExit("No MASK_PATTERNS dictionary found in the source engine.")

    patterns: dict[str, str] = {}
    for key, value in zip(node.keys, node.values):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            continue
        if not (isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "compile"
                and value.args
                and isinstance(value.args[0], ast.Constant)):
            continue
        patterns[key.value] = value.args[0].value
    return patterns


def _extract_groups(source: str) -> dict[str, list[str]]:
    tree = ast.parse(source)
    node = _dict_node(tree, "POLICY_TO_DETECTION")
    if node is None:
        return {}

    groups: dict[str, list[str]] = {}
    for key, value in zip(node.keys, node.values):
        if not isinstance(key, ast.Constant) or not isinstance(value, ast.List):
            continue
        members = [
            item.value for item in value.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        ]
        if members:
            groups[key.value] = members
    return groups


def _severity_of(policy_key: str) -> str:
    """Infer severity from the policy group a detection belongs to.

    The engine stores severity in tenant configuration rather than beside the
    pattern, so the shipped grouping is the only source available offline. It
    errs toward approval, not silence.
    """
    key = policy_key.lower()
    if any(word in key for word in ("secret", "credential", "api_key", "encryption",
                                    "shadowkey", "cipher", "coffer", "code_config")):
        return "critical"
    if any(word in key for word in ("social_security", "financial_fortress",
                                    "finance_fortifier", "health_data", "identity_shield",
                                    "session_access", "authentication_artifact",
                                    "password_reset")):
        return "critical"
    if any(word in key for word in ("personal_information", "geolocation",
                                    "prompt_injection", "employee", "government",
                                    "third_party", "reidentify")):
        return "high"
    return "medium"


def _usable(pattern: str) -> bool:
    """Reject patterns that cannot be evaluated by the hook's plain `re`."""
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error:
        return False
    # A pattern this loose matches something in nearly any file.
    return len(pattern) > 12


def _literal_assignment(tree: ast.AST, name: str, default=None):
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        try:
            return ast.literal_eval(node.value)
        except (ValueError, TypeError):
            return default
    return default


def _policy_source_dir(source_path: str) -> Path | None:
    source = Path(source_path).expanduser().resolve()
    candidates = []
    if source.is_dir():
        candidates.extend((source, source / "core" / "llm_policy_engine"))
    else:
        candidates.extend((source.parent / "core" / "llm_policy_engine", source.parent))
    for candidate in candidates:
        if len(list(candidate.glob("policy[0-9][0-9]_*.py"))) == 60:
            return candidate
    return None


def _extract_policy_module(path: Path) -> dict:
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    policy_id = int(_literal_assignment(tree, "POLICY_ID", 0) or 0)
    policy_key = str(_literal_assignment(tree, "POLICY_KEY", "") or "")
    policy_name = str(_literal_assignment(tree, "POLICY_NAME", "") or "")
    severity = str(_literal_assignment(tree, "SEVERITY", "medium") or "medium").lower()
    risk_score = int(_literal_assignment(tree, "DEFAULT_RISK_SCORE", 50) or 50)
    scopes = list(_literal_assignment(tree, "SCOPES", []) or [])
    patterns = list(_literal_assignment(tree, "REGEX_PATTERNS", []) or [])

    # A small number of policies implement a custom compiled expression rather
    # than REGEX_PATTERNS. Extract the literal without importing the licensed
    # package or executing any of its code.
    if not patterns:
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "compile"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                continue
            patterns.append(node.args[0].value)

    if not (1 <= policy_id <= 60 and policy_key and policy_name):
        raise ValueError(f"Invalid policy metadata in {path.name}")
    return {
        "id": policy_id,
        "key": policy_key,
        "name": policy_name,
        "severity": severity,
        "risk_score": risk_score,
        "source_scopes": scopes,
        "patterns": patterns,
    }


def _guard_scopes(policy_id: int, source_scopes: list[str]) -> list[str]:
    scopes = {"prompt"}
    if (policy_id in SAFE_CONTENT_POLICY_IDS
            and any(value in source_scopes for value in ("code_text", "config_text"))):
        scopes.update(("content", "command"))
    return sorted(scopes)


def _build_policy_modules(source_dir: Path, pack_name: str) -> dict:
    modules = [
        _extract_policy_module(path)
        for path in sorted(source_dir.glob("policy[0-9][0-9]_*.py"))
    ]
    ids = [item["id"] for item in modules]
    if ids != list(range(1, 61)):
        raise SystemExit(f"Expected private policy IDs 1-60, found {ids}")

    rules = []
    policies = []
    skipped = 0
    for item in modules:
        built_in = BUILT_IN_POLICY_COVERAGE.get(item["id"], [])
        action = SEVERITY_ACTION.get(item["severity"], MONITOR)
        scopes = _guard_scopes(item["id"], item["source_scopes"])
        rule_count = 0

        if not built_in:
            for index, pattern in enumerate(item["patterns"], start=1):
                if not _usable(pattern):
                    skipped += 1
                    continue
                rule_scopes = (
                    ["prompt"]
                    if (item["id"], index) in PROMPT_ONLY_POLICY_RULES
                    else scopes
                )
                rules.append({
                    "id": f"{pack_name}.policy{item['id']:02d}.{item['key']}.r{index}",
                    "policy_id": item["id"],
                    "policy_key": item["key"],
                    "policy_name": item["name"],
                    "title": item["name"],
                    "pattern": pattern,
                    "action": action,
                    "scope": rule_scopes,
                })
                rule_count += 1

        policies.append({
            "id": item["id"],
            "key": item["key"],
            "name": item["name"],
            "severity": item["severity"],
            "risk_score": item["risk_score"],
            "scope": scopes,
            "rule_count": rule_count,
            "covered_by": built_in,
        })

    return {
        "name": pack_name,
        "version": 2,
        "source": source_dir.name,
        "policy_count": len(policies),
        "policies": policies,
        "rules": rules,
        "_skipped": skipped,
    }


def build(source_path: str, pack_name: str) -> dict:
    policy_dir = _policy_source_dir(source_path)
    if policy_dir is not None:
        return _build_policy_modules(policy_dir, pack_name)

    with open(source_path, encoding="utf-8", errors="replace") as handle:
        source = handle.read()

    patterns = _extract_patterns(source)
    groups = _extract_groups(source)

    owner: dict[str, str] = {}
    for policy_key, members in groups.items():
        for member in members:
            owner.setdefault(member, policy_key)

    rules = []
    skipped = 0
    for name, pattern in sorted(patterns.items()):
        if name in EXCLUDE_EXACT or name in REDUNDANT or name.startswith(EXCLUDE_PREFIXES):
            skipped += 1
            continue
        if not _usable(pattern):
            skipped += 1
            continue

        policy_key = owner.get(name)
        if policy_key is None:
            skipped += 1
            continue

        action = SEVERITY_ACTION[_severity_of(policy_key)]
        if name in PROMPT_ONLY or name in PROSE_ONLY:
            scope = ["prompt"]
        else:
            scope = ["prompt", "content", "command"]

        rules.append({
            "id": f"{pack_name}.{policy_key}.{name.lower()}",
            "title": name.replace("_", " ").title(),
            "pattern": pattern,
            "action": action,
            "scope": scope,
        })

    return {
        "name": pack_name,
        "version": 1,
        "source": os.path.basename(source_path),
        "policy_count": len(groups),
        "policies": [
            {"key": key, "name": key.replace("_", " ").title()}
            for key in sorted(groups)
        ],
        "rules": rules,
        "_skipped": skipped,
    }


def _measure(pack: dict, root: str) -> int:
    """Count how often each file-scope rule matches real source.

    A rule that fires on ordinary code is worse than no rule: it trains the
    developer to bypass the guard, and then nothing is protected.
    """
    extensions = (".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java",
                  ".rb", ".sh", ".yaml", ".yml", ".json", ".md")
    texts: list[str] = []
    for directory, _, names in os.walk(root):
        if any(part in directory for part in ("node_modules", ".git", ".venv", "__pycache__")):
            continue
        for name in names:
            if not name.endswith(extensions):
                continue
            try:
                with open(os.path.join(directory, name), encoding="utf-8", errors="replace") as handle:
                    texts.append(handle.read())
            except OSError:
                continue

    counts: list[tuple[int, str]] = []
    for rule in pack["rules"]:
        if "content" not in rule["scope"]:
            continue
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        hits = sum(1 for text in texts if pattern.search(text))
        if hits:
            counts.append((hits, rule["id"]))

    print(f"Scanned {len(texts)} files under {root}")
    if not counts:
        print("No file-scope rule matched. Nothing to move into PROSE_ONLY.")
        return 0
    print(f"{len(counts)} of {len(pack['rules'])} rules matched at least once:\n")
    for hits, name in sorted(counts, reverse=True):
        share = hits / len(texts) * 100
        flag = "  <- consider PROSE_ONLY" if share >= 1.0 else ""
        print(f"  {hits:5} files ({share:5.1f}%)  {name}{flag}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True,
                        help="Path to the licensed detection engine on this machine.")
    parser.add_argument("--name", default="private",
                        help="Pack name, used to prefix rule ids.")
    parser.add_argument("--measure", metavar="DIR",
                        help="Report how often each rule fires against real source "
                             "in DIR instead of writing a pack. Use this to decide "
                             "what belongs in PROSE_ONLY.")
    parser.add_argument("--out", default=os.path.join(
        os.path.expanduser("~"), ".enkstein", "policy-packs"))
    args = parser.parse_args()

    if not os.path.exists(args.source):
        print(f"Source engine not found: {args.source}", file=sys.stderr)
        return 1

    pack = build(args.source, args.name)
    skipped = pack.pop("_skipped")

    if args.measure:
        return _measure(pack, args.measure)

    os.makedirs(args.out, exist_ok=True)
    destination = os.path.join(args.out, f"{args.name}.json")
    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(pack, handle, indent=2)
    os.chmod(destination, 0o600)

    counts: dict[str, int] = {}
    for rule in pack["rules"]:
        counts[rule["action"]] = counts.get(rule["action"], 0) + 1

    print(
        f"Wrote {len(pack.get('policies', []))} policies / "
        f"{len(pack['rules'])} rules to {destination}"
    )
    print(f"Skipped {skipped} detections as too noisy for a coding agent.")
    for action in (DENY, REQUIRE_APPROVAL, MASK, MONITOR):
        if counts.get(action):
            print(f"  {action:<17} {counts[action]}")
    print("\nThis pack is outside the repository and is not committed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
