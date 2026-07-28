"""Governed local Prowler runner and result normalizer.

Prowler is an executable dependency, not a Python library embedded in
Enkstein. This module treats it as a read-only local scanner:

* no shell is used and user values never become command fragments;
* only documented providers are accepted;
* cloud credentials are passed through the child environment, never argv;
* execution is timeout-bounded and output is capped;
* a non-zero exit without parseable results is a failure, never a clean scan;
* every normalized result receives a stable ``prowler:<check_id>`` control id.

Prowler publishes JSON OCSF/ASFF output and compliance metadata. The parser
accepts both shapes because the CLI has emitted both across supported versions.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from app.claws import provenance

SUPPORTED_PROVIDERS = frozenset({"aws", "azure", "gcp", "kubernetes", "github"})
ALLOWED_EXECUTABLES = frozenset({"prowler", "prowler-cli.py", "prowler.exe"})
MAX_TIMEOUT_SECONDS = 1800
MAX_OUTPUT_FILES = 2000
MAX_FILE_BYTES = 10 * 1024 * 1024
_CHECK_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")


class ProwlerError(RuntimeError):
    """A safe, operator-facing Prowler execution error."""


def _executable(value: str | None) -> str:
    candidate = value or shutil.which("prowler") or "prowler"
    name = Path(candidate).name
    if name not in ALLOWED_EXECUTABLES:
        raise ProwlerError("Prowler executable must be prowler or prowler-cli.py")
    return candidate


def _provider(value: Any) -> str:
    provider = str(value or "").strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise ProwlerError(
            "Prowler provider must be one of: " + ", ".join(sorted(SUPPORTED_PROVIDERS))
        )
    return provider


def _command(credentials: dict[str, Any], output_dir: str) -> list[str]:
    provider = _provider(credentials.get("provider", "aws"))
    argv = [
        _executable(credentials.get("executable")),
        provider,
        "-M",
        "json-ocsf",
        "-o",
        output_dir,
    ]
    checks = credentials.get("checks")
    if checks:
        values = checks if isinstance(checks, list) else str(checks).split(",")
        clean = [str(item).strip() for item in values if str(item).strip()]
        if not clean or any(not _CHECK_ID.fullmatch(item) for item in clean):
            raise ProwlerError("Prowler checks contain an invalid check identifier")
        argv.extend(["--checks", ",".join(clean)])
    if credentials.get("region"):
        argv.extend(["--region", str(credentials["region"])])
    if credentials.get("profile"):
        argv.extend(["--profile", str(credentials["profile"])])
    return argv


def _environment(credentials: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    # Only provider credential names are copied. Arbitrary user keys must not
    # become process environment injection or accidental telemetry.
    mapping = {
        "access_key_id": "AWS_ACCESS_KEY_ID",
        "secret_access_key": "AWS_SECRET_ACCESS_KEY",
        "session_token": "AWS_SESSION_TOKEN",
        "azure_client_id": "AZURE_CLIENT_ID",
        "azure_client_secret": "AZURE_CLIENT_SECRET",
        "azure_tenant_id": "AZURE_TENANT_ID",
        "google_application_credentials": "GOOGLE_APPLICATION_CREDENTIALS",
        "github_token": "GITHUB_TOKEN",
    }
    for source, target in mapping.items():
        if credentials.get(source):
            env[target] = str(credentials[source])
    return env


def _items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("findings", "Findings", "resources", "Resources", "items", "Items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    # ASFF is commonly one finding per file.
    return [payload] if any(key in payload for key in ("Finding", "finding_info", "CheckID", "check_id")) else []


def _nested(item: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        current: Any = item
        for key in path:
            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
                current = current[key]
            else:
                current = None
                break
        if current not in (None, ""):
            return current
    return None


def normalize(items: list[dict[str, Any]], provider: str) -> list[dict[str, Any]]:
    """Convert Prowler OCSF/ASFF rows into Enkstein findings."""
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        check_id = str(_nested(
            item,
            ("check_id",), ("CheckID",), ("check_metadata", "CheckID"),
            ("metadata", "check_id"), ("GeneratorId",),
        ) or "unknown")
        finding_id = str(_nested(item, ("finding_info", "uid"), ("Id",), ("id",)) or check_id)
        if finding_id in seen:
            continue
        seen.add(finding_id)
        severity = str(_nested(
            item, ("severity",), ("Severity", "Label"), ("severity", "label")
        ) or "medium").lower()
        severity = {"informational": "info", "warning": "medium", "critical": "critical"}.get(severity, severity)
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "medium"
        title = str(_nested(
            item, ("finding_info", "title"), ("Title",), ("title",), ("check_metadata", "CheckTitle")
        ) or f"Prowler check {check_id}")[:512]
        description = _nested(item, ("finding_info", "desc"), ("Description",), ("description",))
        remediation = _nested(item, ("remediation", "desc"), ("Remediation", "Recommendation", "Text"), ("remediation",))
        resource = _nested(item, ("resources", 0, "uid"), ("Resources", 0, "Id"), ("resource_id",))
        requirements = _nested(item, ("compliance", "Requirements"), ("Compliance", "RelatedRequirements"))
        if not isinstance(requirements, list):
            requirements = [str(requirements)] if requirements else []
        normalized.append({
            "provider": f"prowler_{provider}",
            "title": title,
            "description": description,
            "severity": severity,
            "risk_score": {"critical": 92, "high": 78, "medium": 55, "low": 32, "info": 12}[severity],
            "resource_id": str(resource) if resource else None,
            "resource_type": "cloud_resource",
            "external_id": f"prowler:{provider}:{finding_id}",
            "control_id": f"prowler:{provider}:{check_id}",
            "control_source": "prowler",
            "frameworks": {"prowler": requirements} if requirements else None,
            "zt_pillar": "applications" if provider in {"aws", "azure", "gcp", "kubernetes"} else "applications",
            "remediation": str(remediation) if remediation else None,
            "actively_exploited": False,
            "raw_data": item,
        })
    return provenance.live(normalized, provider=f"prowler_{provider}", connector="prowler")


async def run(credentials: dict[str, Any]) -> list[dict[str, Any]]:
    """Run Prowler read-only and return normalized live findings."""
    timeout = max(30, min(int(credentials.get("timeout_seconds", 900)), MAX_TIMEOUT_SECONDS))
    with tempfile.TemporaryDirectory(prefix="enkstein-prowler-") as output_dir:
        argv = _command(credentials, output_dir)
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_environment(credentials),
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise ProwlerError(f"Prowler exceeded the {timeout}-second timeout") from exc
        records: list[dict[str, Any]] = []
        for path in sorted(Path(output_dir).rglob("*.json"))[:MAX_OUTPUT_FILES]:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                records.extend(_items(json.loads(path.read_text())))
            except (OSError, json.JSONDecodeError):
                continue
        if process.returncode and not records:
            detail = stderr.decode(errors="replace").strip().splitlines()[-1:] 
            raise ProwlerError(detail[0][:300] if detail else f"Prowler exited with code {process.returncode}")
        return normalize(records, _provider(credentials.get("provider", "aws")))


def installation_status(executable: str | None = None) -> dict[str, Any]:
    """Return safe local readiness metadata without running a scan."""
    path = executable or shutil.which("prowler")
    installed = bool(path) and Path(path).exists() and Path(path).name in ALLOWED_EXECUTABLES
    return {"installed": installed, "executable": Path(path).name if installed else None}


async def fetch_findings(credentials: dict[str, Any]) -> list[dict[str, Any]]:
    return await run(credentials)
