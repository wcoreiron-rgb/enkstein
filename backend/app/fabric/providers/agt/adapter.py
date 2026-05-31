"""Regent Fabric -> AGT adapter.

Keeps AGT wiring in one place so Claws do not import AGT directly.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.trust_fabric.agt_bridge import (
    AGT_AVAILABLE,
    agt_status,
    scan_module_directory,
    scan_package_json,
    scan_requirements,
)
from app.fabric.providers.agt.version import AGTVersionInfo
from app.fabric.security import get_agent_signer


@dataclass(frozen=True)
class AGTFeatureFlags:
    version_mode: str
    enable_agent_mesh: bool
    enable_e2e_messaging: bool
    enable_mcp_gateway: bool
    enable_shadow_discovery: bool


class AGTAdapter:
    def __init__(self) -> None:
        self.version = AGTVersionInfo(compatibility_mode=settings.AGT_VERSION_MODE)
        self.flags = AGTFeatureFlags(
            version_mode=settings.AGT_VERSION_MODE,
            enable_agent_mesh=settings.AGT_ENABLE_AGENT_MESH,
            enable_e2e_messaging=settings.AGT_ENABLE_E2E_MESSAGING,
            enable_mcp_gateway=settings.AGT_ENABLE_MCP_GATEWAY,
            enable_shadow_discovery=settings.AGT_ENABLE_SHADOW_DISCOVERY,
        )

    def status(self) -> dict[str, Any]:
        signer = get_agent_signer()
        signer_status = signer.status()
        return {
            "provider": self.version.provider,
            "sdk_target": self.version.sdk_target,
            "agt_available": AGT_AVAILABLE,
            "features": asdict(self.flags),
            "bridge": agt_status(),
            "crypto_identity": {
                "enabled": signer_status.available,
                "algorithm": signer_status.algorithm,
                "key_id": signer_status.key_id,
            },
        }

    def scan_backend_deps(self, requirements_path: str) -> dict[str, Any]:
        result = scan_requirements(requirements_path)
        return asdict(result)

    def scan_frontend_deps(self, package_json_path: str) -> dict[str, Any]:
        result = scan_package_json(package_json_path)
        return asdict(result)

    def scan_path(self, path: str) -> dict[str, Any]:
        resolved = Path(path).resolve(strict=False)
        repo_root = Path(__file__).resolve().parents[4]
        try:
            resolved.relative_to(repo_root)
        except ValueError:
            return {
                "is_safe": False,
                "risk_score": 100.0,
                "findings": [],
                "critical_count": 0,
                "high_count": 0,
                "agt_used": True,
                "path": str(repo_root),
                "error": "Path outside repository root",
            }

        result = scan_module_directory(str(resolved))
        payload = asdict(result)
        payload["path"] = str(resolved)
        return payload

    def send_secure_message(
        self,
        sender: str,
        recipient: str,
        message_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        E2E messaging feature-flag path.
        Keeps all call-sites on Regent Fabric even when AGT capability is toggled.
        """
        if not self.flags.enable_e2e_messaging:
            return {
                "enabled": False,
                "status": "disabled",
                "provider": "agt",
            }

        signer = get_agent_signer()
        metadata = {
            "timestamp": int(time.time()),
            "nonce": secrets.token_hex(12),
            "message_id": secrets.token_hex(16),
        }
        message = {
            "sender": sender,
            "recipient": recipient,
            "message_type": message_type,
            "payload": payload,
            "metadata": metadata,
        }
        raw = json.dumps(
            message,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        envelope = base64.b64encode(raw).decode("ascii")
        signature = signer.sign(raw)

        return {
            "enabled": True,
            "status": "simulated_encrypted" if not AGT_AVAILABLE else "encrypted",
            "provider": "agt",
            "sender": sender,
            "recipient": recipient,
            "message_type": message_type,
            "envelope": envelope,
            "digest": digest,
            "signature": signature,
            "signature_algorithm": signer.algorithm,
            "key_id": signer.key_id,
            "metadata": metadata,
        }

    def verify_secure_message(self, envelope: str, signature: str, key_id: str | None = None) -> dict[str, Any]:
        signer = get_agent_signer()
        try:
            raw = base64.b64decode(envelope.encode("ascii"))
        except Exception:
            return {"verified": False, "reason": "invalid_envelope_encoding"}

        verified = signer.verify(raw, signature, key_id=key_id)
        return {
            "verified": verified,
            "algorithm": signer.algorithm,
            "key_id": signer.key_id,
        }


_adapter: AGTAdapter | None = None


def get_agt_adapter() -> AGTAdapter:
    global _adapter
    if _adapter is None:
        _adapter = AGTAdapter()
    return _adapter
