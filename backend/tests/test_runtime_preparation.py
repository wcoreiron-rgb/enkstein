"""Startup data preparation diagnostics and status surface."""
from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from main import app


BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_entrypoint_collects_sanitizes_and_persists_seed_failures(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    status_file = tmp_path / "data_preparation.json"
    real_python = BACKEND_ROOT / ".venv" / "bin" / "python"

    _write_executable(
        fake_bin / "python",
        textwrap.dedent(
            f"""\
            #!{real_python}
            import os
            import sys

            if len(sys.argv) > 1 and sys.argv[1] == "-":
                source = sys.stdin.read()
                if "NamedTemporaryFile" in source or "sensitive_markers" in source:
                    sys.argv = sys.argv[1:]
                    exec(compile(source, "<entrypoint-test>", "exec"))
                raise SystemExit(0)

            script = os.path.basename(sys.argv[1]) if len(sys.argv) > 1 else ""
            if script == "seed_policies.py":
                for index in range(30):
                    print(f"verbose diagnostic {{index}}", file=sys.stderr)
                print(
                    "OperationalError: password="
                    + os.environ["POSTGRES_PASSWORD"]
                    + " at "
                    + os.environ["DATABASE_URL_SYNC"],
                    file=sys.stderr,
                )
                print("[parameters: ('tenant-api-credential-123',)]", file=sys.stderr)
                raise SystemExit(17)
            raise SystemExit(0)
            """
        ),
    )
    for command in ("alembic", "uvicorn"):
        _write_executable(fake_bin / command, "#!/bin/sh\nexit 0\n")

    password = "probe-password-that-must-not-leak"
    database_url = f"postgresql://marcellus:{password}@db:5432/probe"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "DATABASE_URL": database_url.replace("postgresql://", "postgresql+asyncpg://"),
            "DATABASE_URL_SYNC": database_url,
            "POSTGRES_PASSWORD": password,
            "ENKSTEIN_PREPARATION_STATUS_FILE": str(status_file),
        }
    )

    result = subprocess.run(
        ["bash", "entrypoint.sh"],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0
    assert "DATA PREPARATION DEGRADED: 1 failure(s)" in output
    assert "[seed] seed_policies.py" in output
    assert "OperationalError" in output
    assert password not in output
    assert database_url not in output
    assert "tenant-api-credential-123" not in output
    assert "[parameters: redacted]" in output
    assert output.count("verbose diagnostic") <= 11

    payload = json.loads(status_file.read_text(encoding="utf-8"))
    assert payload["status"] == "degraded"
    assert payload["ready"] is False
    assert payload["completed"] is True
    assert payload["failure_count"] == 1
    assert payload["failures"][0]["phase"] == "seed"
    assert payload["failures"][0]["name"] == "seed_policies.py"
    assert payload["failures"][0]["reason"].startswith("exit 17:")
    assert "OperationalError" in payload["failures"][0]["reason"]
    assert password not in json.dumps(payload)
    assert "tenant-api-credential-123" not in json.dumps(payload)


@pytest.mark.asyncio
async def test_runtime_preparation_endpoint_reads_status_artifact(
    client: AsyncClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_file = tmp_path / "data_preparation.json"
    monkeypatch.setenv("ENKSTEIN_PREPARATION_STATUS_FILE", str(status_file))
    status_file.write_text(
        json.dumps(
            {
                "status": "degraded",
                "ready": False,
                "completed": True,
                "started_at": "2026-08-06T12:00:00Z",
                "finished_at": "2026-08-06T12:00:03Z",
                "failure_count": 1,
                "failures": [
                    {
                        "phase": "seed",
                        "name": "seed_policies.py",
                        "reason": "exit 17: database unavailable",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    response = await client.get("/api/v1/runtime/preparation")

    assert response.status_code == 200
    assert response.json()["failure_count"] == 1
    assert response.json()["failures"][0]["name"] == "seed_policies.py"

    status_file.unlink()
    response = await client.get("/api/v1/runtime/preparation")
    assert response.status_code == 200
    assert response.json() == {
        "status": "unknown",
        "ready": False,
        "completed": False,
        "started_at": None,
        "finished_at": None,
        "failure_count": 0,
        "failures": [],
    }


@pytest.mark.asyncio
async def test_health_contract_stays_public_and_runtime_status_stays_protected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "DEBUG", False)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/health")
        runtime_status = await client.get("/api/v1/runtime/preparation")

    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
    assert runtime_status.status_code == 401
