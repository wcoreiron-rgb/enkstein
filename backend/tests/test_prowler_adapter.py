from __future__ import annotations

import pytest
from sqlalchemy import select

from app.services.finding_pipeline import ingest_findings
from app.services.prowler import ProwlerError, _command, installation_status, normalize
from app.models.control import Control


def test_normalize_ocsf_finding_carries_control_and_origin():
    rows = normalize(
        [
            {
                "finding_info": {
                    "uid": "finding-1",
                    "title": "S3 bucket is public",
                    "desc": "Public access is enabled.",
                },
                "check_id": "s3_bucket_public_access",
                "severity": "High",
                "resources": [{"uid": "arn:aws:s3:::example"}],
                "remediation": {"desc": "Block public access."},
                "compliance": {"Requirements": ["CIS 2.1"]},
            }
        ],
        "aws",
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["control_id"] == "prowler:aws:s3_bucket_public_access"
    assert row["control_source"] == "prowler"
    assert row["data_origin"] == "live"
    assert row["source_connector"] == "prowler"
    assert row["resource_id"] == "arn:aws:s3:::example"
    assert row["severity"] == "high"


def test_normalize_asff_finding():
    rows = normalize(
        [
            {
                "Id": "asff-1",
                "Title": "Root access key exists",
                "Severity": {"Label": "CRITICAL"},
                "Resources": [{"Id": "arn:aws:iam::1:root"}],
                "GeneratorId": "iam_no_root_access_key",
                "Compliance": {"RelatedRequirements": ["AC-2"]},
            }
        ],
        "aws",
    )
    assert rows[0]["control_id"] == "prowler:aws:iam_no_root_access_key"
    assert rows[0]["severity"] == "critical"
    assert rows[0]["frameworks"] == {"prowler": ["AC-2"]}


def test_command_never_places_aws_secrets_in_argv():
    argv = _command(
        {
            "provider": "aws",
            "access_key_id": "AKIA-SECRET",
            "secret_access_key": "super-secret",
            "checks": ["iam_no_root_access_key"],
        },
        "/tmp/output",
    )
    assert "AKIA-SECRET" not in argv
    assert "super-secret" not in argv
    assert argv[-1] == "iam_no_root_access_key"


def test_command_rejects_unsupported_provider():
    with pytest.raises(ProwlerError, match="provider"):
        _command({"provider": "unknown"}, "/tmp/output")


def test_command_rejects_untrusted_executable():
    with pytest.raises(ProwlerError, match="executable"):
        _command({"provider": "aws", "executable": "/tmp/evil.sh"}, "/tmp/output")


def test_installation_status_is_safe_when_missing():
    status = installation_status("/tmp/prowler-not-installed")
    # Asserted by behaviour rather than exact shape: readiness must report
    # not-installed and must not leak a path or version for a missing binary.
    assert status["installed"] is False
    assert status["executable"] is None
    assert status.get("path") is None
    assert status.get("version") is None


@pytest.mark.asyncio
async def test_prowler_finding_materializes_control(db_session):
    rows = normalize(
        [{"CheckID": "iam_no_root_access_key", "Title": "Root key exists"}],
        "aws",
    )
    await ingest_findings(
        db_session,
        "cloudclaw",
        rows,
        run_policy_eval=False,
        run_alerts=False,
    )
    controls = (await db_session.execute(select(Control))).scalars().all()
    assert len(controls) == 1
    assert controls[0].control_id == "prowler:aws:iam_no_root_access_key"
    assert controls[0].source == "prowler"
