"""
AWS Provider Adapter
Connects to AWS Security Hub to pull findings.
Real call: GET https://securityhub.{region}.amazonaws.com/findings
Falls back to simulated findings when no credentials configured.
"""
import logging
from datetime import datetime
from typing import Optional

import httpx

from app.claws import credential_aliases, provenance

logger = logging.getLogger("cloudclaw.aws")

TIMEOUT = httpx.Timeout(30.0)


# ─── Simulated findings for demo when no real credentials ────────────────────

SIMULATED_FINDINGS = [
    {
        "title": "S3 Bucket Publicly Accessible",
        "description": (
            "S3 bucket 'prod-data-exports' has public access enabled. "
            "Any internet user can read objects without authentication."
        ),
        "category": "misconfiguration",
        "severity": "critical",
        "resource_id": "arn:aws:s3:::prod-data-exports",
        "resource_type": "s3_bucket",
        "resource_name": "prod-data-exports",
        "region": "us-east-1",
        "risk_score": 95.0,
        "remediation": (
            "Enable S3 Block Public Access at both the bucket and account level. "
            "Review and remove any bucket policies granting public read/write. "
            "Enable S3 server access logging."
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-SECURITYHUB-S3.2",
        "reference_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    },
    {
        "title": "Security Group Allows SSH from 0.0.0.0/0",
        "description": (
            "Security group 'sg-0abc1234' (launch-wizard-1) allows inbound SSH (port 22) "
            "from all IPv4 addresses (0.0.0.0/0). This exposes instances to brute-force attacks."
        ),
        "category": "misconfiguration",
        "severity": "high",
        "resource_id": "sg-0abc1234def567890",
        "resource_type": "security_group",
        "resource_name": "launch-wizard-1",
        "region": "us-east-1",
        "risk_score": 82.0,
        "remediation": (
            "Restrict SSH access to known IP ranges (VPN CIDR or bastion host IP). "
            "Consider using AWS Systems Manager Session Manager instead of SSH. "
            "Enable VPC Flow Logs to monitor connection attempts."
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-SECURITYHUB-EC2.13",
        "reference_url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
    },
    {
        "title": "RDS Instance Not Encrypted at Rest",
        "description": (
            "RDS instance 'prod-mysql-01' does not have storage encryption enabled. "
            "Database snapshots and logs are also unencrypted."
        ),
        "category": "misconfiguration",
        "severity": "high",
        "resource_id": "arn:aws:rds:us-east-1:123456789012:db:prod-mysql-01",
        "resource_type": "rds_instance",
        "resource_name": "prod-mysql-01",
        "region": "us-east-1",
        "risk_score": 78.0,
        "remediation": (
            "Enable encryption for new RDS instances at creation time using AWS KMS. "
            "For existing unencrypted instances: create an encrypted snapshot, "
            "restore a new encrypted instance from it, and update the connection string."
        ),
        "remediation_effort": "medium_term",
        "external_id": "AWS-SECURITYHUB-RDS.3",
        "reference_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
    },
    {
        "title": "IAM Root Account Has Active Access Keys",
        "description": (
            "The AWS root account has active programmatic access keys. "
            "Root keys have unrestricted access and cannot be scoped by IAM policies."
        ),
        "category": "misconfiguration",
        "severity": "critical",
        "resource_id": "arn:aws:iam::123456789012:root",
        "resource_type": "iam_user",
        "resource_name": "root",
        "region": "us-east-1",
        "risk_score": 98.0,
        "remediation": (
            "Delete all root account access keys immediately. "
            "Enable MFA on the root account. "
            "Use IAM users or roles with least-privilege policies for all programmatic access."
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-SECURITYHUB-IAM.4",
        "reference_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    },
    {
        "title": "CloudTrail Not Enabled in All Regions",
        "description": (
            "CloudTrail multi-region trail is not configured. "
            "API activity in us-west-2 and eu-west-1 is not being logged, "
            "creating blind spots for incident response."
        ),
        "category": "misconfiguration",
        "severity": "medium",
        "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/default",
        "resource_type": "cloudtrail",
        "resource_name": "default",
        "region": "us-east-1",
        "risk_score": 65.0,
        "remediation": (
            "Create a multi-region CloudTrail trail that logs to a dedicated S3 bucket. "
            "Enable log file validation and encrypt logs with KMS. "
            "Set up CloudWatch Alarms for unauthorized API calls."
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-SECURITYHUB-CloudTrail.2",
        "reference_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
    },
    {
        "title": "EC2 Instance Running with IMDSv1 Enabled",
        "description": (
            "Instance 'i-0abc123def456789' allows IMDSv1 requests, which are vulnerable "
            "to SSRF attacks that can steal IAM role credentials from the metadata service."
        ),
        "category": "misconfiguration",
        "severity": "medium",
        "resource_id": "i-0abc123def456789",
        "resource_type": "ec2_instance",
        "resource_name": "web-app-prod-01",
        "region": "us-west-2",
        "risk_score": 60.0,
        "remediation": (
            "Enforce IMDSv2 by setting HttpTokens=required on all EC2 instances. "
            "Use the AWS CLI: aws ec2 modify-instance-metadata-options "
            "--instance-id i-xxx --http-tokens required"
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-SECURITYHUB-EC2.8",
        "reference_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    },
    {
        "title": "Lambda Function Using Deprecated Runtime",
        "description": (
            "Lambda function 'data-processor' is using Python 3.8, which reached "
            "end-of-life and no longer receives security patches."
        ),
        "category": "vulnerability",
        "severity": "medium",
        "resource_id": "arn:aws:lambda:us-east-1:123456789012:function:data-processor",
        "resource_type": "lambda_function",
        "resource_name": "data-processor",
        "region": "us-east-1",
        "risk_score": 55.0,
        "remediation": (
            "Update the Lambda function runtime to Python 3.12 or later. "
            "Test the function with the new runtime in a staging environment before updating production."
        ),
        "remediation_effort": "medium_term",
        "external_id": "AWS-SECURITYHUB-Lambda.2",
        "reference_url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
    },
    {
        "title": "EBS Snapshot Publicly Shared",
        "description": (
            "EBS snapshot 'snap-0abc1234def567890' is shared publicly. "
            "Any AWS account can copy and access the data in this snapshot."
        ),
        "category": "exposure",
        "severity": "critical",
        "resource_id": "snap-0abc1234def567890",
        "resource_type": "ebs_snapshot",
        "resource_name": "prod-db-backup-20240115",
        "region": "us-east-1",
        "risk_score": 92.0,
        "remediation": (
            "Remove public sharing from the snapshot immediately. "
            "Review all EBS snapshots for unintended public sharing. "
            "Enable AWS Config rule 'ebs-snapshot-public-restorable-check'."
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-SECURITYHUB-EC2.1",
        "reference_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html",
    },
    {
        "title": "GuardDuty Finding: Cryptocurrency Mining Activity",
        "description": (
            "GuardDuty detected cryptocurrency mining activity from EC2 instance 'i-0xyz987'. "
            "The instance is communicating with known mining pool domains on port 3333."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "i-0xyz987abc123def",
        "resource_type": "ec2_instance",
        "resource_name": "batch-worker-03",
        "region": "us-west-2",
        "risk_score": 88.0,
        "actively_exploited": True,
        "remediation": (
            "Isolate the instance by moving it to a restricted security group. "
            "Capture a forensic snapshot before termination. "
            "Terminate the compromised instance and redeploy from a known-good AMI. "
            "Review IAM role attached to the instance for credential exposure."
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-GUARDDUTY-CryptoCurrency:EC2-BitcoinTool.B",
        "reference_url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_crypto.html",
    },
    {
        "title": "S3 Bucket Access Logging Disabled",
        "description": (
            "S3 bucket 'app-user-uploads' does not have server access logging enabled. "
            "Without logging, it is impossible to audit who accessed or modified objects."
        ),
        "category": "misconfiguration",
        "severity": "low",
        "resource_id": "arn:aws:s3:::app-user-uploads",
        "resource_type": "s3_bucket",
        "resource_name": "app-user-uploads",
        "region": "us-east-1",
        "risk_score": 35.0,
        "remediation": (
            "Enable S3 server access logging and send logs to a dedicated audit bucket. "
            "Consider enabling S3 Object-level CloudTrail events for sensitive buckets."
        ),
        "remediation_effort": "quick_win",
        "external_id": "AWS-SECURITYHUB-S3.9",
        "reference_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
    },
]


# ─── Real AWS Security Hub call ──────────────────────────────────────────────

async def _fetch_real_findings(credentials: dict) -> list[dict]:
    """
    Call AWS Security Hub GET /findings using the provided credentials.
    Expects credentials dict with keys: access_key_id, secret_access_key, region.

    AWS Security Hub requires request signing (AWS Signature Version 4).
    This implementation uses httpx with manual auth headers.
    For production, use boto3/aioboto3 with the SecurityHub client.
    """
    region = credentials.get("region", "us-east-1")
    url = f"https://securityhub.{region}.amazonaws.com/findings"

    # Construct a minimal filter for active findings
    body = {
        "Filters": {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        },
        "MaxResults": 100,
    }

    # Real AWS Security Hub calls require SigV4 request signing. Returning an
    # empty list here would be indistinguishable from "your account is clean",
    # so this raises instead: an operator who configured AWS credentials needs
    # to know the call was never made.
    raise NotImplementedError(
        "AWS Security Hub requires SigV4 signing (boto3/aioboto3), which is not "
        "installed. Configure AWS via Security Hub export to a supported "
        "connector until native signing is available."
    )


def _parse_security_hub_finding(raw: dict, account_id: str, region: str) -> dict:
    """Parse a raw AWS Security Hub finding into the universal Finding format."""
    severity_label = (
        raw.get("Severity", {}).get("Label", "MEDIUM").lower()
    )
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    }
    severity = severity_map.get(severity_label, "medium")

    resources = raw.get("Resources", [{}])
    resource = resources[0] if resources else {}

    # FindingProviderFields.Severity.Normalized is 0-100; divide by 10 for a 0-10 CVSS-like score.
    # Production should use aioboto3 SecurityHub client for native SigV4 signing; the current
    # httpx-based path works if AWS SigV4 headers are added manually.
    cvss_score = None
    normalized = raw.get("FindingProviderFields", {}).get("Severity", {}).get("Normalized")
    if normalized is not None:
        cvss_score = round(normalized / 10, 1)

    return {
        "claw": "cloudclaw",
        "provider": "aws",
        "title": raw.get("Title", "Unknown AWS Finding")[:512],
        "description": (raw.get("Description") or "")[:2000],
        "category": "misconfiguration",
        "severity": severity,
        "resource_id": resource.get("Id", "")[:512],
        "resource_type": resource.get("Type", "").lower().replace("/", "_")[:128],
        "resource_name": resource.get("Id", "").split(":")[-1][:255],
        "region": region,
        "account_id": account_id,
        "cvss_score": cvss_score,
        "risk_score": raw.get("Severity", {}).get("Normalized", 50.0),
        "actively_exploited": False,
        "status": "open",
        "external_id": raw.get("Id", "")[:256],
        "reference_url": (raw.get("SourceUrl") or "")[:512],
        "raw_data": str(raw)[:5000],
    }


# ─── Public entry point ───────────────────────────────────────────────────────

async def fetch_findings(credentials: dict) -> list[dict]:
    """Authenticated fetch that propagates failure to the caller."""
    credentials = credential_aliases.resolve("aws_security_hub", credentials)
    raw_findings = await _fetch_real_findings(credentials)
    region = credentials.get("region", "us-east-1")
    account_id = credentials.get("account_id", "unknown")
    return provenance.live(
        [_parse_security_hub_finding(f, account_id, region) for f in raw_findings],
        provider="aws",
        connector="aws_security_hub",
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    """
    Main entry point for the AWS adapter.
    If valid credentials are provided, attempts a real Security Hub call.
    Falls back to simulated findings for demo/dev environments.

    Returns a list of Finding-compatible dicts (ready to insert as Finding records).
    """
    if credentials:
        try:
            return await fetch_findings(credentials)
        except Exception as exc:
            logger.warning("AWS Security Hub call failed: %s — falling back to simulated findings", exc)

    # Return simulated findings enriched with required universal fields
    now = datetime.utcnow().isoformat()
    results = []
    for f in SIMULATED_FINDINGS:
        finding = {
            "claw": "cloudclaw",
            "provider": "aws",
            "category": f.get("category", "misconfiguration"),
            "actively_exploited": f.get("actively_exploited", False),
            "status": "open",
            "risk_score": f.get("risk_score", 50.0),
            **f,
        }
        results.append({**finding, "data_origin": provenance.SIMULATED})
    return results
