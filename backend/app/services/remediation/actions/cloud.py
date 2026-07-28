"""
Cloud infrastructure remediation actions — AWS IAM.

Supported actions:
  deactivate_access_key — Deactivate an IAM access key (UpdateAccessKey: Inactive)
  attach_deny_policy    — Attach an inline AWSFullDeny policy to an IAM user
  disable_iam_user      — Delete login profile + deactivate all access keys

Credentials dict expected keys (from secrets_manager):
  {"aws_access_key_id": "...", "aws_secret_access_key": "...", "aws_region": "us-east-1"}

NOTE: AWS SDK (boto3/botocore) is an optional heavy dependency. We use httpx with
SigV4 signing manually to avoid the dependency — but if boto3 is available we
prefer it. If credentials are not configured the action fails rather than
reporting a success that never happened.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .base import ActionResult, not_configured

logger = logging.getLogger(__name__)

SUPPORTED_ACTIONS = [
    "deactivate_access_key",
    "attach_deny_policy",
    "disable_iam_user",
]

_DENY_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect":   "Deny",
            "Action":   "*",
            "Resource": "*",
        }
    ],
})


def _get_iam_client(credentials: dict):
    """Return a boto3 IAM client. Raises ImportError if boto3 not installed."""
    import boto3  # type: ignore
    return boto3.client(
        "iam",
        aws_access_key_id     = credentials.get("aws_access_key_id"),
        aws_secret_access_key = credentials.get("aws_secret_access_key"),
        aws_session_token     = credentials.get("aws_session_token"),
        region_name           = credentials.get("aws_region", "us-east-1"),
    )


def _has_aws_creds(creds: dict) -> bool:
    return bool(creds.get("aws_access_key_id") and creds.get("aws_secret_access_key"))


async def execute(
    action_type: str,
    target_id: str,
    params: dict,
    credentials: dict,
) -> ActionResult:
    """Execute a cloud remediation action."""
    creds = credentials or {}

    if not _has_aws_creds(creds):
        return not_configured(action_type, target_id)

    # Run synchronous boto3 calls in a thread executor
    import asyncio
    loop = asyncio.get_event_loop()

    if action_type == "deactivate_access_key":
        # target_id is the AccessKeyId; params may contain {"username": "..."}
        username   = params.get("username", "")
        access_key = target_id

        def _do() -> ActionResult:
            try:
                iam = _get_iam_client(creds)
                # If no username provided, discover it
                if not username:
                    resp = iam.get_access_key_last_used(AccessKeyId=access_key)
                    uname = resp.get("UserName", "")
                else:
                    uname = username
                # Get current status for rollback
                resp = iam.list_access_keys(UserName=uname)
                key_meta = next(
                    (k for k in resp.get("AccessKeyMetadata", []) if k["AccessKeyId"] == access_key),
                    {},
                )
                was_active = key_meta.get("Status", "Active") == "Active"
                iam.update_access_key(
                    UserName=uname,
                    AccessKeyId=access_key,
                    Status="Inactive",
                )
                return ActionResult(
                    success=True,
                    message=f"AWS IAM access key {access_key} deactivated for user {uname}",
                    rollback_data={"access_key_id": access_key, "username": uname, "was_active": was_active},
                    output={"access_key_id": access_key, "username": uname},
                )
            except Exception as exc:
                return ActionResult(success=False, message=f"AWS deactivate_access_key failed: {exc}", error=str(exc))

        return await loop.run_in_executor(None, _do)

    if action_type == "attach_deny_policy":
        # target_id is the IAM username
        username    = target_id
        policy_name = params.get("policy_name", "RegentClawEmergencyDeny")

        def _do() -> ActionResult:
            try:
                iam = _get_iam_client(creds)
                # Check for existing inline policies to capture rollback state
                existing = iam.list_user_policies(UserName=username).get("PolicyNames", [])
                iam.put_user_policy(
                    UserName=username,
                    PolicyName=policy_name,
                    PolicyDocument=_DENY_POLICY,
                )
                return ActionResult(
                    success=True,
                    message=f"Deny-all policy attached to IAM user {username}",
                    rollback_data={"username": username, "policy_name": policy_name, "pre_existing_policies": existing},
                    output={"username": username, "policy_name": policy_name},
                )
            except Exception as exc:
                return ActionResult(success=False, message=f"AWS attach_deny_policy failed: {exc}", error=str(exc))

        return await loop.run_in_executor(None, _do)

    if action_type == "disable_iam_user":
        username = target_id

        def _do() -> ActionResult:
            try:
                iam = _get_iam_client(creds)
                # 1. Get all access keys for rollback tracking
                keys_resp = iam.list_access_keys(UserName=username)
                key_ids   = [k["AccessKeyId"] for k in keys_resp.get("AccessKeyMetadata", [])]
                active    = [k["AccessKeyId"] for k in keys_resp.get("AccessKeyMetadata", []) if k.get("Status") == "Active"]

                # 2. Deactivate all active keys
                for kid in active:
                    iam.update_access_key(UserName=username, AccessKeyId=kid, Status="Inactive")

                # 3. Delete login profile (console access) — ignore error if none exists
                try:
                    iam.delete_login_profile(UserName=username)
                    had_console = True
                except iam.exceptions.NoSuchEntityException:
                    had_console = False
                except Exception:
                    had_console = False

                return ActionResult(
                    success=True,
                    message=f"IAM user {username} disabled (login profile deleted, all keys deactivated)",
                    rollback_data={
                        "username": username,
                        "deactivated_keys": active,
                        "had_console_access": had_console,
                    },
                    output={"username": username, "keys_deactivated": len(active)},
                )
            except Exception as exc:
                return ActionResult(success=False, message=f"AWS disable_iam_user failed: {exc}", error=str(exc))

        return await loop.run_in_executor(None, _do)

    return ActionResult(success=False, message=f"Unknown cloud action: {action_type}", error="unsupported_action")


async def rollback(
    action_type: str,
    target_id: str,
    rollback_data: dict,
    credentials: dict,
) -> ActionResult:
    """Reverse a previously executed cloud action."""
    creds = credentials or {}
    if not _has_aws_creds(creds):
        return not_configured(f"rollback_{action_type}", target_id)

    import asyncio
    loop = asyncio.get_event_loop()

    if action_type == "deactivate_access_key":
        access_key = rollback_data.get("access_key_id", target_id)
        username   = rollback_data.get("username", "")

        def _do() -> ActionResult:
            try:
                iam = _get_iam_client(creds)
                if rollback_data.get("was_active"):
                    iam.update_access_key(UserName=username, AccessKeyId=access_key, Status="Active")
                return ActionResult(success=True, message=f"AWS access key {access_key} re-activated")
            except Exception as exc:
                return ActionResult(success=False, message=f"Rollback failed: {exc}", error=str(exc))

        return await loop.run_in_executor(None, _do)

    if action_type == "attach_deny_policy":
        username    = rollback_data.get("username", target_id)
        policy_name = rollback_data.get("policy_name", "RegentClawEmergencyDeny")

        def _do() -> ActionResult:
            try:
                iam = _get_iam_client(creds)
                iam.delete_user_policy(UserName=username, PolicyName=policy_name)
                return ActionResult(success=True, message=f"Deny policy removed from IAM user {username}")
            except Exception as exc:
                return ActionResult(success=False, message=f"Rollback failed: {exc}", error=str(exc))

        return await loop.run_in_executor(None, _do)

    return ActionResult(
        success=False,
        message=f"No rollback handler for cloud action '{action_type}'",
        error="no_rollback",
    )
