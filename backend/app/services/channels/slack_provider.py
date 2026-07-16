"""
Enkstein — Slack Channel Provider

Outbound message delivery via Incoming Webhooks and inbound signature
verification for Slack Events API / slash commands.

References:
  https://api.slack.com/messaging/webhooks
  https://api.slack.com/authentication/verifying-requests-from-slack
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Slack rejects events older than this many seconds (replay-attack protection).
_MAX_TIMESTAMP_AGE_SECONDS = 300


async def send_message(
    webhook_url: str,
    text: str,
    blocks: list[dict[str, Any]] | None = None,
    thread_ts: str | None = None,
) -> bool:
    """
    Send a message to a Slack channel via an Incoming Webhook URL.

    Args:
        webhook_url: The Slack Incoming Webhook URL for the target channel.
        text:        Fallback plain-text content (shown in notifications / when
                     blocks cannot be rendered).
        blocks:      Optional list of Slack Block Kit block objects.
        thread_ts:   Optional Slack thread timestamp for threaded replies.

    Returns:
        True if Slack returned HTTP 200, False otherwise.
    """
    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    if thread_ts:
        payload["thread_ts"] = thread_ts

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 200 and resp.text == "ok":
                logger.debug("Slack message delivered to webhook (status 200)")
                return True
            logger.warning(
                "Slack webhook returned unexpected response: status=%s body=%r",
                resp.status_code,
                resp.text,
            )
            return False
    except httpx.HTTPError as exc:
        logger.error("Slack webhook HTTP error: %s", exc)
        return False


async def verify_signature(
    request_body: bytes,
    timestamp: str,
    signature: str,
    signing_secret: str,
) -> bool:
    """
    Verify that an inbound Slack request is genuine using HMAC-SHA256.

    Slack signs every request using the app's Signing Secret:
        sig_basestring = f"v0:{timestamp}:{body}"
        computed       = "v0=" + hmac.new(signing_secret, sig_basestring, sha256).hexdigest()

    Args:
        request_body:   Raw bytes of the HTTP request body.
        timestamp:      Value of the ``X-Slack-Request-Timestamp`` header.
        signature:      Value of the ``X-Slack-Signature`` header.
        signing_secret: The Slack app Signing Secret.

    Returns:
        True if the signature is valid and the request is not stale, False otherwise.
    """
    # Reject stale requests (replay attack protection)
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        logger.warning("Slack signature verification failed: invalid timestamp %r", timestamp)
        return False

    if abs(time.time() - ts) > _MAX_TIMESTAMP_AGE_SECONDS:
        logger.warning("Slack request timestamp is too old (%d seconds)", abs(time.time() - ts))
        return False

    sig_basestring = f"v0:{timestamp}:{request_body.decode('utf-8', errors='replace')}"
    computed_hash  = hmac.new(
        signing_secret.encode("utf-8"),
        sig_basestring.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    computed_sig = f"v0={computed_hash}"

    if hmac.compare_digest(computed_sig, signature):
        return True

    logger.warning("Slack HMAC verification failed — signature mismatch")
    return False
