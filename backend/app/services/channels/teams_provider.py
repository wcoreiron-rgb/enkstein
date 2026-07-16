"""
Enkstein — Microsoft Teams Channel Provider

Sends alert messages to a Teams channel via an Incoming Webhook using the
legacy MessageCard schema (works without installing an app, using only a
channel connector).

Reference:
  https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


async def send_message(
    webhook_url: str,
    title: str,
    text: str,
    color: str = "#0078D4",
    actions: list[dict[str, Any]] | None = None,
    facts: list[dict[str, str]] | None = None,
) -> bool:
    """
    Send a formatted MessageCard to a Microsoft Teams channel webhook.

    Args:
        webhook_url:  The Teams Incoming Webhook URL (from channel connector).
        title:        Card title shown in bold at the top of the message.
        text:         Body text (supports Markdown subset accepted by Teams).
        color:        Accent colour for the card's left border (hex string).
                      Defaults to Microsoft blue (#0078D4).
                      Use "#D13438" for critical alerts, "#CA5010" for warnings.
        actions:      Optional MessageCard potentialAction list.
        facts:        Optional MessageCard facts rendered below the message body.

    Returns:
        True if Teams accepted the payload (HTTP 200 with body "1"), False otherwise.
    """
    payload: dict[str, Any] = {
        "@type":      "MessageCard",
        "@context":   "https://schema.org/extensions",
        "themeColor": color.lstrip("#"),   # Teams expects hex without leading '#'
        "summary":    title,
        "sections": [
            {
                "activityTitle": title,
                "activityText":  text,
                "markdown":      True,
                "facts":         facts or [],
            }
        ],
    }
    if actions:
        payload["potentialAction"] = actions

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            # Teams returns HTTP 200 with body "1" on success
            if resp.status_code == 200:
                logger.debug("Teams message delivered (status 200)")
                return True
            logger.warning(
                "Teams webhook returned unexpected response: status=%s body=%r",
                resp.status_code,
                resp.text,
            )
            return False
    except httpx.HTTPError as exc:
        logger.error("Teams webhook HTTP error: %s", exc)
        return False
