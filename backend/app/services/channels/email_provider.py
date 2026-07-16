"""
Enkstein — Email Channel Provider

Async SMTP email delivery using smtplib in a thread-pool executor so the
FastAPI event loop is never blocked.

Sends a multipart/alternative message with plain-text + optional HTML parts.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


def _send_email_sync(
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
    html_body: Optional[str],
) -> bool:
    """
    Blocking SMTP send — runs in a thread-pool executor.
    Uses STARTTLS when smtp_port is 587, plain SMTP for 25,
    and SMTP_SSL for 465.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)

    # Plain text part (always included as fallback)
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # HTML part (optional — preferred by email clients when present)
    if html_body:
        msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if smtp_port == 465:
            smtp_class = smtplib.SMTP_SSL
            use_starttls = False
        else:
            smtp_class = smtplib.SMTP
            use_starttls = smtp_port == 587

        with smtp_class(smtp_host, smtp_port, timeout=15) as server:
            if use_starttls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())

        logger.info("Email sent to %d recipient(s) via %s:%d", len(to_addrs), smtp_host, smtp_port)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed for %s@%s", username, smtp_host)
        return False
    except smtplib.SMTPRecipientsRefused:
        logger.error("SMTP rejected one or more recipients")
        return False
    except smtplib.SMTPException as exc:
        logger.error("SMTP error sending email: %s", exc)
        return False
    except OSError as exc:
        logger.error("Network error reaching %s:%d — %s", smtp_host, smtp_port, exc)
        return False


async def send_email(
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
    html_body: Optional[str] = None,
) -> bool:
    """
    Async wrapper — dispatches the blocking SMTP call to a thread-pool executor
    so the FastAPI event loop is not blocked during the SMTP handshake.

    Args:
        smtp_host:  SMTP server hostname (e.g. "smtp.gmail.com").
        smtp_port:  Port — 25 (plain), 465 (SSL), or 587 (STARTTLS).
        username:   SMTP auth username.
        password:   SMTP auth password or app-specific password.
        from_addr:  Sender address (e.g. "redacted_user").
        to_addrs:   List of recipient email addresses.
        subject:    Email subject line.
        body:       Plain-text body (always included).
        html_body:  Optional HTML body; clients prefer this when present.

    Returns:
        True on success, False on any SMTP or network error.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,  # Use the default ThreadPoolExecutor
        _send_email_sync,
        smtp_host,
        smtp_port,
        username,
        password,
        from_addr,
        to_addrs,
        subject,
        body,
        html_body,
    )
