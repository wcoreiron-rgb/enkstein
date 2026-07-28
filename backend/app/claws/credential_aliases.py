"""
Reconcile connector form field names with the names adapters read.

The Configure form and the hand-written provider adapters were written at
different times and drifted apart. An operator would fill in "Okta Domain",
the form would store ``domain``, and the adapter would look for ``org_url``,
find nothing, and raise -- so a correctly configured connector reported a
credential failure. The declarative adapters never had this problem because
their required fields are declared in one place.

Rather than rename stored fields (which would break every connector already
configured) or edit each adapter's lookups (which would break anyone who had
worked around the mismatch), each adapter normalises its credentials through
``resolve`` first. Aliases are additive: an explicitly stored value always
wins, and a derived value only fills a gap.
"""
from __future__ import annotations

from typing import Callable, Optional


def _https(value: str) -> str:
    """Accept a bare hostname where a full URL is required."""
    value = value.strip().rstrip("/")
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


# target field -> ordered source fields, plus an optional transform.
_ALIASES: dict[str, dict[str, tuple[tuple[str, ...], Optional[Callable[[str], str]]]]] = {
    "okta": {
        "org_url": (("org_url", "domain", "base_url"), _https),
    },
    "splunk": {
        "base_url": (("base_url", "host", "endpoint"), _https),
    },
    "crowdstrike": {
        "base_url": (("base_url", "endpoint"), _https),
    },
    "gcp_iam": {
        "organization_id": (("organization_id", "org_id", "project_id"), None),
    },
    "gcp_scc": {
        "organization_id": (("organization_id", "org_id", "project_id"), None),
    },
    "aws_iam": {
        "account_id": (("account_id", "aws_account_id"), None),
    },
    "aws_security_hub": {
        "account_id": (("account_id", "aws_account_id"), None),
    },
}


def resolve(connector_type: str, credentials: dict) -> dict:
    """Return credentials with any aliased fields filled in."""
    rules = _ALIASES.get(connector_type)
    if not rules or not credentials:
        return dict(credentials or {})

    resolved = dict(credentials)
    for target, (sources, transform) in rules.items():
        if resolved.get(target):
            continue
        for source in sources:
            value = resolved.get(source)
            if value:
                resolved[target] = transform(str(value)) if transform else value
                break
    return resolved
