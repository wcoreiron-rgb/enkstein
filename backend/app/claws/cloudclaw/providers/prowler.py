"""Prowler local cloud posture adapter for Cloud Security."""

from app.services.prowler import fetch_findings, installation_status

__all__ = ["fetch_findings", "installation_status"]
