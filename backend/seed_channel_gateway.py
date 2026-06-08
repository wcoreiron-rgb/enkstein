"""
Seed ChannelConfig and ChannelIdentity with realistic demo data.
ChannelMessage is intentionally excluded — those are runtime records.
Records are upserted (skipped if already present) so the script is idempotent.

Run: python seed_channel_gateway.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime

from app.database import SessionLocal, engine, Base
from app.models.channel_gateway import ChannelConfig, ChannelIdentity

Base.metadata.create_all(bind=engine)

# ──────────────────────────────────────────────────────────────────────────────
# ChannelConfig records
# ──────────────────────────────────────────────────────────────────────────────
CHANNEL_CONFIGS = [
    {
        "id": "cfg-slack-soc-001",
        "channel_type": "slack",
        "channel_id": "C0SOC0MAIN1",
        "channel_name": "#soc-alerts",
        "webhook_url": "https://hooks.slack.com/services/T00000001/B00000001/placeholder_soc_alerts",
        "bot_token": "xoxb-placeholder-soc-alerts-token",
        "signing_secret": "placeholder_signing_secret_soc_001",
        "is_enabled": True,
        "require_approval": True,
        "allowed_roles": ["analyst", "engineer", "admin"],
        "created_at": datetime(2026, 1, 15, 9, 0, 0),
    },
    {
        "id": "cfg-slack-threat-intel-002",
        "channel_type": "slack",
        "channel_id": "C0THREAT001",
        "channel_name": "#threat-intel",
        "webhook_url": "https://hooks.slack.com/services/T00000001/B00000002/placeholder_threat_intel",
        "bot_token": "xoxb-placeholder-threat-intel-token",
        "signing_secret": "placeholder_signing_secret_threat_002",
        "is_enabled": True,
        "require_approval": False,
        "allowed_roles": ["analyst", "engineer", "admin"],
        "created_at": datetime(2026, 1, 20, 10, 30, 0),
    },
    {
        "id": "cfg-teams-incident-003",
        "channel_type": "teams",
        "channel_id": "19:redacted_user2",
        "channel_name": "Incident Response",
        "webhook_url": "https://company.webhook.office.com/webhookb2/placeholder_incident_response",
        "bot_token": "placeholder-teams-bot-token-incident",
        "signing_secret": "placeholder_signing_secret_teams_003",
        "is_enabled": True,
        "require_approval": True,
        "allowed_roles": ["analyst", "engineer", "admin"],
        "created_at": datetime(2026, 2, 1, 8, 0, 0),
    },
    {
        "id": "cfg-teams-exec-brief-004",
        "channel_type": "teams",
        "channel_id": "19:redacted_exec_briefing",
        "channel_name": "Executive Security Briefing",
        "webhook_url": "https://company.webhook.office.com/webhookb2/placeholder_exec_briefing",
        "bot_token": "placeholder-teams-bot-token-exec",
        "signing_secret": "placeholder_signing_secret_teams_004",
        "is_enabled": True,
        "require_approval": True,
        "allowed_roles": ["admin"],
        "created_at": datetime(2026, 2, 15, 14, 0, 0),
    },
    {
        "id": "cfg-slack-compliance-005",
        "channel_type": "slack",
        "channel_id": "C0COMPLY001",
        "channel_name": "#compliance-ops",
        "webhook_url": "https://hooks.slack.com/services/T00000001/B00000005/placeholder_compliance",
        "bot_token": "xoxb-placeholder-compliance-token",
        "signing_secret": "placeholder_signing_secret_compliance_005",
        "is_enabled": False,
        "require_approval": True,
        "allowed_roles": ["analyst", "admin"],
        "created_at": datetime(2026, 3, 1, 11, 0, 0),
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# ChannelIdentity records
# ──────────────────────────────────────────────────────────────────────────────
CHANNEL_IDENTITIES = [
    {
        "channel_type": "slack",
        "platform_user_id": "U0ALICE0001",
        "platform_email": "redacted_user",
        "platform_name": "Alice Chen",
        "regentclaw_role": "admin",
        "is_trusted": True,
        "trust_score": 95,
        "allowed_claws": [],
        "denied_claws": [],
        "max_autonomy": "autonomous",
        "last_seen": datetime(2026, 5, 3, 8, 42, 0),
        "created_at": datetime(2026, 1, 15, 9, 5, 0),
    },
    {
        "channel_type": "slack",
        "platform_user_id": "U0BOB00002",
        "platform_email": "redacted_user",
        "platform_name": "Bob Martinez",
        "regentclaw_role": "engineer",
        "is_trusted": True,
        "trust_score": 82,
        "allowed_claws": ["endpointclaw", "netclaw", "cloudclaw"],
        "denied_claws": [],
        "max_autonomy": "approval",
        "last_seen": datetime(2026, 5, 3, 7, 15, 0),
        "created_at": datetime(2026, 1, 15, 9, 10, 0),
    },
    {
        "channel_type": "teams",
        "platform_user_id": "29:1alice-teams-aad-object-id",
        "platform_email": "redacted_user",
        "platform_name": "Alice Chen",
        "regentclaw_role": "admin",
        "is_trusted": True,
        "trust_score": 95,
        "allowed_claws": [],
        "denied_claws": [],
        "max_autonomy": "autonomous",
        "last_seen": datetime(2026, 5, 2, 16, 30, 0),
        "created_at": datetime(2026, 2, 1, 8, 15, 0),
    },
    {
        "channel_type": "slack",
        "platform_user_id": "U0CAROL0003",
        "platform_email": "redacted_user",
        "platform_name": "Carol Singh",
        "regentclaw_role": "analyst",
        "is_trusted": True,
        "trust_score": 78,
        "allowed_claws": ["identityclaw", "accessclaw", "complianceclaw"],
        "denied_claws": ["endpointclaw"],
        "max_autonomy": "assist",
        "last_seen": datetime(2026, 5, 3, 6, 50, 0),
        "created_at": datetime(2026, 1, 22, 10, 0, 0),
    },
    {
        "channel_type": "slack",
        "platform_user_id": "U0EVE00005",
        "platform_email": "redacted_user",
        "platform_name": "Eve (Contractor)",
        "regentclaw_role": "readonly",
        "is_trusted": False,
        "trust_score": 35,
        "allowed_claws": ["accessclaw"],
        "denied_claws": ["cloudclaw", "dataclaw", "endpointclaw", "threatclaw"],
        "max_autonomy": "monitor",
        "last_seen": datetime(2026, 5, 3, 4, 12, 0),
        "created_at": datetime(2026, 3, 10, 14, 0, 0),
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Main seeder
# ──────────────────────────────────────────────────────────────────────────────
def seed():
    db = SessionLocal()
    seeded_configs = 0
    seeded_identities = 0

    try:
        # ── ChannelConfig ──────────────────────────────────────────────────────
        for cfg in CHANNEL_CONFIGS:
            existing = db.query(ChannelConfig).filter(ChannelConfig.id == cfg["id"]).first()
            if not existing:
                existing = db.query(ChannelConfig).filter(ChannelConfig.channel_id == cfg["channel_id"]).first()
            if not existing:
                record = ChannelConfig(**cfg)
                db.add(record)
                print(f"  + ChannelConfig: {cfg['channel_name']} ({cfg['channel_type']})")
                seeded_configs += 1
            else:
                print(f"  – ChannelConfig (exists): {cfg['channel_name']}")

        # ── ChannelIdentity ────────────────────────────────────────────────────
        for identity in CHANNEL_IDENTITIES:
            existing = db.query(ChannelIdentity).filter(
                ChannelIdentity.platform_user_id == identity["platform_user_id"],
                ChannelIdentity.channel_type == identity["channel_type"],
            ).first()
            if not existing:
                record = ChannelIdentity(**identity)
                db.add(record)
                print(f"  + ChannelIdentity: {identity['platform_name']} @ {identity['channel_type']}")
                seeded_identities += 1
            else:
                print(f"  – ChannelIdentity (exists): {identity['platform_name']} @ {identity['channel_type']}")

        db.commit()
        print(
            f"\n✓ Seeded {seeded_configs} channel config(s) and "
            f"{seeded_identities} channel identity/identities."
        )

    finally:
        db.close()


if __name__ == "__main__":
    seed()
