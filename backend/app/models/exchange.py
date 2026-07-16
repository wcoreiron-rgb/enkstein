"""
Enkstein — Security Exchange models
Signed marketplace for skills, policies, and playbooks.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, JSON
from app.database import Base


class ExchangePublisher(Base):
    """Verified publisher on the Security Exchange."""
    __tablename__ = "exchange_publishers"

    id            = Column(String, primary_key=True)
    name          = Column(String, nullable=False)
    slug          = Column(String, unique=True, nullable=False, index=True)
    description   = Column(Text, default="")
    website       = Column(String, default="")
    logo_url      = Column(String, default="")
    tier          = Column(String, default="community")    # official|verified|community
    is_verified   = Column(Boolean, default=False)
    public_key    = Column(Text, default="")               # PEM public key stub
    pgp_fingerprint = Column(String, default="")
    total_packages  = Column(Integer, default=0)
    avg_trust_score = Column(Float, default=0.0)
    created_at    = Column(DateTime, default=datetime.utcnow)


class ExchangePackage(Base):
    """A signed package on the Security Exchange (skill, policy, playbook)."""
    __tablename__ = "exchange_packages"

    id              = Column(String, primary_key=True)
    publisher_id    = Column(String, nullable=False, index=True)
    publisher_name  = Column(String, nullable=False)
    name            = Column(String, nullable=False)
    slug            = Column(String, unique=True, nullable=False, index=True)
    package_type    = Column(String, nullable=False)  # skill_pack|policy_pack|playbook|connector
    category        = Column(String, default="General")
    tags            = Column(JSON, default=list)
    description     = Column(Text, default="")
    long_description = Column(Text, default="")
    version         = Column(String, default="1.0.0")
    min_platform    = Column(String, default="0.1.0")
    license_type    = Column(String, default="MIT")
    homepage        = Column(String, default="")
    source_url      = Column(String, default="")
    changelog       = Column(Text, default="")

    # Signature & verification
    sha256_checksum = Column(String, default="")
    pgp_signature   = Column(Text, default="")
    is_signed       = Column(Boolean, default=False)
    signature_verified = Column(Boolean, default=False)

    # Trust & ratings
    trust_score     = Column(Float, default=75.0)
    download_count  = Column(Integer, default=0)
    rating          = Column(Float, default=0.0)
    rating_count    = Column(Integer, default=0)
    is_featured     = Column(Boolean, default=False)
    is_official     = Column(Boolean, default=False)
    is_deprecated   = Column(Boolean, default=False)

    # Manifest payload
    manifest_json   = Column(JSON, default=dict)

    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ExchangeInstallRecord(Base):
    """Tracks what packages have been installed from the Exchange."""
    __tablename__ = "exchange_installs"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    package_id      = Column(String, nullable=False, index=True)
    package_name    = Column(String, nullable=False)
    package_type    = Column(String, nullable=False)
    installed_by    = Column(String, default="platform_admin")
    installed_at    = Column(DateTime, default=datetime.utcnow)
    version         = Column(String, default="1.0.0")
    status          = Column(String, default="installed")   # installed|failed|uninstalled
