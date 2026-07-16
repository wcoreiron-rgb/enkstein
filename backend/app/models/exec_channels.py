"""
Enkstein — Governed Execution Channels models
Shell broker, browser sandbox, credential broker, and production gate.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, JSON, Float
from app.database import Base


class ExecRequest(Base):
    """
    A governed execution request — shell command, browser task, credential access,
    or production deployment gate.
    """
    __tablename__ = "exec_requests"

    id              = Column(String, primary_key=True)
    channel         = Column(String, nullable=False, index=True)  # shell|browser|credential|production
    requested_by    = Column(String, nullable=False, index=True)
    agent_id        = Column(String, default="", index=True)
    workflow_run_id = Column(String, default="", index=True)

    # Request details
    command         = Column(Text, default="")          # shell command or URL
    args            = Column(JSON, default=list)
    target_resource = Column(String, default="")        # hostname, URL, secret path
    environment     = Column(String, default="dev")     # dev|staging|prod
    justification   = Column(Text, default="")

    # Policy / trust
    trust_score     = Column(Float, default=0.0)
    risk_level      = Column(String, default="medium")  # low|medium|high|critical
    policy_decision = Column(String, default="pending") # allowed|blocked|requires_approval
    policy_flags    = Column(JSON, default=list)

    # Approval (for dual-approval production gate)
    requires_approval = Column(Boolean, default=False)
    approved_by_1     = Column(String, default="")
    approved_by_2     = Column(String, default="")
    approval_note     = Column(Text, default="")
    approval_count    = Column(Integer, default=0)

    # Execution result
    status          = Column(String, default="pending")  # pending|approved|running|completed|failed|blocked|expired
    exit_code       = Column(Integer, nullable=True)
    stdout          = Column(Text, default="")
    stderr          = Column(Text, default="")
    output_summary  = Column(Text, default="")
    duration_ms     = Column(Integer, default=0)
    credential_used = Column(String, default="")   # redacted secret path

    created_at      = Column(DateTime, default=datetime.utcnow)
    approved_at     = Column(DateTime, nullable=True)
    executed_at     = Column(DateTime, nullable=True)
    completed_at    = Column(DateTime, nullable=True)
    expires_at      = Column(DateTime, nullable=True)


class CredentialBrokerEntry(Base):
    """
    Registry of secrets that agents can request at runtime.
    Actual secret values are NOT stored here — only metadata.
    Values are fetched from the secrets manager at injection time.
    """
    __tablename__ = "credential_broker"

    id              = Column(String, primary_key=True)
    name            = Column(String, nullable=False, unique=True, index=True)
    description     = Column(Text, default="")
    secret_path     = Column(String, nullable=False)   # e.g. secrets/crowdstrike/api_key
    secret_type     = Column(String, default="api_key")  # api_key|password|token|certificate|ssh_key
    owner           = Column(String, default="platform")
    allowed_agents  = Column(JSON, default=list)       # empty = all
    allowed_claws   = Column(JSON, default=list)
    allowed_envs    = Column(JSON, default=list)       # ["dev", "staging"] — empty = all
    requires_approval = Column(Boolean, default=False)
    max_uses_per_hour = Column(Integer, default=0)     # 0 = unlimited
    use_count       = Column(Integer, default=0)
    last_used_at    = Column(DateTime, nullable=True)
    is_active       = Column(Boolean, default=True)
    rotation_due    = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)


class ProductionGate(Base):
    """
    Production execution gate — dual-approval workflow for production changes.
    """
    __tablename__ = "production_gates"

    id              = Column(String, primary_key=True)
    title           = Column(String, nullable=False)
    description     = Column(Text, default="")
    requested_by    = Column(String, nullable=False, index=True)
    agent_id        = Column(String, default="")
    workflow_run_id = Column(String, default="")

    change_type     = Column(String, default="config")   # config|deploy|secret|infra|firewall
    target_system   = Column(String, default="")
    change_payload  = Column(JSON, default=dict)
    rollback_plan   = Column(Text, default="")
    risk_assessment = Column(Text, default="")
    risk_level      = Column(String, default="high")

    # Approvals
    status              = Column(String, default="pending_approval")  # pending_approval|approved|rejected|executing|completed|rolled_back
    approvals_required  = Column(Integer, default=2)
    approvals_received  = Column(JSON, default=list)  # list of {approver, timestamp, note}
    rejected_by         = Column(String, default="")
    rejection_reason    = Column(Text, default="")

    # Execution
    executed_at     = Column(DateTime, nullable=True)
    completed_at    = Column(DateTime, nullable=True)
    execution_log   = Column(Text, default="")
    rolled_back_at  = Column(DateTime, nullable=True)

    created_at      = Column(DateTime, default=datetime.utcnow)
    expires_at      = Column(DateTime, nullable=True)
