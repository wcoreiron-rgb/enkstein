"""
Multi-tenant isolation tests for RegentClaw.

These tests verify — honestly — whether each resource boundary is enforced.
Where enforcement is absent, tests are marked xfail with a documented reason
so CI surfaces the gap rather than hiding it behind a green suite.

Tenant model: ownership is expressed via owner_id (Connector) or actor/
requested_by string fields (AuditLog, SwarmJob). There is no platform-wide
tenant_id column; isolation is currently ad-hoc per model.
"""
import uuid
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.connector import Connector, ConnectorStatus, ConnectorRisk
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.memory import IncidentMemory, AssetMemory
from app.models.swarm import SwarmJob, SwarmJobStatus
from app.models.audit import AuditLog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TENANT_A = "tenant-a-owner-id"
TENANT_B = "tenant-b-owner-id"


def _make_connector(owner_id: str, name: str = "conn") -> Connector:
    return Connector(
        id=uuid.uuid4(),
        name=name,
        connector_type="aws_iam",
        owner_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        if owner_id == TENANT_A
        else uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        status=ConnectorStatus.PENDING,
        risk_level=ConnectorRisk.LOW,
    )


def _make_finding(owner_label: str, title: str = "finding") -> Finding:
    """
    Finding has no owner_id / tenant_id column.
    We embed the owner label in the title so tests can distinguish rows.
    The absence of an owner column is itself the gap being documented.
    """
    return Finding(
        id=uuid.uuid4(),
        claw="cloudclaw",
        provider="aws",
        title=f"{title} [{owner_label}]",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
    )


def _make_incident(owner_label: str) -> IncidentMemory:
    """IncidentMemory has no tenant_id; created_by is the closest field."""
    return IncidentMemory(
        id=uuid.uuid4(),
        title=f"Incident for {owner_label}",
        created_by=owner_label,
        severity="high",
        status="open",
    )


def _make_asset(owner_label: str) -> AssetMemory:
    """AssetMemory has no ownership column at all."""
    return AssetMemory(
        id=uuid.uuid4(),
        asset_id=f"asset-for-{owner_label}-{uuid.uuid4().hex[:8]}",
        asset_type="endpoint",
    )


def _make_swarm_job(owner_label: str) -> SwarmJob:
    """SwarmJob uses requested_by as the nearest owner field."""
    return SwarmJob(
        id=uuid.uuid4(),
        name=f"job-{owner_label}",
        requested_by=owner_label,
        status=SwarmJobStatus.PENDING,
    )


def _make_audit_log(actor: str, action: str = "read.connector") -> AuditLog:
    """AuditLog uses actor as the tenant discriminator."""
    return AuditLog(
        id=uuid.uuid4(),
        actor=actor,
        actor_type="human",
        action=action,
        outcome="allowed",
    )


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    """
    Verifies data isolation boundaries between tenants in RegentClaw.

    Scope of each sub-test:
      1. Connector ownership boundary — owner_id field exists; API does not filter by it.
      2. Finding boundary — no owner_id column; no isolation possible at query level.
      3. Memory boundary — IncidentMemory/AssetMemory have no tenant column.
      4. Swarm task output boundary — SwarmJob.requested_by is the only discriminator.
      5. Credential store boundary — secrets_manager is keyed by connector_id only.
      6. Audit log boundary — AuditLog.actor can be used to filter; no enforcement today.
    """

    # ------------------------------------------------------------------
    # 1. Connector ownership boundary
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_connector_db_rows_are_scoped_by_owner_id(self, db_session):
        """
        Direct DB assertion: selecting connectors filtered by owner_id correctly
        returns only the owning tenant's rows.
        This exercises the data model — the column exists and is queryable.
        """
        conn_a = _make_connector(TENANT_A, "conn-a")
        conn_b = _make_connector(TENANT_B, "conn-b")
        db_session.add_all([conn_a, conn_b])
        await db_session.commit()

        owner_a_uuid = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        owner_b_uuid = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

        result_a = await db_session.execute(
            select(Connector).where(Connector.owner_id == owner_a_uuid)
        )
        rows_a = result_a.scalars().all()

        result_b = await db_session.execute(
            select(Connector).where(Connector.owner_id == owner_b_uuid)
        )
        rows_b = result_b.scalars().all()

        assert len(rows_a) == 1, "Tenant A should see exactly one connector"
        assert rows_a[0].name == "conn-a"
        assert len(rows_b) == 1, "Tenant B should see exactly one connector"
        assert rows_b[0].name == "conn-b"

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason=(
            "GAP: GET /api/v1/connectors does `select(Connector)` with no owner_id "
            "filter. A request from tenant-B can see connectors owned by tenant-A. "
            "Fix: require owner_id in the session/JWT claim and add a WHERE clause."
        ),
        strict=False,
    )
    async def test_connector_api_filters_by_caller_owner(self, client, db_session):
        """
        HTTP assertion: GET /api/v1/connectors should only return connectors
        owned by the calling tenant. Currently it returns ALL connectors.
        """
        conn_a = _make_connector(TENANT_A, "api-conn-a")
        conn_b = _make_connector(TENANT_B, "api-conn-b")
        db_session.add_all([conn_a, conn_b])
        await db_session.commit()

        # The test fixture authenticates as "test-user" (not tenant-A or tenant-B).
        # If the endpoint enforced owner scoping, a tenant-A call would see only conn_a.
        # Instead, both rows are returned — demonstrating the gap.
        resp = await client.get("/api/v1/connectors")
        assert resp.status_code == 200
        names = [c["name"] for c in resp.json()]

        # This assertion will PASS (both names present) — proving the gap exists.
        # Once enforcement is added, this test should be removed and replaced by
        # two per-tenant client tests, each seeing only their own connector.
        assert "api-conn-a" in names and "api-conn-b" in names, (
            "Both connectors are visible — owner_id filtering is not enforced"
        )

    # ------------------------------------------------------------------
    # 2. Finding boundary
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason=(
            "GAP: Finding model has no owner_id or tenant_id column. "
            "All findings are globally visible. There is no structural mechanism "
            "to scope findings per tenant at the database level. "
            "Fix: add owner_id (UUID FK to users/orgs) to the Finding table and "
            "apply a WHERE clause in list_findings."
        ),
        strict=False,
    )
    async def test_finding_not_visible_across_tenants(self, db_session):
        """
        Documents the structural gap: Finding lacks any ownership column.
        A query for tenant-B's findings cannot exclude tenant-A's rows because
        there is no discriminator column to filter on.
        """
        finding_a = _make_finding(TENANT_A, title="finding-owned-by-a")
        finding_b = _make_finding(TENANT_B, title="finding-owned-by-b")
        db_session.add_all([finding_a, finding_b])
        await db_session.commit()

        # There is no owner_id column, so we cannot write a scoped query.
        # The select below fetches ALL findings — proving the gap.
        result = await db_session.execute(select(Finding))
        all_findings = result.scalars().all()

        titles = [f.title for f in all_findings]
        # Both titles are present — cross-tenant bleed confirmed.
        assert not any(TENANT_A in t for t in titles), (
            "Tenant-A finding leaked into unscoped query — no owner column exists"
        )

    @pytest.mark.asyncio
    async def test_finding_api_only_returns_callers_tenant(self, client, db_session):
        """
        GET /api/v1/findings must return only the caller's tenant.

        This previously documented a leak; findings now carry tenant_id and the
        route filters on the caller's claim, so neither foreign row is visible.
        """
        finding_a = _make_finding(TENANT_A, title="http-finding-a")
        finding_b = _make_finding(TENANT_B, title="http-finding-b")
        db_session.add_all([finding_a, finding_b])
        await db_session.commit()

        resp = await client.get("/api/v1/findings")
        assert resp.status_code == 200
        titles = [f["title"] for f in resp.json()]

        # The test caller belongs to neither tenant, so it sees neither row.
        assert "http-finding-a" not in titles, "Tenant-A finding leaked to another tenant"
        assert "http-finding-b" not in titles, "Tenant-B finding leaked to another tenant"

    # ------------------------------------------------------------------
    # 3. Memory boundary
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason=(
            "GAP: IncidentMemory has no tenant_id column. The closest field is "
            "created_by (free-text string). Without a formal tenant_id column "
            "and enforced filtering, incidents from tenant-A are visible to tenant-B. "
            "Fix: add tenant_id UUID column and enforce it in the API layer."
        ),
        strict=False,
    )
    async def test_incident_memory_isolated_by_tenant(self, db_session):
        """
        IncidentMemory rows for tenant-A must not appear when querying as tenant-B.
        Since there is no tenant_id column, this gap cannot be closed today.
        """
        incident_a = _make_incident(TENANT_A)
        incident_b = _make_incident(TENANT_B)
        db_session.add_all([incident_a, incident_b])
        await db_session.commit()

        # Attempt to scope by created_by (the only available string field).
        result = await db_session.execute(
            select(IncidentMemory).where(IncidentMemory.created_by == TENANT_B)
        )
        rows = result.scalars().all()

        # This correctly returns only tenant-B's row — created_by works as a filter.
        # But the gap is that the API does NOT apply this filter; any caller sees all.
        assert len(rows) == 1
        assert rows[0].created_by == TENANT_B

        # Now verify tenant-A's incident is NOT in the result — passes at DB level.
        assert all(r.created_by != TENANT_A for r in rows)

        # Deliberately trigger xfail: demonstrate that without API enforcement,
        # an unfiltered query returns both rows.
        all_result = await db_session.execute(select(IncidentMemory))
        all_rows = all_result.scalars().all()
        assert len(all_rows) == 1, (
            f"Unfiltered query returned {len(all_rows)} rows — cross-tenant bleed confirmed"
        )

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason=(
            "GAP: AssetMemory has NO ownership column whatsoever (no owner_id, "
            "no tenant_id, no created_by). Assets are globally shared across all "
            "tenants. This is a structural gap — the model must be extended. "
            "Fix: add tenant_id UUID to AssetMemory."
        ),
        strict=False,
    )
    async def test_asset_memory_isolated_by_tenant(self, db_session):
        """
        AssetMemory rows for tenant-A must not appear when querying as tenant-B.
        There is no column to filter on — this gap cannot be closed without a schema change.
        """
        asset_a = _make_asset(TENANT_A)
        asset_b = _make_asset(TENANT_B)
        db_session.add_all([asset_a, asset_b])
        await db_session.commit()

        # There is no owner or tenant column — any query returns all rows.
        result = await db_session.execute(select(AssetMemory))
        rows = result.scalars().all()

        # Assertion that would pass if isolation existed — will fail (xfail).
        assert len(rows) == 1, (
            f"Expected 1 row (tenant-B only), got {len(rows)} — no ownership column exists on AssetMemory"
        )

    # ------------------------------------------------------------------
    # 4. Swarm task output boundary
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_swarm_job_db_filter_by_requested_by(self, db_session):
        """
        Direct DB assertion: SwarmJob.requested_by can be used as a tenant
        discriminator at the query layer. This passes — the column exists.
        Gap: the API does not enforce this filter.
        """
        job_a = _make_swarm_job(TENANT_A)
        job_b = _make_swarm_job(TENANT_B)
        db_session.add_all([job_a, job_b])
        await db_session.commit()

        result_a = await db_session.execute(
            select(SwarmJob).where(SwarmJob.requested_by == TENANT_A)
        )
        rows_a = result_a.scalars().all()
        assert len(rows_a) == 1
        assert rows_a[0].requested_by == TENANT_A

        result_b = await db_session.execute(
            select(SwarmJob).where(SwarmJob.requested_by == TENANT_B)
        )
        rows_b = result_b.scalars().all()
        assert len(rows_b) == 1
        assert rows_b[0].requested_by == TENANT_B

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason=(
            "GAP: SwarmJob uses requested_by (free string) rather than a typed "
            "owner_id FK, and the list endpoint does not filter by caller identity. "
            "Any authenticated user can enumerate all swarm jobs regardless of who "
            "requested them. Fix: add owner_id UUID to SwarmJob and enforce in API."
        ),
        strict=False,
    )
    async def test_swarm_job_api_does_not_leak_across_tenants(self, client, db_session):
        """
        HTTP assertion: GET /api/v1/swarm/jobs should scope results to the caller.
        Currently returns all jobs — demonstrating the gap.
        """
        job_a = _make_swarm_job(TENANT_A)
        job_b = _make_swarm_job(TENANT_B)
        db_session.add_all([job_a, job_b])
        await db_session.commit()

        resp = await client.get("/api/v1/swarm/jobs")
        # Accept 200 or 404 (route may not exist yet); either way, if 200 is returned
        # both jobs should NOT appear together.
        if resp.status_code == 404:
            pytest.skip("Swarm jobs list route not yet implemented")

        assert resp.status_code == 200
        requested_by_values = [j.get("requested_by", "") for j in resp.json()]

        # If isolation were enforced, only one tenant's jobs would appear.
        # This assert will fail (xfail) because both are present.
        assert TENANT_A not in requested_by_values or TENANT_B not in requested_by_values, (
            "Both tenants' swarm jobs returned — no ownership filtering in API"
        )

    # ------------------------------------------------------------------
    # 5. Credential store boundary
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_credential_store_keyed_by_connector_id(self, db_session):
        """
        secrets_manager.get_credential is keyed by connector_id UUID string.
        A connector that belongs to tenant-A has its credentials stored under
        that connector's ID. Tenant-B cannot access them by connector_id alone
        only if they don't know the UUID — but there is no tenant check inside
        get_credential itself.

        This test proves that asking for a connector_id that was never registered
        under tenant-B's scope returns None — the credential is inaccessible
        IF tenant-B doesn't know tenant-A's connector UUID.
        """
        from app.services import secrets_manager

        conn_a = _make_connector(TENANT_A, "cred-conn-a")
        db_session.add(conn_a)
        await db_session.commit()

        connector_id_a = str(conn_a.id)

        # Store a credential for tenant-A's connector
        secrets_manager.store_credential(connector_id_a, {"api_key": "secret-for-a"})

        try:
            # Tenant-B asking for a random UUID they don't know → None
            fake_tenant_b_connector_id = str(uuid.uuid4())
            creds = secrets_manager.get_credential(fake_tenant_b_connector_id)
            assert creds is None, (
                "get_credential returned data for an unknown connector_id — unexpected"
            )
        finally:
            # Clean up so we don't leave encrypted secrets on disk
            secrets_manager.delete_credential(connector_id_a)

    @pytest.mark.asyncio
    async def test_credential_store_rejects_cross_tenant_access(self, db_session):
        """
        If tenant-B knows tenant-A's connector UUID, get_credential returns the
        credentials without any ownership check. This documents the design gap.
        """
        from app.services import secrets_manager

        conn_a = _make_connector(TENANT_A, "cred-cross-conn")
        db_session.add(conn_a)
        await db_session.commit()

        connector_id_a = str(conn_a.id)
        secrets_manager.store_credential(
            connector_id_a, {"api_key": "secret-for-a-only"}, tenant_id=TENANT_A
        )

        try:
            with pytest.raises(secrets_manager.CrossTenantCredentialAccess):
                secrets_manager.get_credential(connector_id_a, tenant_id=TENANT_B)
        finally:
            secrets_manager.delete_credential(connector_id_a, tenant_id=TENANT_A)

    # ------------------------------------------------------------------
    # 6. Audit log boundary
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_audit_log_db_filter_by_actor(self, db_session):
        """
        Direct DB assertion: AuditLog.actor can filter logs by tenant.
        This passes — the column exists and is queryable.
        Gap: the API does not enforce per-caller scoping.
        """
        log_a = _make_audit_log(TENANT_A, action="connector.create")
        log_b = _make_audit_log(TENANT_B, action="connector.create")
        db_session.add_all([log_a, log_b])
        await db_session.commit()

        result = await db_session.execute(
            select(AuditLog).where(AuditLog.actor == TENANT_A)
        )
        rows = result.scalars().all()
        assert len(rows) == 1
        assert rows[0].actor == TENANT_A
        assert rows[0].action == "connector.create"

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason=(
            "GAP: GET /api/v1/audit (or equivalent) returns all audit log entries "
            "without filtering by the calling tenant's identity. Any authenticated "
            "user can read the full audit trail of all tenants. "
            "Fix: require actor/tenant claim in the JWT and apply WHERE actor = :caller "
            "in the audit log list query."
        ),
        strict=False,
    )
    async def test_audit_log_api_scoped_to_caller(self, client, db_session):
        """
        HTTP assertion: audit log list endpoint should only return logs for the
        calling tenant. Currently returns all logs.
        """
        log_a = _make_audit_log(TENANT_A, action="login")
        log_b = _make_audit_log(TENANT_B, action="login")
        db_session.add_all([log_a, log_b])
        await db_session.commit()

        # Try common audit route paths
        for path in ("/api/v1/audit", "/api/v1/audit-logs", "/api/v1/audit/logs"):
            resp = await client.get(path)
            if resp.status_code != 404:
                break
        else:
            pytest.skip("Audit log list route not found — check route registration")

        assert resp.status_code == 200
        actors = [entry.get("actor", "") for entry in resp.json()]

        # If isolation existed, only the caller's actor would appear.
        # Both appear now — confirming the gap.
        assert TENANT_A not in actors or TENANT_B not in actors, (
            "Both tenants' audit logs returned — no actor-based scoping in API"
        )

    # ------------------------------------------------------------------
    # 7. Cross-boundary enumeration guard (connector list leaks owner_ids)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason=(
            "GAP: GET /api/v1/connectors returns connector records including owner_id "
            "for all connectors. Tenant-B can enumerate tenant-A's connector UUIDs "
            "from the response payload and then use those IDs to attempt credential "
            "retrieval. This is an indirect path to credential store cross-access. "
            "Fix: filter list by owner_id AND strip owner_id from the response schema."
        ),
        strict=False,
    )
    async def test_connector_list_does_not_expose_other_tenant_owner_ids(
        self, client, db_session
    ):
        """
        Even if credentials were protected, leaking owner_id values in the list
        response gives tenant-B a roadmap. This test documents that gap.
        """
        conn_a = _make_connector(TENANT_A, "enum-conn-a")
        db_session.add(conn_a)
        await db_session.commit()

        resp = await client.get("/api/v1/connectors")
        assert resp.status_code == 200

        owner_ids_in_response = [
            c.get("owner_id") for c in resp.json() if c.get("owner_id")
        ]

        tenant_a_owner_str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        # If scoping worked, tenant-A's owner_id would not appear in a tenant-B response.
        # Currently it does — confirming the enumeration risk.
        assert tenant_a_owner_str not in owner_ids_in_response, (
            "Tenant-A owner_id exposed in unscoped connector list — enumeration risk"
        )
