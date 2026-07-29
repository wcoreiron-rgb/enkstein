"""Zero Trust control profile, evaluation, and remediation behaviour."""
from __future__ import annotations

import types
from datetime import datetime, timedelta

import pytest

from app.models.control import Control, ControlSource
from app.services import control_profiles as profiles
from app.services import control_collectors as collectors
from app.services import prowler_catalog
from app.services.control_evaluation import Verdict, verdict_for


def _control(**overrides):
    payload = {
        "control_id": "enkstein:identityclaw:identity-authentication",
        "source": ControlSource.AUTHORED.value,
        "title": "Require strong authentication",
        "zt_pillar": "identity",
        "claw": "identityclaw",
        "severity": "high",
        "evaluator_key": "identity.entra",
        "recommendation_only": False,
        "automated": True,
    }
    payload.update(overrides)
    return Control(**payload)


def _finding(status="open", origin="live", risk=90.0, age_days=0):
    return types.SimpleNamespace(
        id="00000000-0000-0000-0000-000000000001",
        status=status,
        severity="critical",
        risk_score=risk,
        data_origin=origin,
        last_seen=datetime.utcnow() - timedelta(days=age_days),
        claw="identityclaw",
    )


class TestVerdicts:
    def test_open_live_finding_fails_the_control(self):
        result = verdict_for(_control(), [_finding()], collector_ran=True)
        assert result["verdict"] == Verdict.FAIL.value

    def test_demonstration_data_never_fails_a_control(self):
        # Labelled demo findings explain an empty screen; they must not become
        # a compliance verdict.
        result = verdict_for(_control(), [_finding(origin="simulated")], collector_ran=True)
        assert result["verdict"] == Verdict.PASS.value

    def test_silence_without_a_collector_is_not_a_pass(self):
        result = verdict_for(_control(), [], collector_ran=False)
        assert result["verdict"] == Verdict.NOT_ASSESSED.value

    def test_control_without_evaluator_is_recommendation_only(self):
        result = verdict_for(_control(evaluator_key=None), [], collector_ran=True)
        assert result["verdict"] == Verdict.RECOMMENDATION.value

    def test_stale_evidence_downgrades_to_not_assessed(self):
        result = verdict_for(_control(), [_finding(status="resolved", age_days=90)], collector_ran=True)
        assert result["verdict"] == Verdict.NOT_ASSESSED.value

    def test_collector_that_ran_clean_passes(self):
        result = verdict_for(_control(), [_finding(status="resolved")], collector_ran=True)
        assert result["verdict"] == Verdict.PASS.value


class TestProfiles:
    def test_every_node_declares_its_nist_families(self):
        from app.core.zero_trust import NODE_DEFAULT_PILLAR

        missing = set(NODE_DEFAULT_PILLAR) - set(profiles.ARM_NIST_FAMILIES)
        assert not missing, f"Nodes without a control profile: {sorted(missing)}"

    def test_nist_controls_map_to_pillars_by_family(self):
        assert profiles.pillar_for_nist("ac-2") == "identity"
        assert profiles.pillar_for_nist("sc-7") == "networks"
        assert profiles.pillar_for_nist("au-12") == "visibility"
        assert profiles.pillar_for_nist("mp-3") == "data"

    def test_unknown_family_falls_back_to_governance(self):
        assert profiles.pillar_for_nist("zz-1") == "governance"

    def test_an_arm_only_inherits_families_it_claims(self):
        identity = _control(control_id="ac-2", source="nist_800_53", claw=None)
        physical = _control(control_id="pe-3", source="nist_800_53", claw=None)
        assert profiles.applies_to("identityclaw", identity) is True
        assert profiles.applies_to("identityclaw", physical) is False

    def test_profiles_are_not_one_undifferentiated_pool(self):
        # The regression this guards: every Arm claiming every control.
        assert profiles.families_for("identityclaw") != profiles.families_for("recoveryclaw")


class TestCollectors:
    def test_every_bound_evaluator_has_a_collector(self):
        unknown = {
            key for key in collectors.BASELINE_EVALUATORS.values()
            if key not in collectors.COLLECTORS
        }
        assert not unknown, f"Evaluators without a collector: {sorted(unknown)}"

    def test_collector_is_not_ready_without_its_connector(self):
        assert collectors.collector_ready("identity.entra", set()) is False
        assert collectors.collector_ready("identity.entra", {"entra_id"}) is True

    def test_local_collector_needs_no_connector(self):
        assert collectors.collector_ready("arcclaw.pattern", set()) is True

    def test_unknown_evaluator_is_never_ready(self):
        assert collectors.collector_ready("does.not.exist", {"entra_id"}) is False
        assert collectors.collector_ready(None, {"entra_id"}) is False

    def test_only_executable_actions_are_linked(self):
        from app.services.remediation.engine import (
            _HIGH_RISK_ACTIONS, _MEDIUM_RISK_ACTIONS, _LOW_RISK_ACTIONS,
        )

        known = _HIGH_RISK_ACTIONS | _MEDIUM_RISK_ACTIONS | _LOW_RISK_ACTIONS
        unknown = set(collectors.BASELINE_REMEDIATION.values()) - known
        assert not unknown, f"Controls linked to actions the engine cannot run: {sorted(unknown)}"


class TestProwlerCatalog:
    def test_check_metadata_becomes_a_control(self):
        record = {
            "CheckID": "s3_bucket_public_access",
            "CheckTitle": "S3 buckets block public access",
            "ServiceName": "s3",
            "Severity": "critical",
            "Description": "Checks public access block configuration.",
            "Categories": ["encryption"],
            "Remediation": {"Recommendation": {"Text": "Enable block public access.", "Url": "https://example.test"}},
        }
        control = prowler_catalog.to_controls("aws", [record], "5.36.0")[0]
        assert control["control_id"] == "prowler:aws:s3_bucket_public_access"
        assert control["source"] == ControlSource.PROWLER.value
        assert control["severity"] == "critical"
        assert control["evaluator_key"] == "prowler.aws"
        # Prowler observes posture; it does not change the tenant's cloud.
        assert control["remediation_action"] is None
        assert control["recommendation_only"] is True

    def test_category_decides_the_pillar_over_the_provider(self):
        record = {"CheckID": "c", "ServiceName": "s3", "Categories": ["identity-and-access-management"]}
        assert prowler_catalog.to_controls("aws", [record], "x")[0]["zt_pillar"] == "identity"

    def test_records_without_a_check_id_are_dropped(self):
        assert prowler_catalog.to_controls("aws", [{"CheckTitle": "no id"}], "x") == []

    def test_github_checks_belong_to_the_developer_node(self):
        record = {"CheckID": "branch_protection", "ServiceName": "repository"}
        assert prowler_catalog.to_controls("github", [record], "x")[0]["claw"] == "devclaw"

    @pytest.mark.parametrize("provider", prowler_catalog.CATALOG_PROVIDERS)
    def test_every_catalog_provider_is_supported_by_the_runner(self, provider):
        from app.services import prowler as runner

        assert provider in runner.SUPPORTED_PROVIDERS
