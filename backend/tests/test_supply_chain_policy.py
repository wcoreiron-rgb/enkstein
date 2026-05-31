import importlib.util
from pathlib import Path
from datetime import date, timedelta


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "enforce_supply_chain_policy.py"
_SPEC = importlib.util.spec_from_file_location("enforce_supply_chain_policy", _SCRIPT_PATH)
assert _SPEC and _SPEC.loader
policy = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(policy)


def test_npm_vulnerability_counts_reads_metadata_shape():
    data = {
        "metadata": {
            "vulnerabilities": {
                "critical": 1,
                "high": 2,
                "moderate": 3,
                "low": 4,
            }
        }
    }
    assert policy.npm_vulnerability_counts(data) == {
        "critical": 1,
        "high": 2,
        "moderate": 3,
        "low": 4,
    }


def test_pip_audit_vulnerability_counts_defaults_unknown_to_high():
    data = [
        {"name": "a", "version": "1.0", "vulns": [{"id": "X"}]},
        {"name": "b", "version": "1.0", "vulns": [{"id": "Y", "severity": "medium"}]},
        {"name": "c", "version": "1.0", "vulns": [{"id": "Z", "severity": "low"}]},
    ]
    counts = policy.pip_audit_vulnerability_counts(data)
    assert counts["high"] == 1
    assert counts["moderate"] == 1
    assert counts["low"] == 1


def test_apply_waiver_reduces_effective_counts():
    current = {"critical": 1, "high": 5, "moderate": 3, "low": 1}
    waiver = {"critical": 0, "high": 2, "moderate": 10, "low": 0}
    assert policy.apply_waiver(current, waiver) == {
        "critical": 1,
        "high": 3,
        "moderate": 0,
        "low": 1,
    }


def test_active_waiver_counts_expire_automatically():
    expired = (date.today() - timedelta(days=1)).isoformat()
    baseline = {
        "waivers": {
            "pip_audit": {
                "expires_on": expired,
                "allowed_existing": {"critical": 9, "high": 9, "moderate": 9, "low": 9},
            }
        }
    }
    assert policy._active_waiver_counts(baseline, "pip_audit") == {
        "critical": 0,
        "high": 0,
        "moderate": 0,
        "low": 0,
    }
