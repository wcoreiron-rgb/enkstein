import importlib.util
from pathlib import Path


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
