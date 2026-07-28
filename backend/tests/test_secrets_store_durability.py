"""
The credential store must not lose credentials.

``_load_store`` swallowed every exception and returned ``{}``. Callers load,
mutate and save, so one unreadable read wrote an empty store back over a file
that still held every connector credential in the deployment -- silently
signing the operator out of everything with no error.
"""
from __future__ import annotations

import json

import pytest

from app.services import secrets_manager


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "connectors.json"
    monkeypatch.setattr(secrets_manager, "_SECRETS_DIR", tmp_path)
    monkeypatch.setattr(secrets_manager, "_SECRETS_FILE", path)
    return path


def test_unreadable_store_raises_instead_of_reporting_empty(store):
    store.write_text("{ this is not json")
    with pytest.raises(RuntimeError, match="could not be read"):
        secrets_manager._load_store()


def test_empty_write_over_populated_store_is_refused(store):
    store.write_text(json.dumps({"connector-a": {"token": "x"}}))
    with pytest.raises(RuntimeError, match="Refusing to overwrite"):
        secrets_manager._save_store({})
    # The original credentials survive the refused write.
    assert json.loads(store.read_text()) == {"connector-a": {"token": "x"}}


def test_empty_write_is_allowed_when_store_is_already_empty(store):
    secrets_manager._save_store({})
    assert json.loads(store.read_text()) == {}


def test_save_is_atomic_and_leaves_no_temporary_file(store):
    secrets_manager._save_store({"connector-a": {"token": "x"}})
    assert json.loads(store.read_text()) == {"connector-a": {"token": "x"}}
    assert not list(store.parent.glob("*.tmp"))


def test_deleting_the_last_credential_still_works(store):
    secrets_manager._save_store({"connector-a": {"token": "x"}})
    # A genuine delete down to zero is legitimate and must not be blocked by
    # the empty-write guard, so it goes through the delete path.
    secrets_manager.delete_credential("connector-a")
    assert json.loads(store.read_text()) == {}
