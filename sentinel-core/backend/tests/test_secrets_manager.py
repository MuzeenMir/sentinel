"""Tests for SecretsManager backend-failure handling (SEC-10).

Covers the fall-back-to-env default and the SECRETS_STRICT fail-closed mode
that re-raises instead of silently degrading to environment variables.
"""

import logging

import pytest

from secrets_manager import SecretsManager


@pytest.fixture(autouse=True)
def _reset_singleton():
    SecretsManager._instance = None
    yield
    SecretsManager._instance = None


def _raise(_name):
    raise ConnectionError("backend unreachable")


def test_vault_failure_falls_back_to_env_by_default(monkeypatch, caplog):
    monkeypatch.setenv("DB_PASSWORD", "env-secret")
    mgr = SecretsManager(backend="vault")
    monkeypatch.setattr(mgr, "_fetch_vault", _raise)

    with caplog.at_level(logging.WARNING):
        value = mgr.get_secret("DB_PASSWORD")

    assert value == "env-secret"
    assert "Vault unavailable" in caplog.text


def test_vault_failure_raises_when_strict(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "env-secret")
    mgr = SecretsManager(backend="vault", strict=True)
    monkeypatch.setattr(mgr, "_fetch_vault", _raise)

    with pytest.raises(RuntimeError, match="vault"):
        mgr.get_secret("DB_PASSWORD")


def test_aws_failure_raises_when_strict(monkeypatch):
    monkeypatch.setenv("API_KEY", "env-secret")
    mgr = SecretsManager(backend="aws", strict=True)
    monkeypatch.setattr(mgr, "_fetch_aws", _raise)

    with pytest.raises(RuntimeError, match="aws"):
        mgr.get_secret("API_KEY")


def test_strict_mode_enabled_via_env(monkeypatch):
    monkeypatch.setenv("SECRETS_STRICT", "true")
    monkeypatch.setenv("API_KEY", "env-secret")
    mgr = SecretsManager(backend="aws")
    monkeypatch.setattr(mgr, "_fetch_aws", _raise)

    with pytest.raises(RuntimeError):
        mgr.get_secret("API_KEY")
