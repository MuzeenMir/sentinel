"""Adapter inverse operations are idempotent for rollback retries."""

import os
import subprocess
import sys

import pytest


BACKEND_DIR = os.path.dirname(os.path.dirname(__file__))
POLICY_ORCH_DIR = os.path.join(BACKEND_DIR, "policy-orchestrator")
for path in (BACKEND_DIR, POLICY_ORCH_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)


def test_policy_iptables_delete_missing_rule_is_success(monkeypatch):
    for key in list(sys.modules):
        if key == "vendors" or key.startswith("vendors."):
            del sys.modules[key]

    from vendors.iptables import IptablesAdapter

    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            1,
            args[0],
            stderr="Bad rule (does a matching rule exist in that chain?)",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = IptablesAdapter._execute(["iptables -D INPUT -s 10.0.0.5/32 -j DROP"])

    assert result["success"] is True
    assert result["idempotent_noop"] is True


@pytest.mark.parametrize(
    "adapter_path, class_name, attrs",
    [
        ("firewall_adapters.iptables_adapter", "IptablesAdapter", {}),
        ("firewall_adapters.nftables_adapter", "NftablesAdapter", {}),
        (
            "firewall_adapters.aws_sg_adapter",
            "AWSSecurityGroupAdapter",
            {"_client": object(), "security_group_id": "sg-123"},
        ),
        (
            "firewall_adapters.azure_nsg_adapter",
            "AzureNSGAdapter",
            {
                "_client": object(),
                "resource_group": "rg",
                "nsg_name": "nsg",
            },
        ),
        (
            "firewall_adapters.gcp_firewall_adapter",
            "GCPFirewallAdapter",
            {"_client": object(), "project_id": "proj"},
        ),
    ],
)
def test_shared_firewall_remove_missing_rule_is_idempotent_noop(
    adapter_path, class_name, attrs
):
    module = __import__(adapter_path, fromlist=[class_name])
    adapter_cls = getattr(module, class_name)
    adapter = adapter_cls.__new__(adapter_cls)
    adapter._rules_cache = {}
    for name, value in attrs.items():
        setattr(adapter, name, value)

    result = adapter.remove_rule("missing-rule")

    assert result["success"] is True
    assert result["idempotent_noop"] is True
