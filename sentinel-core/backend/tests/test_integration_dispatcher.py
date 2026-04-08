"""
Tests for the SENTINEL Integration Dispatcher (SIEM, SOAR, Ticketing, Webhooks).

Validates:
- Adapter registry and dispatcher routing
- CEF and LEEF format functions
- Individual adapter send() with mocked HTTP
- Webhook HMAC signatures
- Error handling when adapters fail
"""
import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from integrations.dispatcher import (
    ADAPTER_REGISTRY,
    IntegrationDispatcher,
    WebhookAdapter,
    SplunkHECAdapter,
    ElasticSIEMAdapter,
    XSOARAdapter,
    ServiceNowAdapter,
    JiraAdapter,
    format_cef,
    format_leef,
)


# ===================================================================
# Adapter Registry
# ===================================================================

class TestAdapterRegistry:
    def test_all_types_registered(self):
        expected = {"webhook", "siem_splunk", "siem_elastic",
                    "soar_xsoar", "ticketing_servicenow", "ticketing_jira"}
        assert set(ADAPTER_REGISTRY.keys()) == expected

    def test_registry_values_are_classes(self):
        for cls in ADAPTER_REGISTRY.values():
            assert hasattr(cls, "send")
            assert hasattr(cls, "test_connection")


# ===================================================================
# IntegrationDispatcher
# ===================================================================

class TestDispatcher:
    def test_register_known_type(self):
        d = IntegrationDispatcher()
        adapter = d.register({"type": "webhook", "name": "test-hook", "url": "http://x"})
        assert adapter is not None
        assert len(d.get_adapters()) == 1

    def test_register_unknown_type_returns_none(self):
        d = IntegrationDispatcher()
        adapter = d.register({"type": "unknown_type", "name": "bad"})
        assert adapter is None
        assert len(d.get_adapters()) == 0

    def test_dispatch_calls_all_adapters(self):
        d = IntegrationDispatcher()
        mock_a = MagicMock()
        mock_a.name = "a"
        mock_a.send.return_value = True
        mock_b = MagicMock()
        mock_b.name = "b"
        mock_b.send.return_value = False
        d._adapters = [mock_a, mock_b]

        event = {"type": "brute_force", "severity": "high"}
        results = d.dispatch(event)
        assert results == {"a": True, "b": False}
        mock_a.send.assert_called_once_with(event)
        mock_b.send.assert_called_once_with(event)

    def test_dispatch_handles_adapter_exception(self):
        d = IntegrationDispatcher()
        mock_a = MagicMock()
        mock_a.name = "exploder"
        mock_a.send.side_effect = RuntimeError("boom")
        d._adapters = [mock_a]

        results = d.dispatch({"type": "test"})
        assert results["exploder"] is False

    def test_get_adapters_format(self):
        d = IntegrationDispatcher()
        d.register({"type": "webhook", "name": "hook1", "url": "http://x"})
        adapters = d.get_adapters()
        assert len(adapters) == 1
        assert adapters[0]["name"] == "hook1"
        assert adapters[0]["type"] == "webhook"
        assert "config_keys" in adapters[0]

    def test_dispatch_empty(self):
        d = IntegrationDispatcher()
        assert d.dispatch({"type": "test"}) == {}


# ===================================================================
# WebhookAdapter
# ===================================================================

class TestWebhookAdapter:
    def test_send_success(self):
        adapter = WebhookAdapter({"name": "test", "type": "webhook", "url": "http://hook.test/ep"})
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            result = adapter.send({"type": "alert", "severity": "high"})
        assert result is True
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "http://hook.test/ep" in call_kwargs.args or call_kwargs.kwargs.get("url") == "http://hook.test/ep"

    def test_send_failure(self):
        adapter = WebhookAdapter({"name": "test", "type": "webhook", "url": "http://hook.test/ep"})
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.side_effect = ConnectionError("refused")
            result = adapter.send({"type": "test"})
        assert result is False

    def test_send_no_url_returns_false(self):
        adapter = WebhookAdapter({"name": "test", "type": "webhook"})
        assert adapter.send({"type": "test"}) is False

    def test_hmac_signature_added_with_secret(self):
        adapter = WebhookAdapter({
            "name": "signed",
            "type": "webhook",
            "url": "http://hook.test",
            "secret": "my-secret",
        })
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            adapter.send({"type": "test"})

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "X-Sentinel-Signature" in headers


# ===================================================================
# SplunkHECAdapter
# ===================================================================

class TestSplunkHECAdapter:
    def test_send_success(self):
        adapter = SplunkHECAdapter({
            "name": "splunk", "type": "siem_splunk",
            "hec_url": "https://splunk.test:8088/services/collector",
            "hec_token": "tok-123",
            "index": "main",
        })
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            result = adapter.send({"type": "alert"})
        assert result is True
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "Splunk tok-123" in headers.get("Authorization", "")

    def test_send_missing_config(self):
        adapter = SplunkHECAdapter({"name": "splunk", "type": "siem_splunk"})
        assert adapter.send({"type": "test"}) is False


# ===================================================================
# ElasticSIEMAdapter
# ===================================================================

class TestElasticSIEMAdapter:
    def test_send_success(self):
        adapter = ElasticSIEMAdapter({
            "name": "elastic", "type": "siem_elastic",
            "elastic_url": "https://elastic.test:9200",
            "api_key": "key-abc",
            "index": "sentinel-events",
        })
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=201)
            mock_post.return_value.raise_for_status = MagicMock()
            result = adapter.send({"type": "alert"})
        assert result is True
        url = mock_post.call_args.args[0] if mock_post.call_args.args else mock_post.call_args.kwargs.get("url", "")
        assert "sentinel-events/_doc" in str(url) or "sentinel-events/_doc" in str(mock_post.call_args)

    def test_send_missing_url(self):
        adapter = ElasticSIEMAdapter({"name": "elastic", "type": "siem_elastic"})
        assert adapter.send({"type": "test"}) is False


# ===================================================================
# XSOARAdapter
# ===================================================================

class TestXSOARAdapter:
    def test_send_success(self):
        adapter = XSOARAdapter({
            "name": "xsoar", "type": "soar_xsoar",
            "xsoar_url": "https://xsoar.test",
            "api_key": "xsoar-key",
        })
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=201)
            mock_post.return_value.raise_for_status = MagicMock()
            result = adapter.send({"type": "malware", "severity": "critical"})
        assert result is True

    def test_send_missing_config(self):
        adapter = XSOARAdapter({"name": "xsoar", "type": "soar_xsoar"})
        assert adapter.send({"type": "test"}) is False


# ===================================================================
# ServiceNowAdapter
# ===================================================================

class TestServiceNowAdapter:
    def test_send_success(self):
        adapter = ServiceNowAdapter({
            "name": "snow", "type": "ticketing_servicenow",
            "instance": "mycompany",
            "username": "admin",
            "password": "pass",
        })
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=201)
            mock_post.return_value.raise_for_status = MagicMock()
            result = adapter.send({"type": "alert", "severity": "high"})
        assert result is True
        url = str(mock_post.call_args)
        assert "mycompany.service-now.com" in url

    def test_send_missing_config(self):
        adapter = ServiceNowAdapter({"name": "snow", "type": "ticketing_servicenow"})
        assert adapter.send({"type": "test"}) is False


# ===================================================================
# JiraAdapter
# ===================================================================

class TestJiraAdapter:
    def test_send_success(self):
        adapter = JiraAdapter({
            "name": "jira", "type": "ticketing_jira",
            "jira_url": "https://myco.atlassian.net",
            "email": "bot@co.com",
            "api_token": "jira-tok",
            "project_key": "SEC",
        })
        with patch("integrations.dispatcher.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=201)
            mock_post.return_value.raise_for_status = MagicMock()
            result = adapter.send({"type": "alert", "severity": "critical"})
        assert result is True

    def test_send_missing_config(self):
        adapter = JiraAdapter({"name": "jira", "type": "ticketing_jira"})
        assert adapter.send({"type": "test"}) is False


# ===================================================================
# CEF Formatter
# ===================================================================

class TestFormatCEF:
    def test_basic_format(self):
        cef = format_cef({"type": "brute_force", "severity": "high", "description": "SSH brute"})
        assert cef.startswith("CEF:0|SENTINEL|SecurityPlatform|1.0|")
        assert "brute_force" in cef
        assert "|7|" in cef  # high -> 7

    def test_severity_mapping(self):
        for sev, expected in [("low", "3"), ("medium", "5"), ("high", "7"), ("critical", "10")]:
            cef = format_cef({"severity": sev})
            assert f"|{expected}|" in cef

    def test_extension_fields(self):
        cef = format_cef({
            "type": "scan",
            "severity": "medium",
            "source_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "description": "Port scan detected",
        })
        assert "src=10.0.0.1" in cef
        assert "dst=10.0.0.2" in cef
        assert "msg=Port scan detected" in cef

    def test_default_severity(self):
        cef = format_cef({"type": "unknown"})
        assert "|5|" in cef  # default medium -> 5

    def test_description_truncated(self):
        long_desc = "A" * 300
        cef = format_cef({"type": "test", "description": long_desc})
        # Description in the CEF header is truncated to 100
        # msg extension truncated to 200
        assert len(cef) < 500


# ===================================================================
# LEEF Formatter
# ===================================================================

class TestFormatLEEF:
    def test_basic_format(self):
        leef = format_leef({"type": "brute_force", "severity": "critical"})
        assert leef.startswith("LEEF:2.0|SENTINEL|SecurityPlatform|1.0|")
        assert "brute_force" in leef
        assert "sev=10" in leef

    def test_extension_fields(self):
        leef = format_leef({
            "type": "scan",
            "severity": "low",
            "source_ip": "192.168.1.1",
            "dest_ip": "192.168.1.2",
            "source_port": 12345,
            "dest_port": 443,
            "description": "TLS scan",
        })
        assert "src=192.168.1.1" in leef
        assert "dst=192.168.1.2" in leef
        assert "srcPort=12345" in leef
        assert "dstPort=443" in leef
        assert "msg=TLS scan" in leef

    def test_tab_separated_attributes(self):
        leef = format_leef({
            "type": "test",
            "severity": "medium",
            "source_ip": "1.2.3.4",
        })
        # After the header pipe-delimited section, attrs are tab-separated
        parts = leef.split("|")
        attr_section = parts[-1]
        assert "\t" in attr_section

    def test_default_severity(self):
        leef = format_leef({"type": "test"})
        assert "sev=5" in leef
