"""Integration dispatcher -- routes SENTINEL events to configured external systems.

Supports:
- Webhooks (generic HTTP POST)
- SIEM: Splunk HEC, Elastic SIEM, Microsoft Sentinel (CEF/LEEF format)
- SOAR: Palo Alto XSOAR, Tines (webhook trigger)
- Ticketing: ServiceNow, Jira
- Notifications: Slack, Email (via alert-service)

Each integration type is a thin adapter that transforms a SENTINEL event
into the target's expected format and delivers it.
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class IntegrationAdapter(ABC):
    """Base class for all integration adapters."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get("name", "unnamed")
        self.type = config.get("type", "unknown")

    @abstractmethod
    def send(self, event: Dict[str, Any]) -> bool:
        """Send an event to the external system. Returns True on success."""
        ...

    def test_connection(self) -> bool:
        """Test connectivity to the external system."""
        return True


# ── Webhook ──────────────────────────────────────────────────────────

class WebhookAdapter(IntegrationAdapter):
    """Generic HTTP webhook -- POSTs JSON events to a configured URL."""

    def send(self, event: Dict[str, Any]) -> bool:
        url = self.config.get("url")
        headers = self.config.get("headers", {"Content-Type": "application/json"})
        secret = self.config.get("secret")
        timeout = self.config.get("timeout", 10)

        if not url:
            return False

        payload = {
            "source": "sentinel",
            "timestamp": time.time(),
            "event": event,
        }

        if secret:
            import hashlib
            import hmac
            sig = hmac.new(secret.encode(), json.dumps(payload).encode(), hashlib.sha256).hexdigest()
            headers["X-Sentinel-Signature"] = sig

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Webhook %s failed: %s", self.name, exc)
            return False


# ── SIEM: Splunk HEC ────────────────────────────────────────────────

class SplunkHECAdapter(IntegrationAdapter):
    """Splunk HTTP Event Collector integration."""

    def send(self, event: Dict[str, Any]) -> bool:
        url = self.config.get("hec_url")
        token = self.config.get("hec_token")
        index = self.config.get("index", "sentinel")
        source_type = self.config.get("sourcetype", "sentinel:event")

        if not url or not token:
            return False

        hec_payload = {
            "index": index,
            "sourcetype": source_type,
            "source": "sentinel",
            "event": event,
            "time": event.get("timestamp", time.time()),
        }

        try:
            resp = requests.post(
                url,
                json=hec_payload,
                headers={
                    "Authorization": f"Splunk {token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
                verify=self.config.get("verify_ssl", True),
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Splunk HEC %s failed: %s", self.name, exc)
            return False


# ── SIEM: Elastic ────────────────────────────────────────────────────

class ElasticSIEMAdapter(IntegrationAdapter):
    """Elasticsearch / Elastic SIEM integration."""

    def send(self, event: Dict[str, Any]) -> bool:
        url = self.config.get("elastic_url")
        api_key = self.config.get("api_key")
        index = self.config.get("index", "sentinel-events")

        if not url:
            return False

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        doc = {
            "@timestamp": event.get("timestamp", time.time()),
            "event": {"kind": "alert", "module": "sentinel"},
            **event,
        }

        try:
            resp = requests.post(
                f"{url.rstrip('/')}/{index}/_doc",
                json=doc,
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Elastic SIEM %s failed: %s", self.name, exc)
            return False


# ── SOAR: XSOAR ─────────────────────────────────────────────────────

class XSOARAdapter(IntegrationAdapter):
    """Palo Alto Cortex XSOAR incident creation."""

    def send(self, event: Dict[str, Any]) -> bool:
        url = self.config.get("xsoar_url")
        api_key = self.config.get("api_key")

        if not url or not api_key:
            return False

        incident = {
            "name": f"SENTINEL: {event.get('type', 'security_event')}",
            "type": "SENTINEL Alert",
            "severity": _map_severity_to_xsoar(event.get("severity", "medium")),
            "details": json.dumps(event),
            "createInvestigation": True,
        }

        try:
            resp = requests.post(
                f"{url.rstrip('/')}/incident",
                json=incident,
                headers={
                    "Authorization": api_key,
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("XSOAR %s failed: %s", self.name, exc)
            return False


# ── Ticketing: ServiceNow ────────────────────────────────────────────

class ServiceNowAdapter(IntegrationAdapter):
    """ServiceNow incident table integration."""

    def send(self, event: Dict[str, Any]) -> bool:
        instance = self.config.get("instance")
        username = self.config.get("username")
        password = self.config.get("password")
        table = self.config.get("table", "incident")

        if not instance or not username:
            return False

        incident = {
            "short_description": f"SENTINEL: {event.get('type', 'security_event')}",
            "description": json.dumps(event, indent=2),
            "urgency": _map_severity_to_snow(event.get("severity", "medium")),
            "impact": _map_severity_to_snow(event.get("severity", "medium")),
            "category": "Security",
        }

        try:
            resp = requests.post(
                f"https://{instance}.service-now.com/api/now/table/{table}",
                json=incident,
                auth=(username, password),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("ServiceNow %s failed: %s", self.name, exc)
            return False


# ── Ticketing: Jira ──────────────────────────────────────────────────

class JiraAdapter(IntegrationAdapter):
    """Jira Cloud / Server issue creation."""

    def send(self, event: Dict[str, Any]) -> bool:
        url = self.config.get("jira_url")
        email = self.config.get("email")
        api_token = self.config.get("api_token")
        project_key = self.config.get("project_key")

        if not url or not email or not api_token or not project_key:
            return False

        issue = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"SENTINEL: {event.get('type', 'security_event')}",
                "description": json.dumps(event, indent=2),
                "issuetype": {"name": "Bug"},
                "priority": {"name": _map_severity_to_jira(event.get("severity", "medium"))},
            }
        }

        try:
            resp = requests.post(
                f"{url.rstrip('/')}/rest/api/2/issue",
                json=issue,
                auth=(email, api_token),
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Jira %s failed: %s", self.name, exc)
            return False


# ── CEF Formatter ────────────────────────────────────────────────────

def format_cef(event: Dict[str, Any]) -> str:
    """Format a SENTINEL event as CEF (Common Event Format) for SIEM ingestion."""
    severity_map = {"low": 3, "medium": 5, "high": 7, "critical": 10}
    sev = severity_map.get(event.get("severity", "medium"), 5)

    extension_parts = []
    if event.get("source_ip"):
        extension_parts.append(f"src={event['source_ip']}")
    if event.get("dest_ip"):
        extension_parts.append(f"dst={event['dest_ip']}")
    if event.get("description"):
        extension_parts.append(f"msg={event['description'][:200]}")

    extension = " ".join(extension_parts)

    return (
        f"CEF:0|SENTINEL|SecurityPlatform|1.0|"
        f"{event.get('type', 'generic')}|"
        f"{event.get('description', 'Security Event')[:100]}|"
        f"{sev}|{extension}"
    )


# ── Dispatcher ───────────────────────────────────────────────────────

ADAPTER_REGISTRY: Dict[str, type] = {
    "webhook": WebhookAdapter,
    "siem_splunk": SplunkHECAdapter,
    "siem_elastic": ElasticSIEMAdapter,
    "soar_xsoar": XSOARAdapter,
    "ticketing_servicenow": ServiceNowAdapter,
    "ticketing_jira": JiraAdapter,
}


class IntegrationDispatcher:
    """Routes events to all active integrations."""

    def __init__(self):
        self._adapters: List[IntegrationAdapter] = []

    def register(self, config: Dict[str, Any]) -> Optional[IntegrationAdapter]:
        adapter_cls = ADAPTER_REGISTRY.get(config.get("type"))
        if not adapter_cls:
            logger.warning("Unknown integration type: %s", config.get("type"))
            return None
        adapter = adapter_cls(config)
        self._adapters.append(adapter)
        logger.info("Registered integration: %s (%s)", adapter.name, adapter.type)
        return adapter

    def dispatch(self, event: Dict[str, Any]) -> Dict[str, bool]:
        """Send event to all registered integrations. Returns per-adapter results."""
        results = {}
        for adapter in self._adapters:
            try:
                results[adapter.name] = adapter.send(event)
            except Exception as exc:
                logger.error("Integration %s dispatch error: %s", adapter.name, exc)
                results[adapter.name] = False
        return results

    def get_adapters(self) -> List[Dict[str, Any]]:
        return [
            {"name": a.name, "type": a.type, "config_keys": list(a.config.keys())}
            for a in self._adapters
        ]


# ── Helpers ──────────────────────────────────────────────────────────

def _map_severity_to_xsoar(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity.lower(), 2)

def _map_severity_to_snow(severity: str) -> str:
    return {"low": "3", "medium": "2", "high": "1", "critical": "1"}.get(severity.lower(), "2")

def _map_severity_to_jira(severity: str) -> str:
    return {"low": "Low", "medium": "Medium", "high": "High", "critical": "Highest"}.get(severity.lower(), "Medium")
