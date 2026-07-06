"""The default compose stack must be the lean offline node, not the v1 farm.

Production-pivot spec (2026-06-26): the node is five real moving parts —
collector, local bus (Redis streams), detector, analyst, policy/enforce —
plus store and console. Kafka/Flink and the out-of-MVP v1 services are
gated OFF the node path by config: they carry the ``full`` compose profile
and only start when explicitly requested (COMPOSE_PROFILES=full, used by
the e2e workflows that still exercise the legacy pipeline).
"""

import os

import yaml

_COMPOSE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.yml")
)

# The distributed pipeline + out-of-MVP v1 services (spec: "what dies /
# collapses for the node").
FULL_ONLY = {
    "zookeeper",
    "kafka",
    "flink-anomaly-detection",
    "flink-feature-extraction",
    "flink-drl-feed",
    "data-collector",
    "drl-engine",
    "elasticsearch",
    "kibana",
    "hids-agent",
    "hardening-service",
    "compliance-engine",
    "xai-service",
}

# The node spine + its store/console — must start with NO profile flags.
NODE_DEFAULT = {
    "postgres",
    "redis",
    "db-migrate",
    "auth-service",
    "api-gateway",
    "admin-console",
    "alert-service",
    "ai-engine",
    "policy-orchestrator",
    "enforcement-reaper",
    "node-collector",
    "node-consumer",
    "llm-gateway",
}


def _services():
    with open(_COMPOSE) as fh:
        return yaml.safe_load(fh)["services"]


def test_legacy_pipeline_is_gated_behind_the_full_profile():
    services = _services()
    for name in FULL_ONLY:
        profiles = services[name].get("profiles") or []
        assert "full" in profiles, f"{name} must carry the 'full' profile"


def test_node_spine_starts_by_default():
    services = _services()
    for name in NODE_DEFAULT:
        profiles = services[name].get("profiles") or []
        assert not profiles, f"{name} must not be profile-gated: {profiles}"


def test_default_services_do_not_depend_on_profiled_ones():
    """depends_on pointing at a profile-gated service makes the default
    `docker compose up` unresolvable — the lean node must come up clean."""
    services = _services()
    for name in NODE_DEFAULT:
        deps = services[name].get("depends_on") or {}
        deps = set(deps) if not isinstance(deps, str) else {deps}
        offenders = deps & FULL_ONLY
        assert not offenders, f"{name} depends on profiled services: {offenders}"
