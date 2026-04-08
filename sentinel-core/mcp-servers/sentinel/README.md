# SENTINEL MCP Server

Exposes SENTINEL API (threats, alerts, policies, compliance, config) as MCP tools for Cursor and other MCP clients.

## Setup

Install dependencies in the **backend venv** (Cursor runs the sentinel MCP server with that interpreter).

From **repo root** (`~/sentinel`):

```bash
sentinel-core/backend/.venv-backend/bin/pip install -r sentinel-core/mcp-servers/sentinel/requirements.txt
```

From **backend directory** (`sentinel-core/backend`) with venv already activated:

```bash
pip install -r ../mcp-servers/sentinel/requirements.txt
```

`.cursor/mcp.json` points the sentinel server at `sentinel-core/backend/.venv-backend/bin/python`, so no other env is used.

## Environment

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTINEL_API_URL` | API gateway base URL | `http://localhost:8080` |
| `SENTINEL_API_TOKEN` | JWT for authenticated API calls | (none) |

## Tools

- `get_health` — API gateway health
- `get_dashboard_stats` — Dashboard statistics
- `get_threats` — List threats (optional severity filter)
- `get_threat` — Get one threat by ID
- `get_alerts` — List alerts (optional status filter)
- `get_policies` — List firewall policies
- `get_compliance_frameworks` — List frameworks
- `run_compliance_assessment` — Run assessment for a framework
- `get_hardening_posture` — Hardening score (requires gateway proxy to hardening-service)
- `get_config` — System configuration

## Cursor

This server is referenced from `.cursor/mcp.json`. Restart Cursor after changing MCP config.
