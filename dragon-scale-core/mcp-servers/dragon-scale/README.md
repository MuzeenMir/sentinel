# DRAGON_SCALE MCP Server

Exposes DRAGON_SCALE API (threats, alerts, policies, compliance, config) as MCP tools for Cursor and other MCP clients.

## Setup

Install dependencies in the **backend venv** (Cursor runs the dragon-scale MCP server with that interpreter).

From **repo root** (`~/dragon-scale`):

```bash
dragon-scale-core/backend/.venv-backend/bin/pip install -r dragon-scale-core/mcp-servers/dragon-scale/requirements.txt
```

From **backend directory** (`dragon-scale-core/backend`) with venv already activated:

```bash
pip install -r ../mcp-servers/dragon-scale/requirements.txt
```

`.cursor/mcp.json` points the dragon-scale server at `dragon-scale-core/backend/.venv-backend/bin/python`, so no other env is used.

## Environment

| Variable | Description | Default |
|----------|-------------|---------|
| `DRAGON_SCALE_API_URL` | API gateway base URL | `http://localhost:8080` |
| `DRAGON_SCALE_API_TOKEN` | JWT for authenticated API calls | (none) |

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
