# MCP servers for SENTINEL

This project uses [Model Context Protocol](https://modelcontextprotocol.io) so Cursor (and other MCP clients) can call SENTINEL APIs, databases, and tools.

Config: **`.cursor/mcp.json`**. Restart Cursor after editing.

## Servers in use

| Server      | Purpose | Configure |
|------------|---------|-----------|
| **sentinel** | SENTINEL API (threats, alerts, policies, compliance, hardening) | Set `SENTINEL_API_URL` (default `http://localhost:8080`), optional `SENTINEL_API_TOKEN` (JWT). |
| **github** | Repo, issues, PRs, file read/write | Set `GITHUB_PERSONAL_ACCESS_TOKEN` in env. |
| **postgres** | Read-only DB queries and schema | Connection string in args; default points at local Postgres (port 5433). |
| **redis**   | Redis get/set/list/delete | Connection string in args; default `redis://localhost:6379`. |
| **filesystem** | Read/write project files | Root path in args; change to your workspace path if different. |

## First-time setup

1. **Sentinel server (Python)**  
   Install in the **backend venv** (Cursor uses that Python to run the sentinel MCP server). From repo root:
   ```bash
   sentinel-core/backend/.venv-backend/bin/pip install -r sentinel-core/mcp-servers/sentinel/requirements.txt
   ```
   If you're already in `sentinel-core/backend` with the venv activated:
   ```bash
   pip install -r ../mcp-servers/sentinel/requirements.txt
   ```
   If the venv doesn't exist yet: `python3 -m venv sentinel-core/backend/.venv-backend` (from repo root), then run the install above.

2. **Node servers (npx)**  
   GitHub, Postgres, Redis, Filesystem run via `npx -y @modelcontextprotocol/server-*`. No install needed; first run may download the package.

3. **Secrets**  
   In `.cursor/mcp.json`, set env for:
   - `GITHUB_PERSONAL_ACCESS_TOKEN` (for GitHub).
   - `SENTINEL_API_TOKEN` if your API gateway requires auth.

4. **Paths**  
   - `SENTINEL_API_URL`: where the API gateway is (e.g. `http://localhost:8080` with docker-compose).
   - Postgres/Redis connection strings: match your local or Docker ports.
   - Filesystem: set the path to your SENTINEL workspace (e.g. `/home/mir/sentinel`).

## Optional MCPs (not in mcp.json)

- **Terraform**: [hashicorp/terraform-mcp-server](https://github.com/hashicorp/terraform-mcp-server) — run as binary or Docker; set `TFE_TOKEN` / `TFE_ADDRESS` for Terraform Enterprise.
- **Kafka**: No official MCP server; use SENTINEL API or a custom MCP if you need topic/consumer tools.
- **Docker**: Community servers exist; add to `mcp.json` with `command`/`args` if needed.
- **Prometheus/Grafana**: Query via their HTTP APIs or a custom MCP.
