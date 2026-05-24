# SENTINEL Quick Start (v1.1.1)

Get a SENTINEL stack running on a dev machine in ~10 minutes. Two host paths covered: **Windows 11 (Docker Desktop + WSL2)** and **Ubuntu 24.04 LTS**.

Ubuntu 24 is the recommended target — XDP / eBPF / HIDS features that require a Linux kernel only work natively there. Windows 11 + Docker Desktop runs the rest of the stack fine; XDP collector is opt-in and stays in stub mode.

---

## Prerequisites (both OSes)

| Need | Version | Reason |
|---|---|---|
| Docker | 24.x+ | Container runtime |
| Docker Compose v2 | bundled with Docker | `docker compose up` not `docker-compose up` |
| RAM | **16 GB recommended** | ~20 services including Elasticsearch + Kafka |
| Disk | **10 GB free** | First-pull image set is ~3 GB; logs/data grow from there |
| Free local ports | 3000, 5601, 8080, 9092, 9200, 5432, 6379 | Adjust via `.env` overrides if you have conflicts |
| Git | any recent | `git clone https://github.com/MuzeenMir/sentinel.git` |

## Required environment variables

Every stack needs these 5 set in `.env`. The compose security validator (`scripts/validate_compose_security.py`, Phase 0 G3/G6) refuses to start if any are blank.

```env
POSTGRES_PASSWORD=<strong password>
JWT_SECRET_KEY=<64+ random chars; use `openssl rand -hex 32` or PowerShell `[Convert]::ToBase64String((1..32 | %% { [byte](Get-Random -Max 256) }))`>
ADMIN_PASSWORD=<strong password>
GRAFANA_PASSWORD=<strong password>
INTERNAL_SERVICE_TOKEN=<64+ random chars; same generator>
```

Copy from the template:

```
cp .env.example .env
```

Open `.env` and replace every `replace-with-...` placeholder. The platform will not start otherwise.

---

## Path 1: Windows 11

### Setup

1. Install **Docker Desktop for Windows** (4.x or later). It ships with the WSL2 backend already configured; accept the default.
2. In Docker Desktop → **Settings → Resources → Advanced**, bump memory to at least **12 GB** (default 8 GB will OOM-kill Elasticsearch and a few backend services).
3. Open PowerShell or Windows Terminal:

```powershell
git clone https://github.com/MuzeenMir/sentinel.git C:\Projects\sentinel
cd C:\Projects\sentinel\sentinel-core
copy .env.example .env
notepad .env       # fill in the 5 required vars (see above)
docker compose up -d
```

First boot takes ~3–5 minutes. Watch progress with:

```powershell
docker compose ps
docker compose logs -f api-gateway
```

### What works on Win11

✅ All 11 backend services
✅ React admin console
✅ Postgres + Redis + Kafka + Flink + Elasticsearch + Kibana
✅ Login, dashboards, alerts, policy decisions, audit log, compliance reports

### What's gated / limited on Win11

- **XDP collector kernel-attach does not work.** XDP needs native Linux kernel access. WSL2's `hv_netvsc` virtual NIC does not support XDP attach (see `sentinel-core/docs/xdp-bridge-network-verification.md`). The `xdp-collector` service is **opt-in via `--profile xdp`** and is not started by default. If you opt in, it runs in stub mode without real packet capture.
- **HIDS agent monitors its container, not your Windows host.** Useful for testing the detection pipeline; not a real HIDS deployment.

### Win11 access URLs

| Service | URL |
|---|---|
| Admin console | http://localhost:3000 |
| API gateway | http://localhost:8080 |
| API docs (Swagger) | http://localhost:8080/docs |
| Kibana (logs) | http://localhost:5601 |

Sign in to the admin console with `ADMIN_USERNAME` (defaults to `admin`) and the `ADMIN_PASSWORD` you set in `.env`.

---

## Path 2: Ubuntu 24.04 LTS (recommended)

### Setup

1. Install Docker from the **official Docker apt repository** (not `apt install docker.io`, which lags and lacks the v2 compose plugin):

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker --version          # expect 27.x or newer
docker compose version    # expect v2.x
```

2. **Sysctl tweak for Elasticsearch** (one-time):

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-sentinel.conf
```

3. Clone, configure, run:

```bash
git clone https://github.com/MuzeenMir/sentinel.git ~/sentinel
cd ~/sentinel/sentinel-core
cp .env.example .env
${EDITOR:-nano} .env       # fill in the 5 required vars
docker compose up -d
```

First boot ~3 minutes.

### What works on Ubuntu 24 that doesn't on Win11

- **XDP kernel-attach** — kernel 6.8+ ships with BTF info, native XDP, eBPF skeletons. T-004 ("verify `xdp_loaded:true` + Kafka flow egress") can complete on Ubuntu with a supported NIC. Check first:

  ```bash
  sudo apt install bpftool linux-tools-generic
  bpftool feature probe | grep -i xdp
  ip -d link show <your-nic>      # look for XDP capability
  ```

  Common consumer NICs (Realtek r8169, Intel e1000e/i225) support native XDP. **VirtIO / Hyper-V virt NICs only support SKB/generic mode**, which xdp-collector explicitly rejects. **WiFi (iwlwifi) is unsupported** by XDP entirely. Use bare-metal Ubuntu with a wired NIC for real XDP testing.

- **Container `cap_add` semantics are honest.** The Phase 0 G6 hardening (`PRIVILEGED_ALLOWED` allowlist in `scripts/validate_compose_security.py`, minimal `cap_add` for data-collector and hids-agent) maps 1:1 to kernel privileges here — making this the right OS to verify the closure-review's outstanding "G6 runtime cap behavior unverified" carry-over.

### Ubuntu 24 gotchas

1. **AppArmor.** Ubuntu 24 ships with stricter default AppArmor profiles than 22.04. If containers fail with cryptic permission errors:

   ```bash
   sudo aa-status                  # see active profiles
   sudo journalctl -k | grep DENIED
   ```

   Add to the offending service in `docker-compose.yml`:
   ```yaml
   security_opt:
     - apparmor=unconfined
   ```

2. **Cgroups v2 only.** Ubuntu 24 dropped cgroups v1. Docker handles this fine, but old sysadmin docs that write to `/sys/fs/cgroup/cpu/...` paths are wrong — the correct path is `/sys/fs/cgroup/...` directly.

3. **`systemd-resolved` on 127.0.0.53.** Conflicts with anything binding `127.0.0.1:53`. SENTINEL doesn't bind 53; mentioned here in case you're adding services.

### Ubuntu 24 access URLs

Same as Win11 — all on `localhost`.

---

## Smoke test (both OSes)

After `docker compose up -d`, wait ~3 minutes for everything to come online, then:

```bash
# 1. All services up and healthy
docker compose ps

# 2. API gateway answers /health
curl -s http://localhost:8080/health
# Expect: {"status":"healthy"}

# 3. Swagger UI renders
curl -s http://localhost:8080/docs | head -5
# Expect: HTML containing "Swagger UI"

# 4. Database has the Phase 0 schema
docker compose exec postgres psql -U sentinel -d sentinel \
  -c "SELECT relname FROM pg_class WHERE relkind='r' AND relnamespace=2200 ORDER BY relname LIMIT 10"
# Expect: audit_log, baseline_hashes, compliance_assessments, ebpf_programs,
#         hardening_posture, hids_events, host_events, mfa_challenges, ...

# 5. sentinel_app PG role exists and is locked down (T-014c)
docker compose exec postgres psql -U sentinel -d sentinel -c "\du sentinel_app"
# Expect: Role "sentinel_app" with attributes "Cannot login" and "No bypass RLS"

# 6. RLS policies enabled on tenant-scoped tables (T-014c)
docker compose exec postgres psql -U sentinel -d sentinel \
  -c "SELECT relname FROM pg_class WHERE relrowsecurity = true ORDER BY relname"
# Expect: audit_log, compliance_assessments, mfa_challenges, policy_decisions,
#         users, xai_explanations, ...
```

If steps 2 + 3 + 4 + 5 + 6 all return cleanly, your SENTINEL v1.1.1 is alive and Phase 0 closure is verified locally.

### Browser walk-through (after smoke passes)

1. Open http://localhost:3000.
2. Log in with `admin` / your `ADMIN_PASSWORD`.
3. **Dashboard** — should show 0 alerts initially.
4. **Tenants** — at least one row (`default` tenant inserted by `20260313_001` migration).
5. **Audit log** — every action you just took should appear with an `INSERT` row.
6. **Policy editor** — create a test policy, save, confirm it appears in `policy_decisions` table.

If all six work end-to-end you have a working dev-grade SENTINEL.

---

## Common failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `services failed to start: validate_compose_security.py exited 1` | An env var in `.env` still has the `replace-with-...` placeholder | Fill in all 5 required vars |
| `auth-service` keeps restarting; logs say `connection refused (postgres)` | `db-migrate` hasn't completed yet | Wait ~30 s; if persists, check `docker compose logs db-migrate` for migration failure |
| `elasticsearch` exits with `vm.max_map_count too low` | Ubuntu sysctl tweak missing | See Ubuntu 24 → Setup → step 2 |
| `Cannot connect to the Docker daemon` | User not in `docker` group (Ubuntu) | `sudo usermod -aG docker $USER && newgrp docker` |
| Admin console at :3000 returns 502 | Vite dev server still building | Wait 60 s; check `docker compose logs admin-console` |
| `xdp-collector` errors with `XDP attach failed` | Running default profile but XDP isn't actually opted in OR you opted in on Win11/unsupported NIC | XDP is `--profile xdp` only; skip unless on Ubuntu bare-metal with a wired NIC |
| `db-migrate` fails with `relation "users" does not exist` | You're on a stale image cache from before v1.1.1 | `docker compose down -v && docker compose pull && docker compose up -d` |

---

## Teardown

```bash
docker compose down          # stop services, keep volumes (preserves DB data)
docker compose down -v       # nuke everything including volumes (fresh start)
```

`down -v` is the right move between testing sessions to avoid stale state. Postgres data, Elasticsearch indices, Kafka topics — all wiped, all rebuilt clean on next `up -d`.

---

## Where to go next

- **Closure review:** `sentinel-core/docs/reviews/phase-0-critical-fixes.md` — what Phase 0 actually delivered and what's deferred to Phase 1.
- **Architecture:** `sentinel-core/docs/ARCHITECTURE-DESIGN-DEVELOPMENT.md`.
- **API reference:** http://localhost:8080/docs (live Swagger UI after compose up).
- **CLAUDE.md** at repo root: hard constraints, Phase status, "do not" list. Read before opening a ticket.
- **TASKS.md** at the meta-folder root: active and recently-closed work.

---

## Phase 0 status note

This QUICKSTART covers **v1.1.1**, the post-Phase-0 release (2026-05-23). Every smoke-test command above passes on `main`. The 7-day green clock for Phase 0 exit runs **2026-05-23 → 2026-05-30**; assuming `main` stays green, Phase 1 work begins after that window.

Phase 1 carry-overs that affect dev/test setup:
- **T-028** — runtime `sentinel_app` `SET ROLE` per request. Until this lands, the platform connects as the migration superuser; RLS isolation is *architecturally* in place but not *runtime-enforced*. Doesn't affect functional testing of v1.1.1 features.
- **T-021** — xdp-collector multi-stage Dockerfile. Currently single-stage, ships clang/llvm/bpftool to the runtime image; works fine for dev, but the image is larger than it should be in production.
