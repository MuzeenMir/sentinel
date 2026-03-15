# SENTINEL – Troubleshooting

## Postgres container exits with code 3

**Symptom:** `✘ Container sentinel-postgres Error` and `dependency failed to start: container sentinel-postgres exited (3)`.

**Root cause (fixed in repo):** The init script required PostgreSQL extensions (`uuid-ossp`, `pg_trgm`) that are not reliably available in the Alpine image, causing the entrypoint to exit. The image is now `postgres:13` (Debian) and `init.sql` uses the built-in `gen_random_uuid()` so no extensions are required.

**If you still see exit 3** (e.g. after pulling the fix), do the following:

### 1. See why Postgres failed

```bash
cd /mnt/c/Users/MirMu/Projects/sentinel/sentinel-core
docker compose logs postgres
```

(or `docker logs sentinel-postgres`). The last lines usually show the real error (init script, permissions, or port).

### 2. Port 5432 already in use

If you run PostgreSQL (or another container) on the host, port 5432 may be in use and Postgres in Docker will fail.

- **Option A – Stop local Postgres**  
  Stop the service that uses 5432 (e.g. `sudo systemctl stop postgresql` or stop the other container).

- **Option B – Use another host port**  
  In `docker-compose.yml`, change the postgres port mapping from `"5432:5432"` to e.g. `"5433:5432"`.  
  Other services talk to Postgres via the Docker network (`postgres:5432`), so only the host port changes.  
  To connect from the host (e.g. with `psql`), use port 5433.

### 3. Volume / permissions (WSL or Docker Desktop)

After applying the init/image fix, **remove the old volume** so Postgres runs the updated init script on a fresh data dir:

```bash
docker compose --env-file sentinel_env down -v
docker compose --env-file sentinel_env up -d
```

`-v` removes named volumes (including `postgres_data`). If you still see exit 3, check the logs from step 1.

### 4. Init script errors

If the logs point to `init.sql` (e.g. syntax or “relation already exists”), fix or adjust that script. If the DB was half-initialized before a crash, removing the volume (step 3) and starting again often fixes it.

---

## After Postgres is running

Once `sentinel-postgres` stays up and healthy:

- Auth and API gateway depend on it and should start.
- Use: `docker compose --env-file sentinel_env up -d` and check with `docker compose ps`.
