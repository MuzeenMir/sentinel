# SENTINEL Disaster Recovery

This document outlines backup, restore, and failover procedures for SENTINEL.

## Scope

- PostgreSQL database (primary system of record)
- Redis (cache + session data)
- Model artifacts (AI engine models)
- Configuration state (API gateway config)

## Backups

### PostgreSQL

1. Create a backup:
```bash
pg_dump -Fc -h <db-host> -U sentinel -d sentinel_db > sentinel_db.dump
```

2. Store in offsite storage (S3 or equivalent) with encryption enabled.

### Redis

If persistence is enabled (AOF):

```bash
redis-cli -h <redis-host> --rdb redis_backup.rdb
```

### Models and artifacts

Back up `sentinel-core/backend/ai-engine/trained_models/` (or mounted volume).

### Config cache

Persisted in Redis under `sentinel:config`. Include Redis backup in DR.

## Restore

### PostgreSQL

```bash
pg_restore -h <db-host> -U sentinel -d sentinel_db sentinel_db.dump
```

### Redis

```bash
redis-cli -h <redis-host> --pipe < redis_backup.rdb
```

### Models

Restore the model directory to the same mount path as configured in AI engine.

## Verification Checklist

- API gateway `/health` returns healthy
- Auth service `/health` returns healthy
- Admin console loads dashboard
- AI engine can load models
- Alerts flow into alert service

## RTO / RPO Recommendations

- **RTO:** 2 hours or less
- **RPO:** 15 minutes or less

Adjust based on your regulatory requirements.
