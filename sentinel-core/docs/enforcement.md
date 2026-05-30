# Reversible Enforcement

SENTINEL enforcement actions are reversible by construction when
`USE_V2_REVERSIBLE_ENFORCEMENT=true`. A firewall or IPS apply records a durable
rollback contract in PostgreSQL with an `expires_at` timestamp. The default TTL
is 900 seconds, so an autonomous block or rate limit automatically expires after
15 minutes unless an admin confirms it as permanent.

## Operator Model

The policy orchestrator writes an `enforcement_actions` row for each successful
vendor apply. The row stores the policy id, vendor, original rules, apply
result, rollback state, and TTL. The reaper process scans expired active rows
with row locking and calls the adapter inverse operation, such as block to
unblock or rate-limit to clear.

Rollback states:

- `pending`: claimed or not yet active.
- `active`: applied and waiting for TTL expiry or admin confirmation.
- `reverted`: TTL expired and inverse operation succeeded.
- `confirmed`: an admin made the action permanent.
- `revert_failed`: inverse operation failed and is scheduled for retry.

## Configuration

Set these environment variables for the policy orchestrator and reaper:

```env
USE_V2_REVERSIBLE_ENFORCEMENT=true
ENFORCEMENT_DEFAULT_TTL_SECONDS=900
ENFORCEMENT_REAPER_INTERVAL_SECONDS=30
ENFORCEMENT_REAPER_BATCH_SIZE=100
```

`ENFORCEMENT_DEFAULT_TTL_SECONDS` controls the default apply-time TTL. Requests
may override it with `enforcement_ttl_seconds` or `ttl_seconds`; otherwise the
default is used.

## Confirm Permanent

Admins can confirm an enforcement action as permanent:

```http
POST /api/v1/enforcement-actions/{action_id}/confirm
Authorization: Bearer <admin-token>
```

Confirmation sets `confirmed_permanent=true`, clears `expires_at`, and moves the
row to `rollback_state='confirmed'`. The action is then ignored by the reaper.
Confirmation is audited with `audit_log()` like apply and revert events.

## Reaper Operations

Run the reaper as its own service:

```bash
docker compose up enforcement-reaper
```

The reaper uses `FOR UPDATE SKIP LOCKED`, so multiple instances can run without
processing the same action concurrently. Failed inverses move the row to
`revert_failed`, emit an alert log, and schedule retry with backoff instead of
crash-looping.

The safest operating posture is to leave the default TTL short, investigate the
event, and confirm permanent only after a human has checked blast radius.
