# XDP Bridge-Network Verification

Date: 2026-05-17
Branch: `fix/xdp-bridge-network-verify`

## Summary

`xdp-collector` can run on the Compose bridge network without `network_mode: host`
for its userspace control plane. The service now defaults to Docker service DNS
for Kafka, auth-service, and Redis:

- `KAFKA_BOOTSTRAP_SERVERS=kafka:29092`
- `AUTH_SERVICE_URL=http://auth-service:5000`
- `REDIS_URL=redis://redis:6379`

`XDP_KAFKA_BOOTSTRAP_SERVERS` and `XDP_AUTH_SERVICE_URL` remain supported as
operator overrides, but they are no longer required for the normal bridge
profile path.

## Verification Performed

Host:

- WSL2 Linux 6.6.87.2, driver `hv_netvsc`
- Docker 29.4.0, Docker Compose v5.1.2
- `/sys/fs/bpf` present
- No passwordless sudo on host

Commands:

```bash
docker compose --profile xdp config xdp-collector
docker compose --profile xdp build xdp-collector
docker compose --profile xdp up -d xdp-collector
docker run --rm --network sentinel-core_sentinel-network curlimages/curl:8.8.0 \
  -fsS http://sentinel-xdp-collector:5012/health
docker exec sentinel-xdp-collector ip -details link show eth0
docker logs --tail 80 sentinel-xdp-collector
```

Observed:

- The rendered XDP service stays on `sentinel-network` and does not use host
  networking.
- `docker compose --profile xdp up -d xdp-collector` starts the collector and
  required Kafka/Redis/auth dependencies.
- A sibling container can reach `http://sentinel-xdp-collector:5012/health`.
- XDP initializes Kafka with `kafka:29092`.
- XDP initializes Redis with `redis://redis:6379`.

## Remaining Gap

Kernel attachment did not complete:

- `/health` returned `"xdp_loaded": false`.
- `ip -details link show eth0` showed no XDP program attached.
- Collector logs showed `xdp/xdp_flow` load failed because the object file was
  not found.

The current image copies `backend/ebpf-lib/` into `/app/ebpf_lib/`, but the repo
does not ship a compiled `compiled/xdp/xdp_flow.o` artifact and the Dockerfile
does not build one. Because no program is loaded, packet capture and Kafka flow
egress cannot be functionally verified yet.

## Supported Shape

Do not re-add `network_mode: host` for this issue. The verified bridge behavior
is correct for userspace dependencies. Full XDP support needs a compiled kernel
artifact path and live verification on a compatible host:

- Build `backend/ebpf-lib/compiled/xdp/xdp_flow.o` with `make xdp`. The
  `xdp-collector` image builds this object at `/app/ebpf_lib/compiled/xdp/xdp_flow.o`,
  which is the loader's default runtime path.
- If `SENTINEL_EBPF_SIGN_KEY` is configured, the loader requires a matching
  HMAC signature file beside the object. Without that key, loader signature
  verification is explicitly disabled for development mode. Kernel module
  signing does not sign eBPF ELF objects, but kernel lockdown or BPF policy can
  still reject BPF program loading on hardened hosts.
- Run on a host/NIC that supports XDP attachment.
- Re-run the bridge profile verification and confirm:
  - `/health` reports `"xdp_loaded": true`.
  - `ip -details link show <iface>` or `bpftool prog list` shows the XDP program.
  - generated traffic increments collector stats and produces Kafka events.
