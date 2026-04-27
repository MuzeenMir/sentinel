# Sentinel — TODOs

Operational follow-ups not in the active design doc. Each entry has: What, Why, Pros, Cons, Context, Depends on. Sourced from `/plan-eng-review` 2026-04-25.

## Pre-v0.1 sprint

### T1: Archive v1+v2 Python codebase

- **What:** Create `archive/v1-python` branch from current main, push to origin. Then `git rm -r sentinel-core/` on main, commit, push. Add a 1-line README pointer to the archive branch.
- **Why:** P9 lock (one active project) requires clean main. Cruft = scope-mix temptation. The 18 months of v1 + v2 revamp docs are real work worth preserving in history, just not on main.
- **Pros:** Clean main, history preserved, future revisit possible via `git checkout archive/v1-python` if v0.2+ wants to mine v1 audit-service patterns or v2 LLM-gateway design.
- **Cons:** ~30min one-time effort. Forces commit-storm in git log.
- **Context:** Current `sentinel-core/` contains 11 Python microservices, Flask apps, Kafka, Flink jobs, React frontend, Terraform. Yesterday's AI Agent Sec design at `~/.gstack/projects/MuzeenMir-sentinel/dscorp-main-design-20260424-072705.md` is already separate from repo. Today's network-shield design at `~/.gstack/projects/MuzeenMir-sentinel/dscorp-main-design-20260425-191642.md`.
- **Depends on:** nothing.
- **When:** Day 0 spike, Saturday 2026-04-26, BEFORE Rust skeleton work begins.

## v0.1 sprint scope add

### T2: Quarterly Tranco baseline auto-refresh

- **What:** Add quarterly Tranco top-10k baseline refresh to threat-feed updater (`sentinel-core/src/feed/tranco.rs`). Background tokio task. Download to `tranco-baseline.txt.new`, atomic swap. Tray turns yellow if download fails 3 times.
- **Why:** Tranco list shifts over time (new popular sites appear, old ones decline). Allowlist baked at install would go stale over years of installed lifetime, causing legitimate-but-newer sites to potentially get false-positive-blocked by feed updates.
- **Pros:** Allowlist stays honest over years. ~300KB per quarter download. Near-zero CPU.
- **Cons:** ~30 LOC + 1 unit test. README mention.
- **Context:** Tranco list at https://tranco-list.eu/ updates daily; quarterly refresh is conservative + sufficient for the use case.
- **Depends on:** Threat-feed updater scaffold (week 1 of v0.1).
- **When:** Week 1 of v0.1 sprint, alongside threat-feed updater work.

## v0.2 sprint design pre-decision

### T3: VPN-conflict resolution policy = auto-pause + auto-resume

- **What:** Spec + design v0.2 VPN-conflict policy: tray polls per-adapter DNS every 30s. If any non-loopback adapter has DNS != 127.0.0.1, Sentinel enters "paused-by-VPN" state silently (yellow icon, no nag toast). When all adapters return to 127.0.0.1 or VPN drops, auto-resume. Surface state in tray right-click menu ("Paused while VPN active").
- **Why:** v0.1 punts with yellow icon + one-time alert toast. v0.2 must commit to a policy before sprint code starts so the design integrates cleanly. Auto-pause matches silent-defender principle (no nags), respects user intent (they chose to use the VPN), and accepts that most security-focused VPNs (Cloudflare WARP, corporate VPNs) do some level of DNS hygiene themselves.
- **Pros:** Zero nag pattern. Honest deferral to user-chosen VPN. Easy to implement (add state machine to tray, expose via IPC to service).
- **Cons:** Security regression while VPN active (no malware blocking from non-VPN-protected destinations). Document explicitly in SECURITY.md as known trade-off.
- **Context:** v0.3 packet-layer (WinDivert) sees all egress packets regardless of DNS resolver, so this trade-off is temporary — v0.3 catches what v0.2 misses.
- **Depends on:** v0.1 ship + tray-icon + named-pipe IPC working.
- **When:** Day 0 of v0.2 sprint, before VPN-detection code starts.

## v0.1 sprint quality gate (from /plan-design-review)

### Td-4: axe-core a11y CI check on block-page

- **What:** GitHub Actions workflow runs `@axe-core/cli` (or Playwright + `@axe-core/playwright`) against rendered block-page HTML on every PR touching `sentinel-core/src/blockpage/`. Fails PR on any WCAG AA violation.
- **Why:** Block-page is the trust artifact. Silent contrast/keyboard/ARIA regressions exclude screen-reader users from understanding why their connection failed — exactly the kind of failure a security tool can't have. DESIGN.md sets the spec; CI keeps it honest.
- **Pros:** Auto-checked every PR. ~1min CI time. Catches contrast drops, missing alt text, broken keyboard nav, ARIA issues, color-only state communication.
- **Cons:** ~1h to set up the workflow. False-positive flags on weird DOM patterns will need allowlist tuning.
- **Context:** Locked in /plan-design-review P6.1 (2026-04-26). axe-core is OSS (Apache-2.0). Run via either `@axe-core/cli` against static HTML, or Playwright + axe-core for full DOM render.
- **Depends on:** Block-page HTML committed (Week 2 of v0.1 sprint).
- **When:** Week 3 of v0.1 sprint, alongside cosign signing CI work.

### Td-5: Tray icon SVG files (9 total)

- **What:** Produce 9 SVG tray icon files matching DESIGN.md spec: shield-16-green.svg, shield-16-amber.svg, shield-16-red.svg, then 24px and 32px sets. Same shield geometry across sizes; only color (`--accent #4ec3a8` / `--warn #f0a868` / `--danger #c97a64`) varies. Stroke-only design at small sizes (no fill alpha at 16px to keep edges crisp).
- **Why:** Tray icon is the constant visual presence for a daily-use product. Without these, the `tray-icon` Rust crate ships with placeholder icon = first install looks unfinished = trust lost at the moment of install.
- **Pros:** ~1h work. Same SVG path used inline in block-page already, just resized + recolored. Could be done in Inkscape OR by hand-editing path data.
- **Cons:** Manual SVG drawing is tedious; alternative is to hire a designer for ~$50 on Fiverr (faster, may or may not be on-brand).
- **Context:** Locked in /plan-design-review (2026-04-26). DESIGN.md has full spec including amber sub-state tooltips.
- **Depends on:** DESIGN.md (committed at `/mnt/c/Projects/sentinel/DESIGN.md`).
- **When:** Week 2 of v0.1 sprint, alongside `tray-icon` crate Rust binding work.

### T3: v0.1 DX Expansion (9 items, ~5 days, sourced from /plan-devex-review 2026-04-26)

- **What:** Land DX gaps before v0.1 launch. Persona: HN/Show HN reader (sec-curious dev, 5min eval window). Mode: DX EXPANSION. Initial score 5/10 → projected 9/10 post-implementation. Adds ~5 days to v0.1 sprint; ship date slips from 2026-05-16 to ~2026-05-23.
- **Why:** v0.1 launch motion = Show HN (design line 461). HN reader within 5 minutes decides install/bookmark/skip. Each item below traced to concrete friction in the persona empathy narrative.
- **Pros:** Closes friction on trust-evaluation path. Pre-empts repeat HN comments. Opens door to OSS contributors from day 1. Compatible with zero-telemetry trust commitment (all measurement opt-in/self-paste).
- **Cons:** +5 days on a 3-week sprint = ~1 week ship slip. Some items (`sentinel doctor`, CONTRIBUTING.md) could defer cleanly to v0.2 if budget bites; user chose all-in.
- **Context:** /plan-devex-review run 2026-04-26 on commit a398b283. Persona, narrative, per-pass scoring logged in `~/.gstack/projects/MuzeenMir-sentinel/main-reviews.jsonl`.
- **Depends on:** v0.1 sprint scaffolding (T1 archive done, project skeleton up).
- **When:** Interleaved through v0.1 sprint Weeks 1-3.

**Checklist:**

README:
- [ ] Platform gate ("Windows-only v0.1; Linux v0.4; macOS v2.0+") ABOVE install one-liner
- [ ] `cosign verify-blob` snippet next to download link
- [ ] FAQ.md link in trust-signal section

CLI:
- [ ] `sentinel tail` — block.log JSONL streamer (~30 LOC)
- [ ] `sentinel --help` complete + per-subcommand help text
- [ ] `sentinel doctor` — port-53 + feed-stale + VPN-detect + DNS-config diag
- [ ] `sentinel doctor --report` — anonymized opt-in paste for bug reports
- [ ] `sentinel update --check` — opt-in GitHub Releases poll
- [ ] `sentinel service --foreground --no-install` — contributor dev-loop

Errors (Rust-tier: code + cause + fix + doc-link):
- [ ] E001 PORT_53_OCCUPIED → installer dialog + `127.0.0.1/help/port-conflict`
- [ ] E002 FEED_STALE → tray tooltip + `127.0.0.1/help/feed`
- [ ] E003 DNS_RESTORE_PARTIAL → uninstaller dialog (handles laptop adapter changes)
- [ ] E004 VPN_DETECTED → toast + `127.0.0.1/help/vpn` (silent breakage prevention)

Docs:
- [ ] FAQ.md (Dnscache, DoH bypass, VPN per-adapter, Mac/Linux ETA, FP procedure)
- [ ] SECURITY.md PGP key (pick PGP, not email-only)
- [ ] CONTRIBUTING.md (`cargo run`, `--foreground` dev-loop, fixtures)
- [ ] `/help/{port-conflict,feed,vpn,uninstall}` block-page routes (template HTML)

Config:
- [ ] `version: 1` field in `allowlist.json` + `config.toml` (v0.2 migration anchor)

CI:
- [ ] Linux + macOS `cargo check sentinel-core` (lib cross-platform sanity, GH Actions free)

GitHub repo:
- [ ] Issue templates: `bug.yml` / `fp-report.yml` / `feature.yml`
- [ ] GitHub Discussions enabled (separate from issues for HN-launch question volume)
