# v0.1 Watch-Test Roster

Status: LOCKED 2026-04-30 (office-hours session 5).
Closes Hard Gate part 2 of 2 (per design doc 2026-04-29).

## Sample size

Reduced from 5 → 3 per dev choice in office-hours 2026-04-30. Design doc
allows fallback to 3 with stated cost: less signal, faster lock-in. Proceed.

## Roster (codenames; real-name mapping kept private off-repo)

| # | Codename | Install Date  | Day-3 Ping  | Day-7 Check  | Status |
|---|----------|---------------|-------------|--------------|--------|
| 1 | Yami     | 2026-04-30    | 2026-05-03  | 2026-05-07   | scheduled |
| 2 | Levi     | 2026-05-01    | 2026-05-04  | 2026-05-08   | scheduled |
| 3 | Ragyo    | 2026-05-02    | 2026-05-05  | 2026-05-09   | scheduled |

Real-name mapping is held by the dev in a private file (NOT in this repo,
NOT in any cloud sync). The codename + dates are sufficient to track the
test publicly; the mapping connects codenames to people for the dev's own
follow-up.

## Build under test

v0.1.1 (post PR #19 merge). Frozen for the test window. Do NOT hand
watchees mid-T3 builds — signal density requires a stable surface.

If PR #19 has not merged by 2026-04-30 install date, hand the watchee a
local build of the PR-#19 branch and note "v0.1.1-pre-merge" in the
session log. Do NOT delay the install — the install date is the artifact.

## Per-session protocol

**Day 0 (install date):**
1. Verbal consent, plain language: "I'll watch you install this for 30
   minutes, take notes, and ping you on day 3 and day 7. OK?"
2. Hand them the signed `.msi`. Sit silent. Do not coach. Do not narrate.
3. Speak only if blocked >5 minutes on something they cannot resolve
   alone.
4. Take notes on your own screen, NOT in their view.
5. Note timestamps for: download, install start, install finish, first
   block-page seen, any errors, any moment they ask "what does this do?"

**Day 3 (3 days post-install):**
- Single message: "is Sentinel still running, did anything break?"
- If they say uninstalled → ask why, do NOT defend the product.
- If they say still running → do not prompt further; one-line answer
  is the artifact.

**Day 7 (7 days post-install):**
- Single message: "uninstalled? still running? noticed anything?"
- "Still running" verification: process present in Task Manager AND
  `127.0.0.1` is the active DNS on at least one adapter. Self-attestation
  alone does NOT count.
- Note final state: still-running / uninstalled-when-and-why /
  partial (e.g. paused-by-VPN per T3 spec).

## Pass conditions

- 1 of 3 watchees has v0.1.1 still running on day 7 → wedge survives,
  proceed to Show HN.
- 0 of 3 still running → wedge wrong, NOT polish wrong. Re-run premise
  challenge before any HN post.
- ≥2 of 3 fail to complete install → install flow broken. Trim path
  (Approach B in design doc) becomes mandatory; ship 0.1.2 install
  fixes first.

## Notes per session (filled as test runs)

### #1 Yami — install 2026-04-30
- consent: [ ]
- install start: __:__
- install finish: __:__
- first block-page: __:__
- errors: 
- ask-moments: 
- day-3: 
- day-7: 

### #2 Levi — install 2026-05-01
- consent: [ ]
- install start: __:__
- install finish: __:__
- first block-page: __:__
- errors: 
- ask-moments: 
- day-3: 
- day-7: 

### #3 Ragyo — install 2026-05-02
- consent: [ ]
- install start: __:__
- install finish: __:__
- first block-page: __:__
- errors: 
- ask-moments: 
- day-3: 
- day-7: 
