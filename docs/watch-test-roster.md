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
- consent: [x] (verbal, before install)
- install start: 2026-04-30 ~20:22 local
- install finish: 2026-04-30 ~20:29 local (sentinel.exe build + bundle copy + first setup.ps1 run)
- first block-page: 2026-04-30 ~21:15 local (placeholder render at 127.0.0.1)
- first REAL block-page: 2026-04-30 ~21:25 local (`0022a601.pphost.net`,
  URLhaus `malware_download`, listed 2020-05-25, sinkhole → 127.0.0.1)
- errors:
  - **Run #1:** sentinel.exe exited immediately after Start-Process;
    root cause = setup.ps1 launched without `service` subcommand.
    Fixed in PR #22 (squashed into commit `d4eebbaa`). Bundle
    re-tested same evening.
  - **Run #2 (post-fix):** clean. Resolver listening, URLhaus
    refresher loaded 2422 domains (per `sentinel.err.log`),
    block-page rendered placeholder + real block on a confirmed
    URLhaus listing.
  - Minor unfixed: `nslookup not-listed-domain.example` returns
    "Server failed" (SERVFAIL) instead of NXDOMAIN. Filed for v0.2
    polish; does not affect blocking semantics. Not a blocker.
- ask-moments / verbatim feedback (Yami's words, dev's notes):
  - **"OK but like simple .exe file, click give permission, install
    and runs"** — wants a double-click installer experience, not
    PowerShell scripts. *Validates T3 `.msi` installer scope.*
  - **"likes that he is stopped from connecting to bad sites"** —
    restated the wedge in his own words without prompting. *OQ2
    effectively passing informally.* Formal stranger-skim test on
    `docs/show-hn-draft.md` not yet run; the value-prop landed in
    plain conversation, which is the underlying signal OQ2 was
    designed to detect.
  - **"will it auto-start after shutdown?"** — expected reboot
    persistence. Bundle did not have it on first install. *Patched
    same evening in PR #22 (commit `1969532a`,
    `feat(installer): Task Scheduler SentinelWatchtest at user
    logon`).* Yami needs to run the updated `.\uninstall.ps1` then
    `.\setup.ps1` once for the auto-start to register.
- day-3 (2026-05-03): 
- day-7 (2026-05-07): 

### Day-0 lessons for v0.1 product (from Yami session, not test data)

Three findings shape T3 / v0.1 priorities:

1. **`.msi` installer is non-negotiable for v0.1 launch.** The current
   PowerShell-script bundle works, but Yami articulated the gap on
   first contact. T3 already has signed `.msi` installer in scope;
   this confirms it must ship before Show HN.
2. **Wedge sentence works in plain conversation.** Yami did not need
   the Show HN draft to articulate the value back; being blocked from
   a real malicious domain was self-evidently the value. Stronger
   signal than any draft re-read can produce.
3. **Auto-start is table stakes**, not a v0.2 polish item. A user who
   has to re-run `setup.ps1` after every reboot is a user who
   uninstalls by day 2. Watch-test bundle now patches this via Task
   Scheduler; v0.1 release MUST register sentinel.exe as a real
   Windows Service (T3 `sentinel install --service` scope).

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
