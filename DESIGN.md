# Sentinel — Design System

Single source of truth for visual identity. Anchors all UI surfaces (block-page, tray icon, toast notifications, installer dialogs, future Settings UI).

Extracted from `/plan-design-review` 2026-04-26, anchored to the approved block-page mockup at `~/.gstack/projects/MuzeenMir-sentinel/designs/blockpage-20260426/variant-C-final.html`.

## Voice & Tone

- **Calm. Confident. Technically literate but humane.**
- Like a physician explaining a result, not a security guard barking commands.
- Not corporate ("We have detected..."), not panicky ("WARNING THREAT BLOCKED"), not patronizing ("Don't worry, we got you!").
- Microcopy: short, factual, evidence-led. Always tell the user WHAT, then WHY, then WHAT THEY CAN DO.

Examples:
- ✅ "Listed in URLhaus, a community-curated feed of active malware URLs, since 2026-04-22."
- ✅ "Your machine never connected."
- ✅ "Sentinel intercepted the DNS lookup on your behalf."
- ❌ "WARNING: Phishing attempt detected!"
- ❌ "Don't worry, we've got this covered for you. 🛡️"
- ❌ "Our AI-powered threat intelligence system has identified..."

## Color Palette

CSS variables. Dark-mode is the default identity (system tool, not SaaS); light-mode supported via `prefers-color-scheme: light`.

```css
:root {
  color-scheme: dark;

  /* Surfaces */
  --bg:          #0d1117;  /* page background, deep slate */
  --panel:       #11161e;  /* card/terminal panel */
  --rule:        #1f2630;  /* dividers, borders */

  /* Text */
  --fg:          #e6edf3;  /* primary text */
  --muted:       #7a8590;  /* secondary text, labels */

  /* Accent — calm forest-teal, NOT alarm red */
  --accent:      #4ec3a8;
  --accent-dim:  #1c2925;

  /* Semantic */
  --warn:        #f0a868;  /* amber, "blocked" verdict pill */
  --warn-dim:    #2a221a;
  --danger:      #c97a64;  /* muted brick, "Allow forever" link */
}

@media (prefers-color-scheme: light) {
  :root {
    color-scheme: light;
    --bg:         #f6f7f8;
    --panel:      #ffffff;
    --rule:       #e1e5ea;
    --fg:         #0d1117;
    --muted:      #5f6873;
    --accent:     #0e6b5a;
    --accent-dim: #e6f0ec;
    --warn:       #8a4f1a;
    --warn-dim:   #f4e9d8;
    --danger:     #8c2a14;
  }
}
```

**Rules:**
- NEVER use generic-SaaS purple/violet/indigo. NEVER use alarm-red as primary.
- Accent green = "safety, calm, system-tool" (think htop, Tailscale).
- Amber = "blocked" verdict (caution color matches expectation; green pill on a block screen confuses users).
- All decisions reversible: amber/red are evidence colors, never permanent rejection signals.

## Type Stack

OSS-friendly fonts only. Self-host in v0.2+; v0.1 loads from Google Fonts CDN (`fonts.googleapis.com`).

```css
--mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, monospace;
--sans: 'IBM Plex Sans', system-ui, sans-serif;
```

- **JetBrains Mono** (Apache-2.0) — primary, used for h1 / props key+value / data / chrome
- **IBM Plex Sans** (SIL OFL 1.1) — secondary, used inside buttons + body prose
- NO `system-ui` or `Inter` as primary headline font (the "I gave up on typography" signal)
- Weights used: 400 (regular), 500 (medium), 600 (semibold)

## Spacing Scale

4-px base, doubling-then-add cadence. Pin all margins/padding to one of these:

| Token | px | Use |
|-------|-----|-----|
| s-1 | 4 | tight inline padding (verdict pill) |
| s-2 | 8 | gap between buttons in a row |
| s-3 | 12 | small section padding |
| s-4 | 16 | titlebar padding, props left-pad |
| s-5 | 24 | between major sections in body |
| s-6 | 32 | between hero + props |
| s-7 | 48 | between body + actions |
| s-8 | 64 | top/bottom of full page |

## Component Patterns

### Action Button Hierarchy

Three-tier visual hierarchy. The SAFE action is the easy click; the DANGEROUS action is visually demoted.

| Tier | Style | Use |
|------|-------|-----|
| **Primary** | filled `--accent` background, `--bg` text, semibold | Safe action: "Keep blocked", "Cancel" (in modal) |
| **Secondary** | transparent, `--rule` border, `--fg` text | Neutral action: "Allow once" |
| **Subdued** | transparent, `--danger` text, underlined, `margin-left: auto` (right-aligned, away from primary) | Dangerous action: "Allow forever" |

All buttons:
- `min-height: 44px` (touch target, accessibility)
- `font-family: var(--mono); font-size: 13px`
- `padding: 9px 16px; border-radius: 4px`
- `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }` (keyboard nav)
- `transition: background 120ms, border-color 120ms` (subtle hover)

### Terminal-Frame Chrome

Sentinel's signature container: bordered panel with titlebar + body + footer.

```
+------------------------------------------------+
| 🛡 sentinel — resolver       localhost · listen | titlebar (--bg, --rule border-bottom)
+------------------------------------------------+
|                                                |
| [body content]                                 | body (--panel, padding s-5)
|                                                |
+------------------------------------------------+
| ts ... id ... v0.1 ... github.com/...         | footer (--bg, --rule border-top, mono 11px)
+------------------------------------------------+
```

- `border: 1px solid var(--rule); border-radius: 6px; overflow: hidden;`
- Titlebar always shows brand identity ("sentinel" wordmark + shield) for trust ("this is your local Sentinel, not a phishing intermediary")
- Footer always shows: ISO timestamp, monospace block-id (forensic trust), version + license, GitHub repo link

### Key/Value Props

For showing structured data (block reason, system status, log entries).

```html
<div class="props">
  <div class="row"><span class="key">feed</span> <span class="val feed">URLhaus</span></div>
  <div class="row"><span class="key">listed</span> <span class="val">2026-04-22</span></div>
</div>
```

```css
.props {
  border-left: 1px solid var(--rule);
  padding-left: 16px;
  font-size: 13px;
  color: var(--muted);
}
.props .key { display: inline-block; min-width: 90px; color: var(--muted); }
.props .val { color: var(--fg); }
.props .val.feed { color: var(--accent); }
.props .val.warn { color: var(--warn); }
```

### Verdict Pill

Used to label the result of a Sentinel decision (blocked / allowed / paused). Color matches semantic meaning, not state-of-Sentinel.

```css
.verdict {
  display: inline-block;
  border: 1px solid var(--warn);
  background: var(--warn-dim);
  color: var(--warn);
  padding: 2px 10px;
  border-radius: 3px;
  font: 600 11px/1 var(--mono);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.verdict.allowed { border-color: var(--accent); background: var(--accent-dim); color: var(--accent); }
.verdict.paused  { border-color: var(--muted); background: var(--rule); color: var(--muted); }
```

### Animation

3 motions allowed, no more:

1. **Page entrance fade** — `animation: appear 240ms ease-out` (translateY 6px → 0, opacity 0 → 1). On `body` or main panel.
2. **Button hover** — `transition: background 120ms, border-color 120ms`. No transform, no scale.
3. **Keyboard focus ring** — `outline: 2px solid var(--accent); outline-offset: 2px` on `:focus-visible`. No animation, just appears.

`@media (prefers-reduced-motion: reduce)` disables entrance fade.

## Tray Icon (Windows System Tray)

SVG shield, 3 sizes (16px, 24px, 32px) × 3 states (green=healthy, amber=degraded, red=stopped).

```
GREEN (#4ec3a8) = healthy: service running, DNS routed, threat-feeds fresh
AMBER (#f0a868) = degraded: see tooltip for sub-state (4 possible)
RED   (#c97a64) = service stopped or recovery in progress
```

Amber sub-states (each shows in tooltip on hover):
1. "Threat feeds 26h stale" (last update >24h ago)
2. "Upstream DNS failover, using Quad9" (Cloudflare 1.1.1.1 unreachable)
3. "VPN active, Sentinel paused" (per-adapter DNS != 127.0.0.1, v0.2 auto-pause)
4. "Block-page server failed to bind :80" (blocking still works, but explainer URL broken)

SVG geometry: shield outline (stroke 1.5px) + interior fill (15% alpha for depth) + checkmark (stroke 1.5px, rounded line caps).

## Toast Notification (Windows Native)

Native Windows `winrt-notification` API. Fixed format:

```
🛡 Sentinel
Blocked example.com (URLhaus)
[Why?] [Allow once] [Allow forever]
```

Copy library:

| Event | Title | Body | Buttons |
|-------|-------|------|---------|
| Block | Sentinel | Blocked **{domain}** ({source}) | Why? · Allow once · Allow forever |
| Block (long domain >40 chars) | Sentinel | Blocked **{truncated...}** ({source}) | Why? · Allow once · Allow forever |
| Pause activated | Sentinel | Paused 5 min · resumes {time} | Resume now |
| Service stopped | Sentinel | Service stopped — DNS restored | Open log |
| Threat-feed stale (24h) | Sentinel | Threat feeds 24h stale · check internet | (no buttons) |
| VPN auto-pause (v0.2) | Sentinel | Paused while {VPN} active | Pause anyway |
| Weekly digest (v0.2, Sun 09:00) | Sentinel | Blocked **{N}** threats this week | View details |

Truncation rule: domain >40 chars → middle-truncated with ellipsis (`subdomain...example.com`). Native Windows toast has limited width.

## Installer Dialog Copy (NSIS)

Each dialog has fixed copy. No marketing language, no "thank you for choosing Sentinel" bloat.

### Welcome
**Title:** Install Sentinel v0.1.0
**Body:** Sentinel is an open-source DNS shield for Windows. It runs as a background service and blocks connections to known-malicious domains using community-curated threat feeds. All processing is local; nothing is sent to a server.
**Buttons:** [Install] [Cancel]

### Port 53 conflict detected
**Title:** Port 53 already in use
**Body:** Sentinel needs UDP port 53 (DNS) on 127.0.0.1, but another program is using it (likely Pi-hole, Acrylic DNS Proxy, or Dnsmasq). Stop the conflicting service first, then re-run this installer.
**Buttons:** [Quit] [Open detected service]

### Port 80 conflict detected
**Title:** Port 80 already in use
**Body:** Sentinel uses port 80 to serve the block-page when it sinkhole-redirects malicious sites. Another program is using it (likely IIS, nginx, or Docker Desktop). You can either stop that service, or use port 8053 instead. Block-pages will still work but the URL changes from `127.0.0.1` to `127.0.0.1:8053`.
**Buttons:** [Use 8053 instead] [Quit and fix manually]

### DNS modification consent
**Title:** Sentinel needs to set system DNS to 127.0.0.1
**Body:** Sentinel intercepts DNS by setting your system resolver to itself (127.0.0.1). Your current DNS server ({current_DNS}) will be saved and restored if you uninstall.
**Buttons:** [Set DNS to Sentinel] [Cancel install]

### Install complete
**Title:** Sentinel is installed and running
**Body:** Look for the green shield in your system tray. You're protected starting now. Block-page on http://127.0.0.1{:port}/ when something gets caught.
**Buttons:** [Done]

### Uninstall — preserve allowlist?
**Title:** Keep your allowlist?
**Body:** You added {N} domains to your personal allowlist. Keep them for next time you install Sentinel?
**Buttons:** [Keep allowlist] [Delete everything]

### Uninstall complete
**Title:** Sentinel uninstalled
**Body:** Your DNS is restored to {original_DNS}. Threat-feed cache and block log have been removed.
**Buttons:** [Done]

## Accessibility

Hard requirements for v0.1:
- All text contrast ≥ 4.5:1 (verify in CI via `axe-core` against block-page HTML)
- All interactive elements have `:focus-visible` ring
- All buttons keyboard-reachable in logical Tab order: Keep blocked → Allow once → Allow forever → footer link
- ARIA landmark on terminal `<div>` (use `<main role="main">` instead)
- Reduced motion: `@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; } }`
- Touch targets ≥ 44px × 44px (already enforced via `min-height: 44px` on buttons)
- No color-only state communication: amber pill has BOTH the amber color AND the word "BLOCKED"
- Screen-reader: announce verdict via `<output role="status" aria-live="polite">` (block-page renders for short flow, no live updates needed beyond initial)

## What This System Does NOT Include (intentionally)

- No animations beyond the 3 listed (no scroll-linked reveals, no parallax, no parallax-of-anything)
- No 3-column feature grid anywhere (AI slop blacklist)
- No icon-in-colored-circle decoration anywhere
- No emoji as primary design element (only allowed: 🛡 in toast title because Windows toast UI conventions, NOT as ornament inside body)
- No hero "carousels" or sliding banners
- No marketing-style "trusted by 10,000+ users" badges
- No purple/violet/indigo gradients

## Future Surfaces (v0.2+)

When new surfaces are designed, they MUST anchor to this DESIGN.md. The terminal-frame chrome + key/value props + button hierarchy + verdict pill carry across:

- **Tauri Settings UI** (v0.2): same color palette, same fonts, terminal-frame as window chrome
- **Threat-intel rule details page** (v0.2): same layout pattern as block-page, served on `127.0.0.1:80/rule/{id}`
- **HTTPS sinkhole** (v0.2): same block-page HTML, presented via self-signed cert chain
- **Multi-endpoint dashboard** (v2.0+ paid): same system, scaled to multi-machine grid view
