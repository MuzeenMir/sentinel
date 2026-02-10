#!/usr/bin/env python3
"""
generate-report.py — Parse baseline & protected attack results, build HTML diff report.

Usage:
    python3 generate-report.py <baseline_dir> <protected_dir> [--output report.html]

Example:
    python3 generate-report.py \
        ../attacker/results/baseline_20260210T120000Z \
        ../attacker/results/protected_20260210T130000Z \
        --output report.html
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Attack metadata (matches the 12 scripts)
# ---------------------------------------------------------------------------
ATTACK_META = {
    "01_recon_portscan": {
        "name": "Port Scan (SYN)",
        "tool": "nmap -sS",
        "category": "Reconnaissance",
        "sss_detection": "Port scan (behavioral features)",
        "sss_response": "DENY source IP",
    },
    "02_recon_vuln_scan": {
        "name": "Vulnerability Scan (NSE)",
        "tool": "nmap NSE scripts",
        "category": "Reconnaissance",
        "sss_detection": "Aggressive scan patterns",
        "sss_response": "DENY + Alert",
    },
    "03_brute_ssh": {
        "name": "SSH Brute Force",
        "tool": "hydra",
        "category": "Brute Force",
        "sss_detection": "Brute force (connection patterns)",
        "sss_response": "RATE_LIMIT then DENY",
    },
    "04_brute_web_login": {
        "name": "Web Login Brute Force",
        "tool": "hydra / curl",
        "category": "Brute Force",
        "sss_detection": "Brute force (HTTP patterns)",
        "sss_response": "RATE_LIMIT then DENY",
    },
    "05_dos_syn_flood": {
        "name": "SYN Flood (DoS)",
        "tool": "hping3",
        "category": "Denial of Service",
        "sss_detection": "DoS/DDoS (SYN ratio, packet rate)",
        "sss_response": "DROP + rate limit",
    },
    "06_dos_slowloris": {
        "name": "Slowloris (HTTP DoS)",
        "tool": "slowloris",
        "category": "Denial of Service",
        "sss_detection": "DoS (slow connections)",
        "sss_response": "DENY + connection reset",
    },
    "07_sqli_attack": {
        "name": "SQL Injection",
        "tool": "sqlmap / curl",
        "category": "Web Application",
        "sss_detection": "SQL injection (XGBoost)",
        "sss_response": "DENY + Alert",
    },
    "08_xss_attack": {
        "name": "Cross-Site Scripting (XSS)",
        "tool": "curl payloads",
        "category": "Web Application",
        "sss_detection": "XSS (XGBoost)",
        "sss_response": "DENY + Alert",
    },
    "09_data_exfil_dns": {
        "name": "DNS Data Exfiltration",
        "tool": "dig (DNS tunneling)",
        "category": "Data Exfiltration",
        "sss_detection": "Anomalous DNS patterns",
        "sss_response": "QUARANTINE + Alert",
    },
    "10_data_exfil_http": {
        "name": "HTTP Data Exfiltration",
        "tool": "curl (covert channel)",
        "category": "Data Exfiltration",
        "sss_detection": "Outbound traffic anomaly",
        "sss_response": "RATE_LIMIT + Alert",
    },
    "11_arp_spoof": {
        "name": "ARP Spoofing (MitM)",
        "tool": "arpspoof",
        "category": "Network Attack",
        "sss_detection": "Protocol deviation (L2)",
        "sss_response": "Alert (L2 not blockable via iptables)",
    },
    "12_c2_beacon": {
        "name": "C2 Beaconing",
        "tool": "curl (periodic callbacks)",
        "category": "Command & Control",
        "sss_detection": "C2 periodicity patterns",
        "sss_response": "DENY + Quarantine",
    },
}


def load_results(results_dir: str) -> dict:
    """Load all JSON result files from a directory."""
    results = {}
    rdir = Path(results_dir)
    if not rdir.exists():
        print(f"[ERROR] Directory not found: {results_dir}", file=sys.stderr)
        sys.exit(1)

    for f in sorted(rdir.glob("*.json")):
        if f.name.startswith("_"):
            continue  # skip summary files
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            key = f.stem  # e.g. "01_recon_portscan"
            results[key] = data
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Warning: Could not parse {f}: {e}", file=sys.stderr)
    return results


def load_summary(results_dir: str) -> dict:
    """Load _summary.json if it exists."""
    summary_path = Path(results_dir) / "_summary.json"
    if summary_path.exists():
        try:
            return json.loads(summary_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def build_comparison(baseline: dict, protected: dict) -> list:
    """Build a comparison table from baseline and protected results."""
    rows = []
    all_keys = sorted(set(list(baseline.keys()) + list(protected.keys())))

    for key in all_keys:
        meta = ATTACK_META.get(key, {})
        b = baseline.get(key, {})
        p = protected.get(key, {})

        row = {
            "id": key,
            "name": meta.get("name", key),
            "tool": meta.get("tool", ""),
            "category": meta.get("category", ""),
            "sss_detection": meta.get("sss_detection", ""),
            "sss_response": meta.get("sss_response", ""),
            "baseline_success": b.get("success", None),
            "baseline_evidence": b.get("evidence", "No data"),
            "protected_success": p.get("success", None),
            "protected_evidence": p.get("evidence", "No data"),
            "defended": (
                b.get("success", False) is True and p.get("success", False) is False
            ),
        }
        rows.append(row)
    return rows


def generate_html(rows: list, baseline_summary: dict, protected_summary: dict) -> str:
    """Generate the full HTML report."""

    # Calculate stats
    total = len(rows)
    baseline_succeeded = sum(1 for r in rows if r["baseline_success"] is True)
    protected_blocked = sum(1 for r in rows if r["protected_success"] is False)
    defended = sum(1 for r in rows if r["defended"])
    protection_rate = (defended / total * 100) if total > 0 else 0

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Build table rows
    table_rows = ""
    for r in rows:
        # Baseline status
        if r["baseline_success"] is True:
            b_class = "status-success"
            b_icon = "SUCCEEDED"
        elif r["baseline_success"] is False:
            b_class = "status-blocked"
            b_icon = "FAILED"
        else:
            b_class = "status-unknown"
            b_icon = "N/A"

        # Protected status
        if r["protected_success"] is True:
            p_class = "status-success"
            p_icon = "SUCCEEDED"
        elif r["protected_success"] is False:
            p_class = "status-blocked"
            p_icon = "BLOCKED"
        else:
            p_class = "status-unknown"
            p_icon = "N/A"

        # Defense verdict
        if r["defended"]:
            d_class = "verdict-defended"
            d_text = "DEFENDED"
        elif r["baseline_success"] is True and r["protected_success"] is True:
            d_class = "verdict-bypassed"
            d_text = "BYPASSED"
        elif r["baseline_success"] is False:
            d_class = "verdict-na"
            d_text = "N/A (baseline failed)"
        else:
            d_class = "verdict-unknown"
            d_text = "INCONCLUSIVE"

        # Escape HTML
        def esc(s):
            return (
                str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )

        table_rows += f"""
        <tr>
            <td class="attack-name">
                <strong>{esc(r['name'])}</strong><br>
                <small>{esc(r['tool'])} | {esc(r['category'])}</small>
            </td>
            <td class="{b_class}">{b_icon}</td>
            <td class="evidence">{esc(r['baseline_evidence'][:200])}</td>
            <td class="{p_class}">{p_icon}</td>
            <td class="evidence">{esc(r['protected_evidence'][:200])}</td>
            <td class="sss-info">
                <strong>Detection:</strong> {esc(r['sss_detection'])}<br>
                <strong>Response:</strong> {esc(r['sss_response'])}
            </td>
            <td class="{d_class}">{d_text}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSS Lab Report — Baseline vs Protected</title>
<style>
:root {{
    --bg: #0d1117;
    --bg2: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text2: #8b949e;
    --green: #238636;
    --green-bg: #0d2818;
    --red: #f85149;
    --red-bg: #3d1418;
    --yellow: #d29922;
    --yellow-bg: #2d2000;
    --blue: #58a6ff;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2em;
}}
h1 {{ color: #fff; margin-bottom: 0.5em; font-size: 1.8em; }}
h2 {{ color: var(--blue); margin: 1.5em 0 0.5em; font-size: 1.3em; }}
.meta {{ color: var(--text2); margin-bottom: 2em; }}

/* Executive Summary Cards */
.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1em;
    margin: 1.5em 0;
}}
.card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2em;
    text-align: center;
}}
.card .number {{
    font-size: 2.5em;
    font-weight: bold;
    display: block;
}}
.card .label {{ color: var(--text2); font-size: 0.9em; }}
.card.green .number {{ color: var(--green); }}
.card.red .number {{ color: var(--red); }}
.card.yellow .number {{ color: var(--yellow); }}
.card.blue .number {{ color: var(--blue); }}

/* Protection meter */
.meter {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5em;
    margin: 1.5em 0;
}}
.meter-bar {{
    background: #21262d;
    border-radius: 4px;
    height: 30px;
    position: relative;
    overflow: hidden;
}}
.meter-fill {{
    background: linear-gradient(90deg, var(--green), #2ea043);
    height: 100%;
    border-radius: 4px;
    transition: width 1s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    color: #fff;
    font-size: 0.9em;
}}

/* Comparison Table */
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
    font-size: 0.85em;
}}
th {{
    background: var(--bg2);
    color: var(--text);
    padding: 10px 8px;
    text-align: left;
    border-bottom: 2px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 1;
}}
td {{
    padding: 10px 8px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}}
tr:hover {{ background: rgba(56, 139, 253, 0.05); }}

.attack-name {{ min-width: 160px; }}
.attack-name small {{ color: var(--text2); }}
.evidence {{ max-width: 250px; word-break: break-word; color: var(--text2); font-size: 0.9em; }}
.sss-info {{ max-width: 200px; font-size: 0.85em; color: var(--text2); }}
.sss-info strong {{ color: var(--text); }}

/* Status cells */
.status-success {{ color: var(--red); font-weight: bold; background: var(--red-bg); text-align: center; }}
.status-blocked {{ color: var(--green); font-weight: bold; background: var(--green-bg); text-align: center; }}
.status-unknown {{ color: var(--text2); text-align: center; }}

/* Verdict cells */
.verdict-defended {{ color: var(--green); font-weight: bold; background: var(--green-bg); text-align: center; }}
.verdict-bypassed {{ color: var(--red); font-weight: bold; background: var(--red-bg); text-align: center; }}
.verdict-na {{ color: var(--text2); text-align: center; }}
.verdict-unknown {{ color: var(--yellow); text-align: center; }}

/* Legend */
.legend {{
    display: flex;
    gap: 2em;
    margin: 1em 0;
    font-size: 0.9em;
    color: var(--text2);
}}
.legend span {{
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 3px;
    margin-right: 4px;
    vertical-align: middle;
}}
.legend .green {{ background: var(--green); }}
.legend .red {{ background: var(--red); }}
.legend .gray {{ background: var(--text2); }}

footer {{
    margin-top: 3em;
    padding-top: 1em;
    border-top: 1px solid var(--border);
    color: var(--text2);
    font-size: 0.85em;
}}
</style>
</head>
<body>

<h1>Sentinel Security System — Lab Test Report</h1>
<p class="meta">Generated: {now} | Target: {baseline_summary.get('target_ip', 'N/A')}</p>

<h2>Executive Summary</h2>
<div class="summary">
    <div class="card blue">
        <span class="number">{total}</span>
        <span class="label">Total Attacks</span>
    </div>
    <div class="card red">
        <span class="number">{baseline_succeeded}</span>
        <span class="label">Baseline Succeeded<br>(No Protection)</span>
    </div>
    <div class="card green">
        <span class="number">{protected_blocked}</span>
        <span class="label">Blocked by SSS<br>(With Protection)</span>
    </div>
    <div class="card green">
        <span class="number">{defended}</span>
        <span class="label">Attacks Defended<br>(Succeeded &rarr; Blocked)</span>
    </div>
</div>

<div class="meter">
    <strong>SSS Protection Rate</strong>
    <div class="meter-bar">
        <div class="meter-fill" style="width: {protection_rate:.0f}%">
            {protection_rate:.1f}%
        </div>
    </div>
    <p style="margin-top:0.5em; color: var(--text2);">
        Of the {baseline_succeeded} attacks that succeeded without protection,
        SSS defended against {defended}.
    </p>
</div>

<h2>Attack-by-Attack Comparison</h2>

<div class="legend">
    <div><span class="red"></span> Attack Succeeded (bad for defender)</div>
    <div><span class="green"></span> Attack Blocked (good for defender)</div>
    <div><span class="gray"></span> Inconclusive / N/A</div>
</div>

<table>
<thead>
<tr>
    <th>Attack</th>
    <th>Baseline<br>(No SSS)</th>
    <th>Baseline Evidence</th>
    <th>Protected<br>(With SSS)</th>
    <th>Protected Evidence</th>
    <th>SSS Detection</th>
    <th>Verdict</th>
</tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>

<h2>Methodology</h2>
<ul style="margin:1em 0; padding-left:2em; color:var(--text2)">
    <li><strong>Baseline run:</strong> All SSS services stopped, iptables SENTINEL chains flushed. Attacks executed from Kali VM.</li>
    <li><strong>Protected run:</strong> Full SSS Docker stack deployed (AI Engine, Data Collector, Policy Orchestrator, DRL Engine, Alert Service). Same attacks re-executed.</li>
    <li><strong>Verdict:</strong> An attack is "DEFENDED" if it succeeded in baseline but was blocked in the protected run.</li>
    <li><strong>Environment:</strong> Ubuntu 20.04 LTS target, Kali Linux attacker, NAT Network.</li>
</ul>

<footer>
    <p>Sentinel Security System (SSS) &mdash; Red Team vs Blue Team Lab Report</p>
    <p>Report generated by generate-report.py</p>
</footer>

</body>
</html>"""

    return html


def main():
    parser = argparse.ArgumentParser(
        description="Generate SSS Lab comparison report from baseline and protected attack results."
    )
    parser.add_argument("baseline_dir", help="Path to baseline results directory")
    parser.add_argument("protected_dir", help="Path to protected results directory")
    parser.add_argument(
        "--output",
        "-o",
        default="sss_lab_report.html",
        help="Output HTML file (default: sss_lab_report.html)",
    )
    args = parser.parse_args()

    print(f"[*] Loading baseline results from: {args.baseline_dir}")
    baseline = load_results(args.baseline_dir)
    baseline_summary = load_summary(args.baseline_dir)
    print(f"    Found {len(baseline)} result files.")

    print(f"[*] Loading protected results from: {args.protected_dir}")
    protected = load_results(args.protected_dir)
    protected_summary = load_summary(args.protected_dir)
    print(f"    Found {len(protected)} result files.")

    if not baseline and not protected:
        print("[ERROR] No results found in either directory.", file=sys.stderr)
        sys.exit(1)

    print("[*] Building comparison...")
    rows = build_comparison(baseline, protected)

    print("[*] Generating HTML report...")
    html = generate_html(rows, baseline_summary, protected_summary)

    output_path = Path(args.output)
    output_path.write_text(html, encoding="utf-8")
    print(f"[OK] Report written to: {output_path.resolve()}")

    # Print quick summary
    total = len(rows)
    defended = sum(1 for r in rows if r["defended"])
    baseline_ok = sum(1 for r in rows if r["baseline_success"] is True)
    protected_ok = sum(1 for r in rows if r["protected_success"] is True)
    print()
    print("=" * 50)
    print(f"  Total attacks:           {total}")
    print(f"  Baseline succeeded:      {baseline_ok}")
    print(f"  Protected succeeded:     {protected_ok}")
    print(f"  Attacks defended by SSS: {defended}")
    rate = (defended / baseline_ok * 100) if baseline_ok > 0 else 0
    print(f"  Protection rate:         {rate:.1f}%")
    print("=" * 50)


if __name__ == "__main__":
    main()
