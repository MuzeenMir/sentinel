#!/usr/bin/env python3
"""
Intentionally Vulnerable Web Application for SSS Lab Testing.

WARNING: This application is DELIBERATELY INSECURE.
         It exists solely to serve as an attack target in the SSS VM lab.
         NEVER deploy this outside an isolated test environment.
"""

import os
import sqlite3
import html
import json
import time
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DB_PATH = "/tmp/vuln_app.db"
HOST = "0.0.0.0"
PORT = int(os.environ.get("VULN_APP_PORT", "8888"))

# ---------------------------------------------------------------------------
# Database helpers (intentionally using raw SQL everywhere)
# ---------------------------------------------------------------------------

def init_db():
    """Create tables and seed data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT NOT NULL,
            price REAL NOT NULL,
            sku   TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            key   TEXT NOT NULL,
            value TEXT NOT NULL
        )
    """)
    # Seed users — weak credentials, no hashing (intentional)
    users = [
        ("admin", "admin123", "admin"),
        ("analyst", "password", "user"),
        ("operator", "sentinel", "user"),
        ("guest", "guest", "user"),
    ]
    for u, p, r in users:
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (u, p, r))
        except sqlite3.IntegrityError:
            pass
    # Seed products
    products = [
        ("Firewall Appliance", 2499.99, "FW-001"),
        ("IDS Sensor", 1899.50, "IDS-002"),
        ("SIEM License", 5499.00, "SIEM-003"),
        ("VPN Gateway", 3200.00, "VPN-004"),
        ("Endpoint Agent", 49.99, "EP-005"),
    ]
    for name, price, sku in products:
        try:
            c.execute("INSERT INTO products (name, price, sku) VALUES (?, ?, ?)", (name, price, sku))
        except sqlite3.IntegrityError:
            pass
    # Seed secrets (simulated sensitive data for exfiltration scenarios)
    secrets = [
        ("db_password", "Sup3rS3cretDBPa$$w0rd"),
        ("api_key", "sk-live-4f8a9b2c3d7e1f0a6b5c8d9e"),
        ("encryption_key", "AES256-KEY-a1b2c3d4e5f6a7b8"),
        ("jwt_secret", "sentinel-jwt-hmac-secret-do-not-leak"),
        ("ssh_private_key", "-----BEGIN RSA PRIVATE KEY-----MIIFAKE-----"),
    ]
    for k, v in secrets:
        try:
            c.execute("INSERT INTO secrets (key, value) VALUES (?, ?)", (k, v))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

def query_db(sql, args=(), one=False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(sql, args)
    rows = cur.fetchall()
    conn.close()
    if one:
        return dict(rows[0]) if rows else None
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# HTML templates (inline, minimal)
# ---------------------------------------------------------------------------

PAGE_HEAD = """<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>VulnApp – SSS Lab Target</title>
<style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:2em}
a{color:#58a6ff}
input,button{padding:6px 10px;margin:4px 0;font-family:monospace;background:#161b22;color:#c9d1d9;border:1px solid #30363d}
button{cursor:pointer;background:#238636;border-color:#238636;color:#fff}
table{border-collapse:collapse;margin:1em 0}
th,td{border:1px solid #30363d;padding:6px 12px;text-align:left}
th{background:#161b22}
.warn{color:#f85149;font-weight:bold}
pre{background:#161b22;padding:1em;overflow-x:auto;border:1px solid #30363d}
</style></head><body>"""

PAGE_FOOT = "</body></html>"

HOME_PAGE = PAGE_HEAD + """
<h1>VulnApp &mdash; SSS Lab Target</h1>
<p class="warn">WARNING: This application is intentionally vulnerable.</p>
<ul>
  <li><a href="/login">Login</a> (brute-forceable)</li>
  <li><a href="/search?q=">Search Products</a> (SQL injectable)</li>
  <li><a href="/comment?text=Hello">Comment / Reflect</a> (XSS)</li>
  <li><a href="/api/data">Sensitive Data API</a> (exfiltration target)</li>
  <li><a href="/health">Health Check</a></li>
</ul>
""" + PAGE_FOOT


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class VulnHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentionally vulnerable endpoints."""

    # Suppress default stderr logging for cleaner output
    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    # ---- routing ----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            self._send_html(200, HOME_PAGE)
        elif path == "/login":
            self._handle_login_form()
        elif path == "/search":
            self._handle_search(params)
        elif path == "/comment":
            self._handle_comment(params)
        elif path == "/api/data":
            self._handle_api_data()
        elif path == "/health":
            self._send_json(200, {"status": "ok", "timestamp": time.time()})
        else:
            self._send_html(404, PAGE_HEAD + "<h1>404 Not Found</h1>" + PAGE_FOOT)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="replace")

        if path == "/login":
            self._handle_login_submit(body)
        elif path == "/api/data":
            # Accept POST for exfiltration simulation (echo back)
            self._send_json(200, {"received_bytes": len(body), "echo": body[:200]})
        else:
            self._send_html(404, PAGE_HEAD + "<h1>404 Not Found</h1>" + PAGE_FOOT)

    # ---- /login (brute-forceable, no rate limit, no lockout) --------------

    def _handle_login_form(self):
        page = PAGE_HEAD + """
        <h2>Login</h2>
        <form method="POST" action="/login">
          <label>Username: <input name="username" type="text"></label><br>
          <label>Password: <input name="password" type="password"></label><br>
          <button type="submit">Sign In</button>
        </form>
        """ + PAGE_FOOT
        self._send_html(200, page)

    def _handle_login_submit(self, body):
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        # VULN: No rate limiting, no account lockout, plaintext password comparison
        user = query_db(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
            one=True,
        )
        if user:
            token = hashlib.md5(f"{username}:{time.time()}".encode()).hexdigest()
            page = PAGE_HEAD + f"""
            <h2>Login Successful</h2>
            <p>Welcome, <b>{username}</b> (role: {user['role']})</p>
            <p>Session token: <code>{token}</code></p>
            <a href="/">Home</a>
            """ + PAGE_FOOT
            self._send_html(200, page)
        else:
            # VULN: Reveals whether username exists (different message possible)
            page = PAGE_HEAD + """
            <h2>Login Failed</h2>
            <p class="warn">Invalid username or password.</p>
            <a href="/login">Try again</a>
            """ + PAGE_FOOT
            self._send_html(401, page)

    # ---- /search (SQL injection) ------------------------------------------

    def _handle_search(self, params):
        q = params.get("q", [""])[0]

        # VULN: Direct string interpolation into SQL — classic SQL injection
        sql = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR sku LIKE '%{q}%'"
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(sql)
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
        except Exception as e:
            # VULN: Leaks SQL error messages to the user
            page = PAGE_HEAD + f"""
            <h2>Search Error</h2>
            <pre class="warn">{html.escape(str(e))}</pre>
            <p>Query was: <code>{html.escape(sql)}</code></p>
            <a href="/search?q=">Back</a>
            """ + PAGE_FOOT
            self._send_html(500, page)
            return

        rows_html = ""
        for r in rows:
            rows_html += f"<tr><td>{r.get('id','')}</td><td>{r.get('name','')}</td><td>${r.get('price','')}</td><td>{r.get('sku','')}</td></tr>"

        page = PAGE_HEAD + f"""
        <h2>Product Search</h2>
        <form method="GET" action="/search">
          <input name="q" value="{html.escape(q)}" placeholder="Search...">
          <button type="submit">Search</button>
        </form>
        <p>Results for: <b>{q}</b></p>
        <table><tr><th>ID</th><th>Name</th><th>Price</th><th>SKU</th></tr>
        {rows_html}
        </table>
        <a href="/">Home</a>
        """ + PAGE_FOOT
        self._send_html(200, page)

    # ---- /comment (reflected XSS) ----------------------------------------

    def _handle_comment(self, params):
        text = params.get("text", [""])[0]

        # VULN: User input reflected directly without escaping
        page = PAGE_HEAD + f"""
        <h2>Comments</h2>
        <form method="GET" action="/comment">
          <input name="text" value="" placeholder="Leave a comment...">
          <button type="submit">Post</button>
        </form>
        <div class="comment">
          <p>Latest comment:</p>
          <blockquote>{text}</blockquote>
        </div>
        <a href="/">Home</a>
        """ + PAGE_FOOT
        self._send_html(200, page)

    # ---- /api/data (sensitive data for exfiltration targets) ---------------

    def _handle_api_data(self):
        # VULN: No authentication required, exposes sensitive data
        secrets = query_db("SELECT key, value FROM secrets")
        users = query_db("SELECT id, username, password, role FROM users")
        data = {
            "classification": "CONFIDENTIAL",
            "secrets": secrets,
            "users": users,
            "system_info": {
                "hostname": os.environ.get("HOSTNAME", "vuln-app"),
                "db_path": DB_PATH,
            },
        }
        self._send_json(200, data)

    # ---- response helpers -------------------------------------------------

    def _send_html(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # VULN: No security headers (CSP, X-Frame-Options, etc.)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    server = HTTPServer((HOST, PORT), VulnHandler)
    print(f"[VulnApp] Listening on {HOST}:{PORT}")
    print(f"[VulnApp] WARNING: This server is intentionally vulnerable.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[VulnApp] Shutting down.")
        server.server_close()
