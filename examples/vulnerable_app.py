"""A deliberately vulnerable demo app for exercising bughound locally.

Run it, then scan it (authorized, localhost):

    python examples/vulnerable_app.py           # serves on 127.0.0.1:8081
    bughound scan http://127.0.0.1:8081/ \
        --authorize-host 127.0.0.1 --i-am-authorized --aggressive --no-external

The endpoints here are *genuinely* exploitable (real sqlite3 database, real
shell execution, real server-side fetch) so the exploit phase can prove
impact end-to-end: UNION-based credential extraction with automatic login
(account takeover), hidden-data tautology reveal (' OR 1=1--), boolean-blind
binary-search extraction (query param AND TrackingId cookie), `id`/`uname`
output capture, loopback content exfiltration and NoSQL operator-based
authentication bypass.

Every exploit primitive is strictly read-only / informational.
DO NOT expose this app to the internet.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import urllib.request

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

app = FastAPI()

DB_PATH = ":memory:"


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS products "
        "(id INTEGER, name TEXT, price REAL, category TEXT, released INTEGER)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions (sessionid TEXT, username TEXT)"
    )
    conn.executemany(
        "INSERT OR IGNORE INTO products VALUES (?,?,?,?,?)",
        [
            (1, "Widget", 9.99, "Accessories", 1),
            (2, "Gadget", 19.99, "Gadgets", 1),
            (3, "Doohickey", 4.5, "Accessories", 1),
            # A row the app tries to hide (unreleased) -- the /filter tautology
            # lab's objective is to reveal it.
            (4, "Prototype Stealth Widget", 999.0, "Accessories", 0),
        ],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO users VALUES (?,?,?)",
        [(1, "administrator", "S3cret-wizard-pass")],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO sessions VALUES (?,?)",
        [("bhtid-demo-session-0001", "administrator")],
    )
    return conn


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    # Missing security headers, exposes a secret and links with params, and
    # sets a session cookie without Secure/HttpOnly/SameSite. Also includes
    # recon breadcrumbs (script src, admin link, mailto, etc.) so the new
    # recon modules have something to discover in the integration test.
    body = """<html><head><title>Demo Shop</title></head><body>
    <h1>Demo</h1>
    <!-- config -->
    <script>const api_key = "[REDACTED:aws_access_key]"; var stripe="sk_live_0123456789abcdefghijklmn";</script>
    <script src="/static/app.js"></script>
    <a href="/search?q=hello">search</a>
    <a href="/item?id=1">item 1</a>
    <a href="/product?id=1">product 1</a>
    <a href="/filter?category=Accessories">accessories</a>
    <a href="/track">track</a>
    <a href="/stock?sku=Widget">stock</a>
    <a href="/go?url=/home">home</a>
    <a href="/file?name=readme.txt">readme</a>
    <a href="/ping?host=127.0.0.1">ping</a>
    <a href="/fetch?url=/status">fetch</a>
    <a href="/admin">admin</a>
    <a href="mailto:admin@example.com">contact</a>
    <form method="post" action="/transfer">
      <input name="amount" value="10"/><input name="to" value="bob"/>
      <button>send</button>
    </form>
    <form method="post" action="/login">
      <input name="username"/><input type="password" name="password"/>
    </form>
    <form method="post" action="/login-nosql">
      <input name="user"/><input name="pass"/>
      <button>nosql login</button>
    </form>
    </body></html>"""
    r = HTMLResponse(body)
    r.headers["set-cookie"] = "SESSIONID=abc123; Path=/"
    r.headers["server"] = "nginx/1.18.0 (Ubuntu)"
    r.headers["x-powered-by"] = "Express"
    return r


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots() -> str:
    # Recon breadcrumb: robots.txt explicitly hides /admin and /private.
    return "User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: /sitemap.xml\n"


@app.get("/sitemap.xml", response_class=PlainTextResponse)
def sitemap() -> str:
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc></url>
  <url><loc>/search</loc></url>
  <url><loc>/item</loc></url>
  <url><loc>/admin</loc></url>
</urlset>"""


@app.get("/static/app.js", response_class=PlainTextResponse)
def app_js() -> str:
    # Recon breadcrumb: a script referencing internal API endpoints.
    return """
fetch("/api/v1/users").then(r => r.json());
fetch("/api/v1/orders").then(r => r.json());
const config = {endpoint: "/api/internal/health"};
//# sourceMappingURL=/static/app.js.map
"""


@app.get("/static/app.js.map", response_class=PlainTextResponse)
def app_js_map() -> str:
    # Recon breadcrumb: a publicly accessible source map.
    return json.dumps({
        "version": 3,
        "file": "app.js",
        "sources": ["../src/app.js", "../src/internal.js"],
        "mappings": "AAAA",
    })


@app.get("/admin", response_class=HTMLResponse)
def admin() -> HTMLResponse:
    # Recon breadcrumb: an exposed admin panel.
    return "<html><body><h1>Admin Panel</h1><form><input name='password'/></form></body></html>"


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
def security_txt() -> str:
    return "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\n"


@app.get("/search", response_class=HTMLResponse)
def search(q: str = "") -> str:
    # Reflected XSS: q echoed unencoded.
    return f"<html><body>Results for: {q}</body></html>"


@app.get("/item", response_class=HTMLResponse)
def item(id: str = "1") -> HTMLResponse:
    # Error-based SQLi simulation: a quote breaks the "query". The error
    # message is fixed (no input echo) so this stays a pure SQLi demo.
    if "'" in id or '"' in id:
        return HTMLResponse(
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version", status_code=500)
    return HTMLResponse(f"<html><body>Item {id}</body></html>")


@app.get("/product", response_class=HTMLResponse)
def product(id: str = "1") -> HTMLResponse:
    # REAL error-based + UNION SQLi against sqlite3 (stdlib, in-memory).
    # The id is interpolated straight into the query on purpose.
    conn = _db()
    try:
        rows = conn.execute(
            f"SELECT id, name, price FROM products WHERE id={id}"
        ).fetchall()
        body = "".join(f"<div>#{r[0]} {r[1]} price={r[2]}</div>" for r in rows)
        return HTMLResponse(f"<html><body>{body or 'no product'}</body></html>")
    except sqlite3.Error:
        # Sanitized error page: leaks the driver signature but not the input.
        return HTMLResponse(
            "sqlite3.OperationalError: query failed", status_code=500)
    finally:
        conn.close()


@app.get("/filter", response_class=HTMLResponse)
def filter_products(category: str = "") -> HTMLResponse:
    # Hidden-data lab (PortSwigger 'retrieval of hidden data' style):
    # unreleased products are filtered out -- unless you inject ' OR 1=1--.
    conn = _db()
    try:
        rows = conn.execute(
            f"SELECT name, price FROM products WHERE category='{category}' "
            "AND released=1"
        ).fetchall()
        body = "".join(f"<div class=product>{r[0]} - {r[1]}</div>" for r in rows)
        return HTMLResponse(f"<html><body>{body or 'no products'}</body></html>")
    except sqlite3.Error:
        return HTMLResponse("sqlite3.OperationalError: query failed", status_code=500)
    finally:
        conn.close()


@app.get("/track", response_class=HTMLResponse)
def track(request: Request) -> Response:
    # Blind cookie-SQLi lab (PortSwigger TrackingId style): the sessionid
    # cookie value is interpolated into a lookup. TRUE/FALSE responses
    # differ ('Welcome back' vs plain page) giving a boolean oracle; the
    # users table holds the administrator password to extract.
    tid = request.cookies.get("TrackingId", "")
    conn = _db()
    try:
        row = conn.execute(
            f"SELECT username FROM sessions WHERE sessionid='{tid}'"
        ).fetchall()
        if row:
            return HTMLResponse(
                f"<html><body>Welcome back, {row[0][0]}!</body></html>")
        # Issue a real, valid TrackingId (a row in sessions) so the baseline
        # request shows the authenticated variant -- same as the real lab.
        valid = conn.execute(
            "SELECT sessionid FROM sessions LIMIT 1"
        ).fetchone()
        issued = valid[0] if valid else f"bhtid-demo-{secrets.token_hex(8)}"
        resp = HTMLResponse("<html><body>Analytics tracking enabled</body></html>")
    finally:
        conn.close()
    resp.headers["set-cookie"] = f"TrackingId={issued}; Path=/"
    return resp


@app.get("/stock", response_class=HTMLResponse)
def stock(sku: str = "") -> HTMLResponse:
    # Boolean-blind SQLi: TRUE/FALSE pages differ, errors are hidden (200),
    # so only the boolean differential is observable -- the classic blind case.
    conn = _db()
    in_stock = "<html><body>In stock</body></html>"
    out_of_stock = "<html><body>Out of stock</body></html>"
    try:
        rows = conn.execute(
            f"SELECT name FROM products WHERE name='{sku}'"
        ).fetchall()
        return HTMLResponse(in_stock if rows else out_of_stock)
    except sqlite3.Error:
        return HTMLResponse(out_of_stock)
    finally:
        conn.close()


@app.get("/file", response_class=HTMLResponse)
def file(name: str = "readme.txt") -> HTMLResponse:
    # Path traversal simulation: arbitrary read of "system files".
    if "etc/passwd" in name or "../" in name:
        return HTMLResponse(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        )
    if "etc/hostname" in name:
        return HTMLResponse("bh-demo-host")
    return HTMLResponse(f"contents of {name}")


@app.get("/ping", response_class=PlainTextResponse)
def ping(host: str = "127.0.0.1") -> str:
    # REAL OS command injection: host is interpolated into a shell command.
    # Even without a ping binary, appended `;id` / `;uname` still execute.
    stream = os.popen(f"ping -c 1 {host}")
    return stream.read()


@app.get("/fetch", response_class=PlainTextResponse)
def fetch(url: str = "") -> str:
    # REAL SSRF: the server fetches the requested URL and returns the body.
    # Loopback fetches (127.0.0.1:<own port>) prove internal access.
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 -- deliberate demo behaviour
        return f"fetch failed: {exc}"


@app.get("/go")
def go(url: str = "/") -> RedirectResponse:
    # Open redirect.
    return RedirectResponse(url)


@app.post("/login-nosql", response_class=HTMLResponse)
async def login_nosql(request: Request) -> HTMLResponse:
    # NoSQL operator injection: keys like "user[$ne]" rewrite the selector
    # to {"user": {"$ne": "bughound"}} which matches any account -> bypass.
    form = await request.form()
    if any("[$" in str(k) for k in form.keys()):
        return HTMLResponse(
            "<html><body>Welcome back, admin! <a href='/logout'>Logout</a> "
            "<a href='/dashboard'>Dashboard</a></body></html>"
        )
    return HTMLResponse("<html><body>Invalid credentials</body></html>")


@app.get("/status", response_class=PlainTextResponse)
def status() -> str:
    return "status ok"


@app.options("/")
def options_root() -> Response:
    # Recon breadcrumb: OPTIONS exposes dangerous methods.
    r = Response(content="")
    r.headers["allow"] = "GET, POST, OPTIONS, PUT, DELETE, TRACE"
    return r


@app.get("/api/data")
def data(request: Request) -> Response:
    # CORS reflects Origin with credentials.
    origin = request.headers.get("origin", "*")
    r = Response(content='{"ok":true}', media_type="application/json")
    r.headers["access-control-allow-origin"] = origin
    r.headers["access-control-allow-credentials"] = "true"
    return r


@app.get("/login")
def login_form() -> Response:
    # Session cookie without flags.
    r = Response(content="login")
    r.headers["set-cookie"] = "SESSIONID=abc123; Path=/"
    return r


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request) -> HTMLResponse:
    # REAL credential check against the users table. This endpoint is the
    # target of the SQLi-driven account-takeover proof: the exploit engine
    # extracts administrator's password via UNION / blind SQLi elsewhere,
    # then submits it here and must receive an authenticated page.
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    conn = _db()
    try:
        row = conn.execute(
            "SELECT username FROM users WHERE username=? AND password=?",
            (username, password),
        ).fetchall()
    finally:
        conn.close()
    if row:
        return HTMLResponse(
            f"<html><body>Welcome back, {row[0][0]}! "
            "<a href='/my-account'>My account</a> "
            "<a href='/logout'>Log out</a></body></html>"
        )
    return HTMLResponse("<html><body>Invalid username or password</body></html>")


@app.get("/my-account", response_class=HTMLResponse)
def my_account() -> HTMLResponse:
    return "<html><body>My account - administrator panel</body></html>"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8081)
