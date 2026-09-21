"""ASGI middleware that scores every request for bot/scraper behavior and
blocks clients that cross the threshold, in real time.

Tracks TWO independent identities per request:
  - ip:<address>   the usual per-IP bucket
  - fp:<hash>      a header-derived "device fingerprint" (User-Agent +
                    Accept-Language + Accept-Encoding) that stays constant
                    even as an attacker rotates source IPs

A pure IP-rotating scraper (see attack_simulator/distributed_scraper.py)
never sends enough requests from any single IP to trip an IP-keyed rate
limit or build up a sequential-scrape pattern under any one IP -- each
rotation resets that bucket's history. The fingerprint bucket doesn't
reset, because the client's HTTP library/headers don't change between
rotations, so the same behavioral signals (sequential IDs, suspicious UA,
honeypot hit) keep accumulating there and still cross the block threshold.
Once a fingerprint is blocked, every subsequent IP presenting it is
blocked immediately too, without needing to re-accumulate anything.
"""
import hashlib
import re
import time
from urllib.parse import parse_qs

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import scoring
from .store import SecurityStore

PRODUCT_RE = re.compile(r"^/product/(\d+)$")
UNRELEASED_RE = re.compile(r"^/collection/unreleased/(\d+)$")
HONEYPOT_PATH = "/trap/secret-preview"


def ip_key(request: Request) -> str:
    # DEMO SIMPLIFICATION: trusts X-Forwarded-For unconditionally so the
    # attack simulators can demonstrate IP-based attacks against a single
    # local process. A real deployment must only trust XFF from a known,
    # trusted reverse proxy -- otherwise an attacker can spoof this header
    # to reset their own reputation on every request, which is exactly the
    # evasion attack_simulator/distributed_scraper.py demonstrates.
    forwarded = request.headers.get("x-forwarded-for")
    address = forwarded.split(",")[0].strip() if forwarded else (
        request.client.host if request.client else "unknown"
    )
    return f"ip:{address}"


def fingerprint_key(request: Request) -> str:
    parts = "|".join([
        request.headers.get("user-agent", ""),
        request.headers.get("accept-language", ""),
        request.headers.get("accept-encoding", ""),
    ])
    digest = hashlib.sha256(parts.encode()).hexdigest()[:10]
    return f"fp:{digest}"


class BotDefenseMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, store: SecurityStore):
        super().__init__(app)
        self.store = store

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path.startswith("/admin") or path.startswith("/static"):
            return await call_next(request)

        keys = [ip_key(request), fingerprint_key(request)]

        if any(scoring.is_currently_blocked(self.store, k) for k in keys):
            return JSONResponse(
                {"detail": "Too many requests. Access temporarily blocked."},
                status_code=429,
                headers={"Retry-After": "60"},
            )

        product_id = None
        is_unreleased = False
        if m := PRODUCT_RE.match(path):
            product_id = int(m.group(1))
        elif m := UNRELEASED_RE.match(path):
            product_id = int(m.group(1))
            is_unreleased = True

        is_honeypot = path == HONEYPOT_PATH
        is_login = path == "/login" and request.method == "POST"
        username = None
        if is_login:
            # Read raw bytes rather than request.form(): Starlette caches
            # body() for replay to the downstream handler via call_next,
            # but consuming the stream through form()'s multipart/urlencoded
            # parser here leaves nothing for the route handler to re-parse.
            body_bytes = await request.body()
            form_data = parse_qs(body_bytes.decode("utf-8", errors="ignore"))
            username = (form_data.get("username") or [None])[0]

        headers = dict(request.headers)
        max_score, all_reasons, any_blocked = 0.0, set(), False
        for key in keys:
            score, reasons, blocked = scoring.evaluate(
                self.store,
                key,
                headers,
                product_id=product_id,
                is_unreleased=is_unreleased,
                is_honeypot=is_honeypot,
                is_login=is_login,
                username=username,
            )
            max_score = max(max_score, score)
            all_reasons |= reasons
            any_blocked = any_blocked or blocked

        if is_unreleased and product_id is not None and all_reasons:
            self.store.record_design_theft(keys[0], product_id, time.time())

        if is_login and ({"credential_stuffing_burst", "credential_stuffing_many_usernames"} & all_reasons):
            self.store.record_credential_stuffing(keys[0], username or "", time.time())

        if any_blocked:
            return JSONResponse(
                {"detail": "Suspicious activity detected. Access blocked.", "reasons": sorted(all_reasons)},
                status_code=403,
            )

        response = await call_next(request)
        response.headers["X-Bot-Score"] = str(round(max_score, 1))
        return response
