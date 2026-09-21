"""Behavioral bot-scoring engine.

Deliberately does NOT rely on IP address alone -- naive per-IP rate
limiting is trivially defeated by rotating source IPs (see
attack_simulator/distributed_scraper.py). Instead it combines several
independent behavioral signals so that an attacker has to defeat all of
them simultaneously, not just one:

  - honeypot            an invisible link only a naive crawler would fetch
  - high/medium_rate     request rate in a short sliding window
  - sequential_scrape    monotonically incrementing product-id enumeration
  - unreleased_targeting repeated hits on the not-yet-launched collection
  - suspicious_ua        known scraper/HTTP-library user agents
  - no_accept_language   header real browsers always send, scripts often don't
  - regular_timing       near-constant inter-request interval (humans are bursty/irregular)
  - credential_stuffing_* rapid-fire logins or many distinct usernames tried
"""
import time

from .store import BLOCK_SECONDS, SecurityStore, interval_stddev, is_monotonic_sequence

RATE_WINDOW = 10
RATE_THRESHOLD_HIGH = 15
RATE_THRESHOLD_MED = 8
BLOCK_THRESHOLD = 8.0

SUSPICIOUS_UA_MARKERS = [
    "python-requests", "python-httpx", "curl", "headlesschrome",
    "phantomjs", "scrapy", "wget", "bot", "okhttp",
]

WEIGHTS = {
    "honeypot": 10.0,
    "high_rate": 4.0,
    "medium_rate": 2.0,
    "sequential_scrape": 4.0,
    "unreleased_targeting": 3.0,
    "suspicious_ua": 2.5,
    "no_accept_language": 1.0,
    "regular_timing": 2.0,
    "credential_stuffing_burst": 6.0,
    "credential_stuffing_many_usernames": 5.0,
}


def evaluate(
    store: SecurityStore,
    key: str,
    headers: dict,
    product_id: int | None = None,
    is_unreleased: bool = False,
    is_honeypot: bool = False,
    is_login: bool = False,
    username: str | None = None,
):
    now = time.time()
    with store.lock():
        client = store.client(key)
        store.record_request(key, "product" if product_id else "other", now)

        reasons = set()

        if is_honeypot:
            client.honeypot_hits += 1
            reasons.add("honeypot")

        recent = [ts for ts, _ in client.events if now - ts <= RATE_WINDOW]
        if len(recent) >= RATE_THRESHOLD_HIGH:
            reasons.add("high_rate")
        elif len(recent) >= RATE_THRESHOLD_MED:
            reasons.add("medium_rate")

        if product_id is not None:
            client.product_ids_seen.append(product_id)
            if is_monotonic_sequence(client.product_ids_seen):
                reasons.add("sequential_scrape")

        if is_unreleased:
            client.unreleased_hits += 1
            if client.unreleased_hits >= 2:
                reasons.add("unreleased_targeting")

        ua = (headers.get("user-agent") or "").lower()
        if not ua or any(m in ua for m in SUSPICIOUS_UA_MARKERS):
            reasons.add("suspicious_ua")
        if not headers.get("accept-language"):
            reasons.add("no_accept_language")

        stddev = interval_stddev(client.events)
        if 0 <= stddev < 0.15 and len(client.events) >= 6:
            reasons.add("regular_timing")

        if is_login:
            client.login_attempts.append(now)
            if username:
                client.login_usernames_tried.add(username)
            recent_logins = [t for t in client.login_attempts if now - t <= RATE_WINDOW]
            if len(recent_logins) >= 5:
                reasons.add("credential_stuffing_burst")
            if len(client.login_usernames_tried) >= 4:
                reasons.add("credential_stuffing_many_usernames")

        client.reasons = reasons
        client.score = sum(WEIGHTS[r] for r in reasons)

        blocked = False
        if client.score >= BLOCK_THRESHOLD and client.blocked_until <= now:
            client.blocked_until = now + BLOCK_SECONDS
            blocked = True
            store.record_block(key, reasons, now)

        return client.score, reasons, blocked


def is_currently_blocked(store: SecurityStore, key: str) -> bool:
    with store.lock():
        client = store.client(key)
        return client.blocked_until > time.time()
