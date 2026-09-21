"""In-memory request/session store backing the bot defense system.

A real deployment would back this with Redis (shared across app instances);
in-memory is fine for a single-process demo and keeps the project
dependency-free.
"""
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

WINDOW_SECONDS = 30
BLOCK_SECONDS = 60
MAX_EVENTS_PER_CLIENT = 200


@dataclass
class ClientState:
    events: deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_CLIENT))
    product_ids_seen: deque = field(default_factory=lambda: deque(maxlen=50))
    login_attempts: deque = field(default_factory=lambda: deque(maxlen=100))
    login_usernames_tried: set = field(default_factory=set)
    honeypot_hits: int = 0
    unreleased_hits: int = 0
    score: float = 0.0
    reasons: set = field(default_factory=set)
    blocked_until: float = 0.0


class SecurityStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients: dict[str, ClientState] = defaultdict(ClientState)
        self._global_requests: deque = deque(maxlen=5000)
        self._blocks_log: deque = deque(maxlen=200)
        self._design_theft_log: deque = deque(maxlen=200)
        self._credential_stuffing_log: deque = deque(maxlen=200)

    def client(self, key: str) -> ClientState:
        return self._clients[key]

    def lock(self):
        return self._lock

    def record_request(self, key: str, path: str, ts: float):
        self._global_requests.append(ts)
        self._clients[key].events.append((ts, path))

    def record_block(self, key: str, reasons, ts: float):
        self._blocks_log.append({"key": key, "reasons": sorted(reasons), "ts": ts})

    def record_design_theft(self, key: str, product_id: int, ts: float):
        self._design_theft_log.append({"key": key, "product_id": product_id, "ts": ts})

    def record_credential_stuffing(self, key: str, username: str, ts: float):
        self._credential_stuffing_log.append({"key": key, "username": username, "ts": ts})

    def requests_last_n_seconds(self, n: int) -> int:
        cutoff = time.time() - n
        return sum(1 for ts in self._global_requests if ts >= cutoff)

    def requests_per_second_series(self, seconds: int = 60):
        now = time.time()
        buckets = [0] * seconds
        for ts in self._global_requests:
            age = now - ts
            if 0 <= age < seconds:
                buckets[seconds - 1 - int(age)] += 1
        return buckets

    def top_clients(self, n: int = 10):
        with self._lock:
            ranked = sorted(self._clients.items(), key=lambda kv: kv[1].score, reverse=True)
        out = []
        for key, state in ranked[:n]:
            if state.score <= 0:
                continue
            out.append({
                "key": key,
                "score": round(state.score, 1),
                "reasons": sorted(state.reasons),
                "requests": len(state.events),
                "blocked": state.blocked_until > time.time(),
            })
        return out

    def totals(self):
        return {
            "total_requests": len(self._global_requests),
            "active_blocks": sum(1 for c in self._clients.values() if c.blocked_until > time.time()),
            "total_blocks_ever": len(self._blocks_log),
            "honeypot_hits": sum(c.honeypot_hits for c in self._clients.values()),
            "design_theft_attempts": len(self._design_theft_log),
            "credential_stuffing_events": len(self._credential_stuffing_log),
        }

    def recent_design_theft(self, n: int = 10):
        return list(self._design_theft_log)[-n:][::-1]

    def recent_blocks(self, n: int = 10):
        return list(self._blocks_log)[-n:][::-1]


def interval_stddev(events: deque) -> float:
    timestamps = [ts for ts, _ in events]
    if len(timestamps) < 4:
        return -1.0
    intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
    try:
        return statistics.pstdev(intervals)
    except statistics.StatisticsError:
        return -1.0


def is_monotonic_sequence(ids: deque, min_run: int = 4) -> bool:
    values = list(ids)
    if len(values) < min_run:
        return False
    run = 1
    best = 1
    for a, b in zip(values, values[1:]):
        if b == a + 1:
            run += 1
            best = max(best, run)
        else:
            run = 1
    return best >= min_run
