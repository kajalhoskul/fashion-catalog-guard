"""Simulates ordinary human shoppers: random browsing, realistic delays,
real browser user agents, occasional login. This is the "background noise"
the defense system must NOT flag.

Usage:
    python legit_traffic.py [--base-url http://127.0.0.1:8000] [--users 5] [--duration 120]
"""
import argparse
import random
import threading
import time

import httpx

from common import CATALOG_IDS, REAL_BROWSER_UAS


def simulate_user(base_url: str, user_id: int, stop_at: float):
    ua = random.choice(REAL_BROWSER_UAS)
    fake_ip = f"192.168.1.{100 + user_id}"
    headers = {"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9", "X-Forwarded-For": fake_ip}

    with httpx.Client(base_url=base_url, headers=headers, timeout=5.0) as client:
        while time.time() < stop_at:
            try:
                client.get("/")
                time.sleep(random.uniform(0.8, 2.5))
                for _ in range(random.randint(1, 4)):
                    pid = random.choice(CATALOG_IDS)
                    client.get(f"/product/{pid}")
                    time.sleep(random.uniform(1.0, 4.0))
            except httpx.HTTPError:
                pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--users", type=int, default=5)
    parser.add_argument("--duration", type=float, default=120)
    args = parser.parse_args()

    stop_at = time.time() + args.duration
    threads = [
        threading.Thread(target=simulate_user, args=(args.base_url, i, stop_at), daemon=True)
        for i in range(args.users)
    ]
    for t in threads:
        t.start()
    print(f"[legit] {args.users} simulated shoppers browsing for {args.duration:.0f}s...")
    for t in threads:
        t.join()
    print("[legit] done.")


if __name__ == "__main__":
    main()
