"""Simulates a design-scraping bot: logs in with a compromised/leaked
account, then rapidly enumerates every catalog product AND the unreleased
Spring Capsule collection in strict sequential order, with almost no
delay between requests, using the default python-httpx user agent. This
is the "someone is copying our designs before launch" scenario.

Usage:
    python scraper_bot.py [--base-url http://127.0.0.1:8000]
"""
import argparse

import httpx

from common import CATALOG_IDS, UNRELEASED_IDS

SOURCE_IP = "203.0.113.7"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    headers = {"X-Forwarded-For": SOURCE_IP}  # default python-httpx UA left intact, deliberately
    with httpx.Client(base_url=args.base_url, headers=headers, timeout=5.0) as client:
        print(f"[scraper] logging in with leaked credentials from {SOURCE_IP} ...")
        client.post("/login", data={"username": "amelia.stone", "password": "TrenchC0at!92", "next": "/"})

        print("[scraper] enumerating full public catalog...")
        for pid in CATALOG_IDS:
            r = client.get(f"/product/{pid}")
            print(f"  GET /product/{pid} -> {r.status_code}")
            if r.status_code in (403, 429):
                print("[scraper] BLOCKED by defense system.")
                return

        print("[scraper] enumerating unreleased Spring Capsule collection...")
        for pid in UNRELEASED_IDS:
            r = client.get(f"/collection/unreleased/{pid}")
            print(f"  GET /collection/unreleased/{pid} -> {r.status_code}")
            if r.status_code in (403, 429):
                print("[scraper] BLOCKED by defense system.")
                return

        print("[scraper] following every link found on the page, including hidden ones...")
        r = client.get("/trap/secret-preview")
        print(f"  GET /trap/secret-preview -> {r.status_code}")
        if r.status_code in (403, 429):
            print("[scraper] BLOCKED by defense system.")
        else:
            print("[scraper] finished run without being blocked.")


if __name__ == "__main__":
    main()
