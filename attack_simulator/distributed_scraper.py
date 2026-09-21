"""Simulates a MORE sophisticated scraper that rotates its source IP every
couple of requests (like a botnet or residential-proxy pool would), to
demonstrate why naive per-IP rate limiting fails: no single IP ever sends
enough requests to trip an IP-based rate limit, but the *behavioral*
fingerprint (sequential IDs, suspicious UA, honeypot, timing regularity)
is identical across all of them and still gets caught.

Usage:
    python distributed_scraper.py [--base-url http://127.0.0.1:8000]
"""
import argparse
import ipaddress
import random

import httpx

from common import CATALOG_IDS

POOL_SIZE = 40


def random_ip_pool(n: int):
    return [str(ipaddress.IPv4Address(random.randint(0x0B000000, 0xDF000000))) for _ in range(n)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    ip_pool = random_ip_pool(POOL_SIZE)
    print(f"[distributed-scraper] rotating across {len(ip_pool)} source IPs, "
          f"~2 requests per IP -- no single IP looks abusive on its own.")

    with httpx.Client(base_url=args.base_url, timeout=5.0) as client:
        for i, pid in enumerate(CATALOG_IDS):
            ip = ip_pool[i % len(ip_pool)]
            r = client.get(f"/product/{pid}", headers={"X-Forwarded-For": ip})
            print(f"  [{ip}] GET /product/{pid} -> {r.status_code}")
            if r.status_code in (403, 429):
                print(f"[distributed-scraper] {ip} BLOCKED -- behavioral fingerprint caught it "
                      f"even though this IP alone never exceeded a rate threshold.")

    print("[distributed-scraper] done. Check the dashboard: many distinct 'top clients' "
          "should show the same reasons (sequential_scrape, suspicious_ua) despite different IPs.")


if __name__ == "__main__":
    main()
