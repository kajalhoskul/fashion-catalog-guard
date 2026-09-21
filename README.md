# Fashion Catalog Guard

A live demo of a real-time bot/scraper/credential-stuffing defense layer,
built around a mock luxury fashion catalog site ("Maison Verdier"). This
targets two genuine problems the fashion industry actually pays security
vendors (Red Points, Corsearch, Bolster, Netcraft) to solve:

1. **Design theft via scraping** -- counterfeiters and fast-fashion
   copycats scrape a brand's site to copy unreleased designs before
   official launch.
2. **Account takeover via credential stuffing** -- e-commerce accounts
   (with stored payment info, loyalty points, personal data) are a
   standing target for leaked-credential attacks.

Rather than a log-analysis report, this is a **running app you attack**:
a FastAPI site with real middleware that scores every request and blocks
in real time, plus scripts that simulate realistic legitimate traffic and
three different attacks against it, plus a live security dashboard.

## Why this is more than IP-based rate limiting

Naive defenses block by IP address. That's trivially defeated by rotating
source IPs (see `attack_simulator/distributed_scraper.py`). This project
tracks **two independent identities** per request:

- `ip:<address>` -- the usual per-IP bucket
- `fp:<hash>` -- a **device fingerprint** derived from `User-Agent` +
  `Accept-Language` + `Accept-Encoding`, which stays constant even as an
  attacker rotates IPs

A scraper that rotates its IP every request never sends enough traffic
from any single IP to trip a per-IP limit or build up a scraping pattern
under that IP's history -- each rotation resets that bucket. But its HTTP
client's headers don't change between rotations, so the same behavioral
signals keep accumulating in the fingerprint bucket and still cross the
block threshold. Once a fingerprint is blocked, **every subsequent IP
presenting it is blocked immediately**, without re-accumulating anything.

## Detection signals

Implemented in `app/security/scoring.py`, combined so an attacker has to
defeat all of them simultaneously, not just one:

| Signal | What it catches |
|---|---|
| `honeypot` | An invisible link (`<a>` hidden via CSS) only a naive crawler that fetches every `href` would ever request |
| `high_rate` / `medium_rate` | Request rate in a 10s sliding window |
| `sequential_scrape` | Monotonically incrementing product-ID enumeration (`/product/1`, `/product/2`, ...) |
| `unreleased_targeting` | Repeated hits on the not-yet-launched collection |
| `suspicious_ua` | Known scraper/HTTP-library user agents (`python-requests`, `curl`, `HeadlessChrome`, ...) |
| `no_accept_language` | Header real browsers always send, scripts often skip |
| `regular_timing` | Near-constant inter-request interval (bots are often metronomic; humans are bursty) |
| `credential_stuffing_burst` / `_many_usernames` | Rapid-fire logins or many distinct usernames tried |

Each signal has a weight; a client is blocked (403, then 429 while the
block is active) once its combined score crosses a threshold. See
`app/security/middleware.py` for the demo's `X-Forwarded-For` trust model
and why it's a deliberate simplification (a real deployment must only
trust XFF from a known reverse proxy).

## Running it

```bash
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

Then in separate terminals:

```bash
# The site itself
open http://localhost:8000

# Live security operations dashboard
open http://localhost:8000/admin/dashboard

# Background legitimate traffic (should never get flagged/blocked)
python attack_simulator/legit_traffic.py --users 6 --duration 300

# A design-scraping bot (logs in, enumerates the full catalog + unreleased collection)
python attack_simulator/scraper_bot.py

# A credential-stuffing attack (many username/password combos, few source IPs)
python attack_simulator/credential_stuffing.py --attempts 40

# A more sophisticated IP-rotating scraper (defeats per-IP limiting, still caught by fingerprint)
python attack_simulator/distributed_scraper.py
```

Watch `/admin/dashboard` while these run: request rate, top clients by
threat score (with the specific reasons they were flagged), design-theft
attempts on the unreleased collection, and recent blocks, all updating
live every 2 seconds.

Demo accounts (in `app/data/products.json`): `amelia.stone` /
`TrenchC0at!92`, plus three others.

## Project layout

```
app/
  main.py                  FastAPI routes: catalog, login, unreleased collection, dashboard
  security/
    middleware.py           per-request scoring + real-time blocking (ASGI middleware)
    scoring.py               the behavioral signal weights and thresholds
    store.py                 in-memory request/session/score store
  templates/                 catalog + dashboard HTML
  data/products.json         catalog, unreleased collection, demo accounts
attack_simulator/
  legit_traffic.py           realistic human browsing (the false-positive test)
  scraper_bot.py             sequential catalog + unreleased-collection scraper
  credential_stuffing.py     rapid login attempts across many username/password combos
  distributed_scraper.py     IP-rotating scraper, defeats naive per-IP rate limiting
```

## What I'd do differently in production

- Back the store with Redis so scoring works across multiple app instances.
- Only trust `X-Forwarded-For` from a configured, trusted proxy IP list.
- Add a real fingerprinting signal (TLS/JA3, canvas/device fingerprint on
  the client) rather than just HTTP headers, which a determined attacker
  can also randomize.
- Log blocks to persistent storage for after-the-fact investigation, not
  just in-memory.
