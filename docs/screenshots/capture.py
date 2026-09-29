#!/usr/bin/env python3
"""Capture README screenshots of the Grafana dashboards with a headless browser (Playwright).

Runs inside a one-off Playwright container on the nsm Docker network (docs/screenshots/capture.sh), so Grafana is reached
by container name and nothing is published. Authentication is a short-lived Viewer service-account token passed as a
header — never the admin password.

Privacy guard: before an image is saved, the rendered page text is checked for addresses that must not be published
(the dashboard user's own networks, NSM_SCREENSHOT_DENY, comma-separated prefixes). A match aborts that screenshot.
"""
import os
import re
import sys
import time
from datetime import datetime

from playwright.sync_api import sync_playwright

GRAFANA = os.environ.get("GRAFANA_URL", "http://nsm-grafana:3000")
TOKEN = os.environ["GRAFANA_TOKEN"]
OUT = os.environ.get("OUT_DIR", "/out")
DENY = [p for p in os.environ.get("NSM_SCREENSHOT_DENY", "").split(",") if p]

# uid, file name, a panel title that proves the dashboard rendered, time range without private addresses, page height
SHOTS = [
    ("nsm-live-traffic", "traffic-overview", "Connections by direction", "from=2026-09-14T08:00:00Z&to=2026-09-15T04:00:00Z", 2300),
    ("nsm-alerts", "alerts", "Top signatures", "from=2026-09-14T08:00:00Z&to=2026-09-15T04:00:00Z", 3000),
    ("nsm-c2-hunt", "c2-hunt", "Most regular outbound pairs", "from=2026-09-14T08:00:00Z&to=2026-09-15T04:00:00Z", 2900),
    ("nsm-dns", "dns", "Top registered domains", "from=2026-09-14T08:00:00Z&to=2026-09-15T04:00:00Z", 2500),
    ("nsm-honeypot", "honeypot", "Top username:password pairs", "from=2026-09-14T08:00:00Z&to=2026-09-15T08:00:00Z", 2000),
    ("nsm-response", "response", "Decision log", "from=2026-09-14T06:00:00Z&to=2026-09-15T04:10:00Z&var-mode=dry-run", 2700),
    ("nsm-soc-kpi", "soc-kpi", "ATT&CK coverage", "from=now-7d&to=now", 3100),
    ("nsm-attack-map", "attack-map", "Where the attacks come from", "from=now-30d&to=now", 2400),
]


def grafana_range(query):
    """Grafana 13 reads absolute from/to in the URL as epoch milliseconds; ISO strings turn into 1970-01-01."""
    def to_ms(m):
        ts = datetime.strptime(m.group(2), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=__import__("datetime").timezone.utc)
        return f"{m.group(1)}={int(ts.timestamp() * 1000)}"
    return re.sub(r"\b(from|to)=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", to_ms, query)


def main():
    failed = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        for uid, name, expect, query, height in SHOTS:
            # An explicit locale is required: without one Grafana's bootstrap throws "Incorrect locale information provided"
            # in Intl.NumberFormat and shows its "failed to load application files" page instead of the dashboard.
            context = browser.new_context(viewport={"width": 1600, "height": height}, device_scale_factor=1, locale="en-US",
                                          timezone_id="UTC", extra_http_headers={"Authorization": f"Bearer {TOKEN}"}, color_scheme="dark")
            page = context.new_page()
            page.goto(f"{GRAFANA}/d/{uid}?orgId=1&kiosk&{grafana_range(query)}", wait_until="networkidle", timeout=120_000)
            time.sleep(14)  # panels render after their queries return; map tiles arrive later still
            text = page.inner_text("body")
            leaked = [d for d in DENY if d in text]
            # Check rendering first: an error page has no private data either, so the privacy check alone would pass it.
            empty = text.count("No data") + text.count("No rows")
            if expect not in text or "failed to load its application files" in text:
                print(f"FAIL {name}: dashboard not rendered (no '{expect}' in the page)", flush=True)
                failed += 1
            elif "1970-01-01" in text or empty > 4:
                print(f"FAIL {name}: time range not applied or mostly empty ({empty} empty panels)", flush=True)
                failed += 1
            elif leaked:
                print(f"SKIP {name}: page text contains a denied prefix {leaked}", flush=True)
                failed += 1
            else:
                path = os.path.join(OUT, f"{name}.png")
                page.screenshot(path=path, full_page=True)
                print(f"saved {path}", flush=True)
            context.close()
        browser.close()
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
