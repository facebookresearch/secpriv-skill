"""Reports k-aggregated city counts to a third-party analytics endpoint."""

from collections import Counter

import requests

ANALYTICS_URL = "https://analytics.example.com/aggregate"
K_THRESHOLD = 50


def report_city_counts(rows: list[dict]) -> None:
    counts = Counter(r["city"] for r in rows)
    # Only emits buckets with at least K_THRESHOLD members — k-aggregation.
    report = {city: n for city, n in counts.items() if n >= K_THRESHOLD}
    if not report:
        return
    requests.post(ANALYTICS_URL, json={"by_city": report})
