"""Intra-group transfer to a non-EU subsidiary with no BCRs in place."""

import requests


def push_to_us_subsidiary(records: list[dict]) -> None:
    # Even within the same corporate group, EU->US transfers require
    # BCRs (Art. 47), SCCs (Art. 46), or adequacy. Code shows none
    # of those mechanisms; raw PII is just POSTed.
    requests.post("https://intra.example-us.com/replicate", json={"records": records})


def replicate_users() -> None:
    push_to_us_subsidiary([{"id": 1, "email": "a@example.de"}])
