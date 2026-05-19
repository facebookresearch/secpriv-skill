"""Public CSV export drops the email column."""

import csv


EXPORT_FIELDS = ["id", "country", "signup_year"]


def export_users(rows: list[dict], path: str) -> None:
    # Email and other PII fields are explicitly excluded from the
    # public export — minimization at the sink.
    with open(path, "w") as f:
        w = csv.DictWriter(f, fieldnames=EXPORT_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in EXPORT_FIELDS})
