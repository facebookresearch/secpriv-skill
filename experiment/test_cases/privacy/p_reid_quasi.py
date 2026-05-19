"""Public health-data export — releases quasi-identifiers in the clear."""

import csv


def export_records(records: list[dict], path: str) -> None:
    # zip + DOB + gender uniquely identifies ~87% of the US population.
    # Releasing this triple constitutes re-identification risk.
    fields = ["zip", "date_of_birth", "gender", "diagnosis"]
    with open(path, "w") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r[k] for k in fields})
