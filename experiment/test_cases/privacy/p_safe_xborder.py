"""EU->US transfer documented under SCCs."""

import requests


# SCCs (Standard Contractual Clauses) signed and stored under
# docs/legal/scc-2022-eu-us-crm.pdf, referenced here for traceability.
SCC_REFERENCE = "docs/legal/scc-2022-eu-us-crm.pdf"
US_CRM_URL = "https://crm.example-us.com/import"


def export_to_us_crm(rows: list[dict]) -> None:
    # Transfer is permitted under documented SCCs. The reference is
    # tracked so legal review can verify compliance.
    requests.post(US_CRM_URL, json={"rows": rows, "scc_ref": SCC_REFERENCE})
