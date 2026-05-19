# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Daily PII export from EU-resident customers to a US-based CRM."""

import requests


US_CRM_URL = "https://crm.example-us.com/import"


def eu_customers() -> list[dict]:
    return [{"id": 1, "email": "alice@example.de", "country": "DE"}]


def nightly_export() -> None:
    data = eu_customers()
    # Cross-border transfer EU -> US with no Standard Contractual
    # Clauses, no Binding Corporate Rules, no adequacy decision —
    # GDPR Art. 44-49 violation.
    requests.post(US_CRM_URL, json={"customers": data})
