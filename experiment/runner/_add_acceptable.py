# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Adds an `acceptable_findings` field to ground_truth.json for TP cases where the
SecPriv-Sonnet runs surface additional valid co-findings beyond the single
canonical ground-truth finding.

The list below was hand-audited against the actual code in test_cases/ — only
co-findings that genuinely describe a real defect in the file are credited.
Findings that require stretch interpretation (e.g., flagging auth_bypass on a
test-only redirect-setter) are NOT credited.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT_PATH = ROOT / "ground_truth.json"

# case_id -> list of additional acceptable findings (category, surface, line, severity)
# Lines are advisory — the matcher uses ±10-line tolerance.
ACCEPTABLE: dict[str, list[dict]] = {
    # P-TP-04: account creation forwards record to training pipeline.
    # Primary: consent_bypass. Co-finding: purpose_creep (account-creation data
    # collected for account purposes, but reused for ML training).
    "P-TP-04": [
        {
            "surface": "privacy",
            "category": "purpose_creep",
            "line": 22,
            "severity": "MEDIUM",
        },
    ],
    # P-TP-06: page-view tracker forwards raw email to third-party analytics.
    # Primary: third_party_sharing. Co-finding: consent_bypass (no consent
    # gate before sending PII to a third-party).
    "P-TP-06": [
        {
            "surface": "privacy",
            "category": "consent_bypass",
            "line": 17,
            "severity": "HIGH",
        },
    ],
    # P-TP-08: CSV export of zip + DOB + gender (quasi-identifiers).
    # Primary: re_identification_risk. Co-finding: pii_leakage (the CSV file is
    # a sink that emits raw PII columns).
    "P-TP-08": [
        {
            "surface": "privacy",
            "category": "pii_leakage",
            "line": 11,
            "severity": "HIGH",
        },
    ],
    # P-TP-09: subscription endpoint over-collects identity fields.
    # Primary: data_minimization. Co-findings: consent_bypass (no consent for
    # storing government_id), data_retention (SUBSCRIBERS is an indefinite
    # in-memory store).
    "P-TP-09": [
        {
            "surface": "privacy",
            "category": "consent_bypass",
            "line": 18,
            "severity": "MEDIUM",
        },
        {
            "surface": "privacy",
            "category": "data_retention",
            "line": 18,
            "severity": "MEDIUM",
        },
    ],
    # P-TP-10: shipping address re-used for ad targeting.
    # Primary: purpose_creep. Co-finding: consent_bypass (no consent for the
    # ad-targeting use of shipping data).
    "P-TP-10": [
        {
            "surface": "privacy",
            "category": "consent_bypass",
            "line": 24,
            "severity": "HIGH",
        },
    ],
    # S-TP-10: agent_csrf endpoint also lacks authentication.
    # Primary: agent_csrf. Co-finding: auth_bypass (no auth on /agent/run).
    "S-TP-10": [
        {
            "surface": "security",
            "category": "auth_bypass",
            "line": 13,
            "severity": "MEDIUM",
        },
    ],
    # X-TP-01: admin endpoint missing auth + raw PII shipped to third party.
    # Primary findings already include auth_bypass + third_party_sharing.
    # Co-finding: pii_leakage (raw email and IP transit through the response
    # body and the audit body — the same data is leaked in two places).
    "X-TP-01": [
        {
            "surface": "privacy",
            "category": "pii_leakage",
            "line": 17,
            "severity": "HIGH",
        },
    ],
}


def main() -> None:
    gt = json.loads(GT_PATH.read_text())
    n_added = 0
    for case in gt["cases"]:
        cid = case["case_id"]
        if cid in ACCEPTABLE:
            case["acceptable_findings"] = ACCEPTABLE[cid]
            n_added += len(ACCEPTABLE[cid])
    GT_PATH.write_text(json.dumps(gt, indent=2) + "\n")
    print(f"Added {n_added} acceptable co-findings across {len(ACCEPTABLE)} cases.")


if __name__ == "__main__":
    main()
