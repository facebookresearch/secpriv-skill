# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Tag each benchmark category (and case) with the review *mechanism* it needs.

ACSAC reviewer 531A-1 / director point D1: the source-to-sink flow reasoning that
SecPriv unifies covers only a *subset* of security + privacy review. This script
records that subset explicitly so results can be reported in-scope
(``source_to_sink``) vs. out-of-scope (``authz_logic``, ``crypto``,
``concurrency``, ``resource``, ``policy_temporal`` -- the classes reviewer 531A
named as NOT covered by source-to-sink reasoning).

It is non-destructive: it writes two side maps next to ``ground_truth.json`` and
does not rewrite that file (avoiding a large reformat diff). ``aggregate.py`` /
``rescore.py`` can join on category or case_id to split recall by mechanism.
Idempotent.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

EXPERIMENT_DIR: Path = Path(__file__).resolve().parent.parent
GT_PATH: Path = EXPERIMENT_DIR / "ground_truth.json"
MECH_MAP_PATH: Path = EXPERIMENT_DIR / "mechanism_map.json"
CASE_MECH_PATH: Path = EXPERIMENT_DIR / "case_mechanism.json"

IN_SCOPE: str = "source_to_sink"

# Category -> review mechanism. In-scope for the unification claim = the shared
# source-to-sink flow reasoning; everything else is a mechanism reviewer 531A
# named as out of scope (authz logic, crypto misuse, race conditions, plus
# resource-exhaustion and temporal/policy obligations).
CATEGORY_MECHANISM: dict[str, str] = {
    # --- source_to_sink (in scope) : 20 ---
    "sql_injection": IN_SCOPE,
    "command_injection": IN_SCOPE,
    "path_traversal": IN_SCOPE,
    "xss": IN_SCOPE,
    "xss_dom": IN_SCOPE,
    "deserialization": IN_SCOPE,
    "eval_injection": IN_SCOPE,
    "ssrf": IN_SCOPE,
    "open_redirect": IN_SCOPE,
    "xxe": IN_SCOPE,
    "ssti": IN_SCOPE,
    "insecure_logging": IN_SCOPE,
    "second_order_sqli": IN_SCOPE,
    "hardcoded_secret": IN_SCOPE,
    "pii_leakage": IN_SCOPE,
    "insecure_storage": IN_SCOPE,
    "re_identification_risk": IN_SCOPE,
    "third_party_sharing": IN_SCOPE,
    "cross_border_transfer": IN_SCOPE,
    "data_minimization": IN_SCOPE,
    # --- out of scope : 10 ---
    "auth_bypass": "authz_logic",
    "csrf": "authz_logic",
    "agent_csrf": "authz_logic",
    "crypto_misuse": "crypto",
    "race_condition": "concurrency",
    "infinite_loop": "resource",
    "consent_bypass": "policy_temporal",
    "purpose_creep": "policy_temporal",
    "data_retention": "policy_temporal",
    "right_to_erasure": "policy_temporal",
}


def case_mechanism(case: dict) -> str:
    """Mechanism of a case: from its expected findings; TN cases -> ``tn``."""
    findings = case.get("expected_findings", [])
    if not findings:
        return "tn"
    mechs = {CATEGORY_MECHANISM.get(f.get("category", ""), "unknown") for f in findings}
    return next(iter(mechs)) if len(mechs) == 1 else "mixed"


def main() -> None:
    gt = json.loads(GT_PATH.read_text())
    cases = gt["cases"]

    seen = {f["category"] for c in cases for f in c.get("expected_findings", [])}
    unmapped = sorted(seen - set(CATEGORY_MECHANISM))
    if unmapped:
        raise ValueError(f"categories missing from CATEGORY_MECHANISM: {unmapped}")

    case_map = {c["case_id"]: case_mechanism(c) for c in cases}
    MECH_MAP_PATH.write_text(json.dumps(CATEGORY_MECHANISM, indent=2) + "\n")
    CASE_MECH_PATH.write_text(json.dumps(case_map, indent=2) + "\n")

    n_in = sum(1 for m in CATEGORY_MECHANISM.values() if m == IN_SCOPE)
    n_out = len(CATEGORY_MECHANISM) - n_in
    print(f"categories: {len(CATEGORY_MECHANISM)} ({n_in} in-scope, {n_out} out)")
    print("category mechanisms:", dict(Counter(CATEGORY_MECHANISM.values())))
    print("case mechanisms:", dict(Counter(case_map.values())))
    print(f"wrote {MECH_MAP_PATH}")
    print(f"wrote {CASE_MECH_PATH}")


if __name__ == "__main__":
    main()
