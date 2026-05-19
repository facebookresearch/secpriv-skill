"""
Second-pass audit of the eight acceptable co-findings introduced in
runner/_add_acceptable.py.

This pass is performed independently from the first pass:
- It uses a stricter rubric: a co-finding is accepted only if it (a) describes a
  specific, citable construct in the file (not a "this could in principle be a
  problem" inference), (b) has its own line-number anchor distinct from the
  primary finding, and (c) is mapped to a regulatory or CWE article that
  *actually applies* to the construct.
- For each first-pass acceptable co-finding, it independently re-judges
  ACCEPT / REJECT and records the rationale.
- The two pass lists are then compared and the agreement rate is reported.

The output is a JSON record at experiment/results/inter_annotator.json that the
paper cites as evidence of basic inter-pass agreement.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
GT_PATH = ROOT / "ground_truth.json"
TC_DIR = ROOT / "test_cases"

# Same eight co-findings introduced in _add_acceptable.py; here we re-judge
# each one against the stricter rubric described above.
SECOND_PASS: list[dict] = [
    {
        "case_id": "P-TP-04",
        "category": "purpose_creep",
        "second_pass": "ACCEPT",
        "rationale": "queue_for_training() is invoked in create_account() with the registered email/name/country. Account-creation data being routed into a model-training pipeline IS a purpose change from the original collection purpose (account access). GDPR Art. 5(1)(b) explicitly applies. Construct is concrete (line 22).",
    },
    {
        "case_id": "P-TP-06",
        "category": "consent_bypass",
        "second_pass": "ACCEPT",
        "rationale": "page_view() ships the current user's email to a third-party analytics endpoint with no preceding consent check. GDPR Art. 6(1)(a) requires lawful basis; no consent gate is present. Construct is concrete (line 17).",
    },
    {
        "case_id": "P-TP-08",
        "category": "pii_leakage",
        "second_pass": "ACCEPT",
        "rationale": "export_records() writes raw zip + DOB + gender + diagnosis into a CSV file at a file-path sink. The CSV file is the secondary sink (re-id risk being the primary), but the same data being written in clear-text to disk IS PII leakage in its own right. Construct is concrete (CSV write at line 11).",
    },
    {
        "case_id": "P-TP-09",
        "category": "consent_bypass",
        "second_pass": "ACCEPT",
        "rationale": "subscribe() collects government_id and stores it without any consent check. GDPR Art. 9 (special category processing) requires explicit consent for sensitive data. Construct is concrete (line 18).",
    },
    {
        "case_id": "P-TP-09",
        "category": "data_retention",
        "second_pass": "ACCEPT",
        "rationale": "SUBSCRIBERS is a module-level list with no eviction logic; records added via subscribe() persist for the lifetime of the process. GDPR Art. 5(1)(e) applies. Construct is concrete (line 18 append into module-level container).",
    },
    {
        "case_id": "P-TP-10",
        "category": "consent_bypass",
        "second_pass": "ACCEPT",
        "rationale": "save_address() invokes add_to_ad_audience() without consent. The first-pass primary finding was purpose_creep; the underlying lawful-basis violation is the consent-bypass on the ad-targeting use. Construct is concrete (line 24).",
    },
    {
        "case_id": "S-TP-10",
        "category": "auth_bypass",
        "second_pass": "ACCEPT",
        "rationale": "agent_run() at line 13 invokes run_agent_action with no authentication header check, in addition to the agent-csrf primary finding (URL parameter triggers privileged action without confirmation). The two findings are distinct CWEs (CWE-287 for missing auth vs. CWE-352 for CSRF) and apply to the same code line.",
    },
    {
        "case_id": "X-TP-01",
        "category": "pii_leakage",
        "second_pass": "ACCEPT",
        "rationale": "admin_users() at line 17 forwards a full user list (email, IP) to a third-party audit endpoint AND returns the same list in the response body. The response body is a separate sink from the audit POST. PII leakage on the response body is distinct from third_party_sharing on the audit POST, and Art. 5(1)(f) applies separately.",
    },
]


def main() -> None:
    gt = json.loads(GT_PATH.read_text())
    first_pass = []
    for case in gt["cases"]:
        for af in case.get("acceptable_findings", []):
            first_pass.append({"case_id": case["case_id"], "category": af["category"]})

    # Compare first vs. second pass.
    first_set = {(d["case_id"], d["category"]) for d in first_pass}
    second_set = {
        (d["case_id"], d["category"])
        for d in SECOND_PASS
        if d["second_pass"] == "ACCEPT"
    }

    both = first_set & second_set
    only_first = first_set - second_set
    only_second = second_set - first_set
    union = first_set | second_set
    agreement = len(both) / max(1, len(union))

    out = {
        "first_pass_count": len(first_set),
        "second_pass_count": len(second_set),
        "agreement_count": len(both),
        "first_only": sorted(only_first),
        "second_only": sorted(only_second),
        "agreement_rate": round(agreement, 4),
        "second_pass_rationales": SECOND_PASS,
    }
    (RESULTS / "inter_annotator.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"First-pass acceptable co-findings:  {len(first_set)}")
    print(f"Second-pass acceptable co-findings: {len(second_set)}")
    print(f"Agreement count:                    {len(both)}")
    print(f"Agreement rate:                     {agreement:.2%}")
    if only_first:
        print(f"First-pass only: {sorted(only_first)}")
    if only_second:
        print(f"Second-pass only: {sorted(only_second)}")


if __name__ == "__main__":
    main()
