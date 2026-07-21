# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Semgrep baseline for the D3 real-CVE probe (reviewer D2: fair baseline).

Runs Semgrep (OSS rulesets p/security-audit + p/owasp-top-ten) over the same
pre/post files as the SecPriv runs, maps each Semgrep finding's CWE to a SecPriv
canonical category (same CWE map as ingest_cve.py), and writes results in the
exact shape evaluate.py produces -- so score_cve_probe.py scores Semgrep with the
identical tiered/family-aware metric. This is the apples-to-apples comparison.

Semgrep is not on the devserver by default; install into a venv:
    /usr/bin/python3 -m venv /tmp/sast_venv
    https_proxy=http://fwdproxy:8080 /tmp/sast_venv/bin/pip install semgrep
Run:
    SEMGREP=/tmp/sast_venv/bin/semgrep python3 runner/run_semgrep_baseline.py
Then:
    python3 runner/score_cve_probe.py cve_semgrep
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from ingest_cve import CWE_CATEGORY  # reuse the exact same CWE->category map

EXPERIMENT = Path(__file__).resolve().parent.parent
SEMGREP = os.environ.get("SEMGREP", "semgrep")
CONFIGS = ["p/security-audit", "p/owasp-top-ten"]
CWE_RE = re.compile(r"(CWE-\d+)")
PROXY = {"https_proxy": "http://fwdproxy:8080", "http_proxy": "http://fwdproxy:8080"}


def _cwe_to_category(md: dict) -> str | None:
    cwes = md.get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    for entry in cwes:
        m = CWE_RE.search(entry or "")
        if m and m.group(1) in CWE_CATEGORY:
            return CWE_CATEGORY[m.group(1)]
    return None


def _scan(path: Path) -> list[dict]:
    cmd = [
        SEMGREP,
        *sum((["--config", c] for c in CONFIGS), []),
        "--json",
        "--quiet",
        str(path),
    ]
    env = {**os.environ, **PROXY}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"Semgrep timeout on {path}", file=sys.stderr)
        return []
    if not proc.stdout.strip():
        return []
    findings = []
    for r in json.loads(proc.stdout).get("results", []):
        md = r.get("extra", {}).get("metadata", {})
        cat = _cwe_to_category(md)
        findings.append(
            {
                "category": cat or r["check_id"].split(".")[-1],
                "line": r["start"]["line"],
                "file": Path(r["path"]).name,
            }
        )
    return findings


def main() -> None:
    gt = json.loads((EXPERIMENT / "ground_truth_cve.json").read_text())["cases"]
    out_cases = []
    for c in gt:
        findings = []
        for rel in c["files"]:
            findings.extend(_scan(EXPERIMENT / rel))
        out_cases.append(
            {
                "case_id": c["case_id"],
                "raw_output": json.dumps(findings),
                "latency_s": 0,
            }
        )
        print(f"  {c['case_id'][:6]} {c['kind']:12s} findings={len(findings)}")
    out_dir = EXPERIMENT / "results" / "semgrep"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "cve_semgrep.json").write_text(
        json.dumps({"config": "semgrep", "cases": out_cases}, indent=2) + "\n"
    )
    print(f"\nwrote {len(out_cases)} cases -> {out_dir / 'cve_semgrep.json'}")


if __name__ == "__main__":
    main()
