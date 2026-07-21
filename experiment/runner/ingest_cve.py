# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Build a real-world CVE probe (D3 external-validity) from public GitHub data.

No hand-labeling: labels are patch-derived. For each reviewed GitHub advisory
that (a) maps to a SecPriv canonical category via its CWE and (b) links a fix
commit, we fetch the changed in-scope code file(s) at the parent SHA (vulnerable
= true positive at the patched hunk) and at the fix SHA (fixed = true negative).
This is a paired diff test and yields real, multi-language, sometimes multi-file
cases with natural, defect-free negatives. Security-only (no public privacy-at-
code dataset exists). Writes files under experiment/probe_cve/ (gitignored) and
ground_truth_cve.json. Stdlib-only; fetches via the ambient proxy.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path

EXPERIMENT_DIR: Path = Path(__file__).resolve().parent.parent
PROBE_DIR: Path = EXPERIMENT_DIR / "probe_cve"
GT_OUT: Path = EXPERIMENT_DIR / "ground_truth_cve.json"

# Optional GitHub PAT (public read-only). Unauthenticated = 60 req/hr (caps the
# pilot at ~15 CVEs); a token raises it to 5000/hr, enough for N>=100.
GITHUB_TOKEN: str | None = os.environ.get("GITHUB_TOKEN")
# How many CVEs to build; override with GITHUB_PROBE_N (needs a token past ~15).
TARGET_N: int = int(os.environ.get("GITHUB_PROBE_N", "15"))
# Advisory pages to pull per ecosystem (100/page); more pages -> more candidates.
PAGES: int = int(os.environ.get("GITHUB_PROBE_PAGES", "1"))
# Build filters (raise to increase yield at the cost of noisier/larger cases).
MAX_CHANGED: int = int(os.environ.get("GITHUB_PROBE_MAX_CHANGED", "60"))
MAX_LOC: int = int(os.environ.get("GITHUB_PROBE_MAX_LOC", "500"))

# CWE -> SecPriv canonical category (in-scope only; everything else is skipped).
CWE_CATEGORY: dict[str, str] = {
    "CWE-89": "sql_injection",
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-552": "path_traversal",
    "CWE-79": "xss",
    "CWE-94": "eval_injection",
    "CWE-95": "eval_injection",
    "CWE-502": "deserialization",
    "CWE-918": "ssrf",
    "CWE-601": "open_redirect",
    "CWE-611": "xxe",
    "CWE-1336": "ssti",
    "CWE-798": "hardcoded_secret",
    "CWE-259": "hardcoded_secret",
    "CWE-321": "hardcoded_secret",
    "CWE-327": "crypto_misuse",
    "CWE-328": "crypto_misuse",
    "CWE-330": "crypto_misuse",
    "CWE-916": "crypto_misuse",
    "CWE-352": "csrf",
    "CWE-362": "race_condition",
    "CWE-367": "race_condition",
    "CWE-532": "insecure_logging",
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-862": "auth_bypass",
    "CWE-863": "auth_bypass",
    "CWE-639": "auth_bypass",
    # privacy-relevant CWEs (the real privacy slice; smaller — few get CVEs)
    "CWE-359": "pii_leakage",
    "CWE-200": "pii_leakage",
    "CWE-312": "insecure_storage",
    "CWE-311": "insecure_storage",
    "CWE-319": "insecure_storage",
}

EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
}
SKIP_PATH = re.compile(
    r"(^|/)(test|tests|__tests__|spec|examples?|docs?|vendor)/", re.I
)
COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", re.M)


def _get(url: str) -> bytes:
    headers = {
        "User-Agent": "secpriv-probe",
        "Accept": "application/vnd.github+json",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=40).read()


def _raw(owner: str, repo: str, sha: str, path: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"
    try:
        return _get(url).decode("utf-8", "replace")
    except Exception:
        return None


def _category(cwes: list[str]) -> str | None:
    for c in cwes:
        if c in CWE_CATEGORY:
            return CWE_CATEGORY[c]
    return None


def _candidates(per_page: int) -> list[dict]:
    out: list[dict] = []
    for eco in ("pip", "npm", "maven", "go", "composer", "rubygems"):
        advs: list[dict] = []
        for page in range(1, PAGES + 1):
            try:
                batch = json.loads(
                    _get(
                        f"https://api.github.com/advisories?type=reviewed&ecosystem={eco}"
                        f"&per_page={per_page}&page={page}"
                    )
                )
            except Exception:
                break
            if not batch:
                break
            advs.extend(batch)
        for a in advs:
            cwes = [c.get("cwe_id") for c in (a.get("cwes") or []) if c.get("cwe_id")]
            cat = _category(cwes)
            if not cat:
                continue
            for r in a.get("references") or []:
                m = COMMIT_RE.search(r or "")
                if m:
                    out.append(
                        {
                            "cve": a.get("cve_id") or a.get("ghsa_id"),
                            "cwe": cwes,
                            "category": cat,
                            "owner": m.group(1),
                            "repo": m.group(2),
                            "sha": m.group(3),
                        }
                    )
                    break
    return out


def _build_case(c: dict) -> dict | None:
    owner, repo, sha = c["owner"], c["repo"], c["sha"]
    try:
        commit = json.loads(
            _get(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}")
        )
    except Exception:
        return None
    parents = commit.get("parents") or []
    if not parents:
        return None
    parent = parents[0]["sha"]
    files = []
    for f in commit.get("files") or []:
        path = f.get("filename", "")
        ext = Path(path).suffix
        patch = f.get("patch")
        is_test = re.search(
            r"(\.test\.|\.spec\.|_test\.|_spec\.|(^|/)test_)", path, re.I
        )
        if ext not in EXT_LANG or SKIP_PATH.search(path) or is_test or not patch:
            continue
        if f.get("status") != "modified" or (f.get("changes") or 999) > MAX_CHANGED:
            continue
        hunks = HUNK_RE.findall(patch)
        if not hunks:
            continue
        old_line, new_line = int(hunks[0][0]), int(hunks[0][1])
        pre = _raw(owner, repo, parent, path)
        post = _raw(owner, repo, sha, path)
        if not pre or not post or len(pre.splitlines()) > MAX_LOC:
            continue
        files.append(
            {
                "path": path,
                "base": Path(path).name,
                "lang": EXT_LANG[ext],
                "pre": pre,
                "post": post,
                "old_line": old_line,
                "new_line": new_line,
            }
        )
        if len(files) >= 3:
            break
    return {**c, "parent": parent, "files": files} if files else None


def _write(case: dict, idx: int) -> tuple[dict, dict]:
    cid = f"CVE-{idx:02d}"
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", str(case["cve"]))
    langs = sorted({f["lang"] for f in case["files"]})
    multi = len(case["files"]) > 1
    pre_files, post_files, pre_exp = [], [], []
    for f in case["files"]:
        for variant, lst in (("pre", pre_files), ("post", post_files)):
            d = PROBE_DIR / cid / variant
            d.mkdir(parents=True, exist_ok=True)
            (d / f["base"]).write_text(f[variant])
            lst.append(f"probe_cve/{cid}/{variant}/{f['base']}")
        pre_exp.append(
            {
                "surface": "security",
                "category": case["category"],
                "file": f["base"],
                "line": f["old_line"],
                "cwe": case["cwe"][0],
            }
        )
    meta = {
        "cve": case["cve"],
        "ghsa_cwe": case["cwe"],
        "repo": f"{case['owner']}/{case['repo']}",
        "sha": case["sha"],
        "langs": langs,
        "multi_file": multi,
    }
    pre_case = {
        "case_id": f"{cid}-{slug}-pre",
        "files": pre_files,
        "kind": "security_tp",
        "lang": case["files"][0]["lang"],
        "expected_findings": pre_exp,
        "cve_meta": meta,
    }
    post_case = {
        "case_id": f"{cid}-{slug}-post",
        "files": post_files,
        "kind": "security_tn",
        "lang": case["files"][0]["lang"],
        "expected_findings": [],
        "cve_meta": meta,
    }
    return pre_case, post_case


def main() -> None:
    target = TARGET_N
    auth = "authenticated (5000/hr)" if GITHUB_TOKEN else "UNAUTH (60/hr — cap ~15)"
    print(f"target={target} pages/eco={PAGES} api={auth}")
    cands = _candidates(per_page=100 if GITHUB_TOKEN else 60)
    print(f"candidates with in-scope CWE + fix commit: {len(cands)}")
    cases: list[dict] = []
    seen: set[str] = set()
    idx = 0
    for c in cands:
        key = f"{c['owner']}/{c['repo']}/{c['sha']}"
        if key in seen:
            continue
        seen.add(key)
        built = _build_case(c)
        if not built:
            continue
        idx += 1
        pre, post = _write(built, idx)
        cases.extend([pre, post])
        m = pre["cve_meta"]
        print(
            f"  [{idx:02d}] {m['cve']:18s} {c['category']:18s} {'+'.join(m['langs']):10s} "
            f"{'MULTI' if m['multi_file'] else 'single':6s} {m['repo']}"
        )
        if idx >= target:
            break
    GT_OUT.write_text(
        json.dumps(
            {"description": "real CVE probe (patch-derived)", "cases": cases}, indent=2
        )
        + "\n"
    )
    print(
        f"\nwrote {len([c for c in cases if c['kind'] == 'security_tp'])} pre + "
        f"{len([c for c in cases if c['kind'] == 'security_tn'])} post cases -> {GT_OUT}"
    )


if __name__ == "__main__":
    main()
