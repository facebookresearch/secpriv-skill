<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# SecPriv

A unified LLM-agent skill for code review that covers both **security weaknesses** (CWE-mapped) and **privacy violations** (GDPR-mapped) through one methodology with a detector-validator decomposition.

The artifact under test is `SKILL.md` — the system prompt that defines the review methodology. The `experiment/` tree contains the 128-case benchmark, ground truth, and evaluation harness used to measure it.

## Why one skill instead of two

Security and privacy review share structural mechanisms: both depend on tracing data from sources to sinks, both depend on transformation awareness (a SQL-injection candidate is suppressed if input passes a parameterized API; a privacy-leakage candidate is suppressed if an identifier passes a salted hash), and both face the same dominant operational problem — false positives that erode developer trust.

A unified skill exploits this overlap. On the 128-case benchmark, SecPriv-Sonnet achieves F1 = 0.79, versus F1 = 0.49 for a two-skill baseline (separate security + privacy skills unioned) and F1 = 0.08 for a no-skill baseline.

## Methodology (5 phases)

Defined in full in [`SKILL.md`](SKILL.md).

| Phase | Purpose |
|-------|---------|
| 1. Repository Context | Detect frameworks (ORMs, sanitizers, auth middleware, consent libraries), map trust boundaries, inventory personal data. |
| 2. Source/Sink + Transformation Flow | Trace data from sources to sinks; classify transformation state (raw, salted-hash, k-aggregated, encrypted, tokenized, base64). |
| 3. Dual-Surface Assessment | Apply 30 canonical categories: 20 security (CWE-mapped) + 10 privacy (GDPR-mapped). Cross-surface findings share a `flow_id`. |
| 4. Validator + Suppression | Seven shared rules: exploitation-path verification, framework auto-protection, test-scope, trusted-source, transformation adequacy, same-purpose reuse, unsuppressible evidence. Confidence threshold 0.8. |
| 5. Standards Mapping | Attach CWE-ID (security) or GDPR article (privacy) + one-paragraph remediation. |

## Benchmark

128 self-contained Python and HTML files across 30 categories:

| Subset | Cases | Composition |
|--------|-------|-------------|
| Security TPs | 60 | 20 categories × 3 construct variants |
| Privacy TPs | 30 | 10 categories × 3 construct variants |
| Near-miss TNs | 30 | 20 calibration + 10 held-out (`holdout: true` in `ground_truth.json`) |
| Cross-domain | 8 | 3 TPs + 5 TNs that span both surfaces |

Category provenance is documented in `experiment/category_sources.md` (security from MITRE Top 25 2025 + OWASP Top 10 2021; privacy from the GDPR Enforcement Tracker).

## Repository Layout

```
.
├── SKILL.md                       The artifact under test (~18 KB prompt)
├── LICENSE
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── .gitignore
└── experiment/
    ├── category_sources.md        MITRE/OWASP/GDPR-Tracker provenance per category
    ├── eval_plan.md               Experiment design (hypotheses, configurations, metrics)
    ├── ground_truth.json          128 cases with category/line/severity + `holdout` flag
    ├── test_cases/                Self-contained .py / .html files
    │   ├── security/              60 TPs + 15 TNs across 20 categories
    │   ├── privacy/               30 TPs + 15 TNs across 10 categories
    │   └── cross/                 8 cross-domain cases
    ├── runner/
    │   ├── evaluate.py            Runs one configuration end-to-end against the bench
    │   ├── aggregate.py           Cross-run aggregation, per-category recall, TN stability
    │   ├── rescore.py             Re-score cached emissions under a different rubric (no API cost)
    │   ├── analyze_failures.py    Failure-mode classification (adversarial / semantic / absence)
    │   ├── rerun_failures.py      Re-invoke only cases that previously parse-failed
    │   ├── aliases.json           181-entry alias normalization (sub-category → canonical)
    │   └── _generate_*.py         Benchmark generators (case-construction reference)
    └── run_wave3.sh               Drives the third TN-only re-run for stability analysis
```

## Headline Results

128-case benchmark, single run per configuration except SecPriv-Sonnet which has 3 runs on the 35 TN cases for stability analysis:

| Config | Precision | Recall | F1 | TN | Latency |
|--------|-----------|--------|------|--------|---------|
| SecPriv-Sonnet | 0.66 | 0.98 | **0.79** | 30/35 | 74 s/case |
| SecPriv-Haiku | 0.75 | 0.96 | 0.84 | 28/35 | 46 s/case |
| Two-skill (Sonnet) | 0.45 | 0.55 | 0.49 | 33/35 | 125 s/case |
| Detector-only (Sonnet) | 0.47 | 0.97 | 0.63 | 18/35 | 76 s/case |
| No-skill (Sonnet) | 0.05 | 0.18 | 0.08 | 12/35 | 31 s/case |

The detector-only ablation drops F1 by 0.16 and TN from 30/35 to 18/35 while keeping recall (0.97 vs 0.98) — confirming the validator carries the precision.

Per-category recall: 27 of 29 evaluated categories at 100% on SecPriv-Sonnet. Two Tier-2 categories: `xss` (0.67, the `string.Template().substitute()` variant is missed) and `second-order-sqli` (0.75, the stored-SSTI variant is categorized as `ssti`).

TN stability across 3 runs: 29/35 (83%) produce identical outcomes. The structurally hardest case (`S-TN-05`, a `@require_admin`-decorated endpoint) is stably wrong — flagged as `auth-bypass` in all 3 runs.

## How to Use the Skill

The skill is a system prompt, not executable code. Provide `SKILL.md` to a code-review LLM agent (Claude Sonnet / Haiku tested; should generalize to other models that follow detailed methodologies) as the system prompt, then send a code file as the user message. The agent returns a JSON array of findings conforming to the schema in `SKILL.md`.

Minimal invocation pattern (Claude CLI):

```bash
claude -p --bare --model sonnet \
  --append-system-prompt "$(cat SKILL.md)" \
  --output-format text \
  "Review the following file. Return only the JSON array.

FILE: my_handler.py

\`\`\`python
$(cat my_handler.py)
\`\`\`"
```

## Reproducing the Benchmark Results

```bash
cd experiment

# Run one configuration end-to-end (~75 s/case × 128 cases ≈ 2.6 h on Sonnet)
python3 runner/evaluate.py --config secpriv_sonnet --run-id run1

# Aggregate results across runs and configurations
python3 runner/aggregate.py

# Re-score cached emissions under a different rubric (no API spend)
python3 runner/rescore.py
```

Outputs land in `experiment/results/<config>/<run-id>.json`. The aggregator writes `results/aggregate.json` (machine-readable) and a printed markdown summary.

Cost: roughly $0.024/case on Claude Sonnet, $0.008/case on Haiku (Sonnet 4.x and Haiku 4.5 list prices at time of paper). Full benchmark across the five configurations is approximately $25.

## Threat Model

Two adversaries:

- **Security adversary**: external attacker who can submit untrusted input to any externally reachable endpoint and may control values previously stored in semi-trusted locations (databases, caches, application-level config tables, feature flags). Application-level configuration is explicitly *not* trusted; OS environment variables are.
- **Privacy adversary**: regulatory or contractual party auditing for GDPR/CCPA compliance, plus the user whose data is at stake. Personal data flowing to a sink is in violation if not adequately transformed, lacks lawful basis, exceeds retention purpose, creates re-identification risk, or is repurposed beyond original collection intent.

The skill does *not* reason about runtime behavior — whether a consent flag is actually checked at runtime, whether a TTL is enforced by the cache backend, or whether an encryption key is actually KMS-managed are runtime-verification questions that no static-analysis approach (LLM or otherwise) can answer with certainty.

## Limitations

- **Single-file scope.** Each file is reviewed independently. Cross-file privacy flows (collection in file A, leakage in file B) are invisible. This is why `second-order-sqli` scores 0.75 even with multi-construct variants in the same file — the cross-construct reasoning is a preview of the harder cross-file problem.
- **Frozen 30-category schema.** A new CWE or GDPR-derived category published after the skill is deployed requires a human to update `SKILL.md`'s category definitions, `experiment/runner/aliases.json`, and the suppression rules.
- **Python + JavaScript focus.** Rules generalize to Java, Go, Rust but the framework-awareness facts (ORM names, template engines, etc.) are biased toward the Python/JS ecosystem.
- **One TN case is stably wrong.** SecPriv consistently flags `auth-bypass` on a `@require_admin`-decorated endpoint because the validator's R2 rule recognizes standard framework decorators (`@login_required`, `@csrf_protect`) but not custom decorators whose implementation is in the same file. Treat auth-related findings on decorator-protected endpoints with extra skepticism.

## Citation

A BibTeX entry will be added here once the paper is published.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors must sign Meta's CLA.

## Security

To report a security issue, see [SECURITY.md](SECURITY.md). Please do not file public GitHub issues for security reports.

## License

MIT — see [LICENSE](LICENSE).
