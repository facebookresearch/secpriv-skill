# SecPriv Evaluation Plan

This document specifies the experiment for the paper *SecPriv: A Unified Multi-Phase Agent Skill for LLM-Assisted Security and Privacy Code Review* (`secpriv_eval/secpriv_paper.tex`). The category-selection rationale and source citations are documented separately in `category_sources.md`.

The benchmark consists of $128$ cases covering $30$ canonical categories (20 security + 10 privacy), with $3$ cases per category, $30$ near-miss true-negative cases (10 of which are held out from suppression-rule calibration), and $8$ cross-domain cases that exercise the unification claim. The category set is grounded in three public popularity / severity rankings: MITRE CWE Top 25 (2024), OWASP Top 10 (2021), and the GDPR Enforcement Tracker, supplemented by the CCPA enforcement record for the right-to-erasure category.

Each section below is structured as **Hypothesis → Procedure → Metrics → Decision rule.** Decision rules state the numerical outcome that would refute the corresponding paper claim.

The experiment is designed to substantiate the four headline claims of the paper:

1. **Unification claim** — The unified skill matches or exceeds the F1 of two separate skills run in sequence, at lower per-case cost.
2. **Asymmetry claim** — The detection–suppression asymmetry observed independently in the two predecessor skills also holds for the unified skill across both surfaces.
3. **Hierarchy claim** — Per-category recall is ordered by structural locality of the violation pattern, and the ordering is invariant across surfaces.
4. **Cross-domain reinforcement claim** — Sharing suppression context between the security and privacy passes eliminates a majority of false positives that either skill alone produces on cases that span both surfaces.

---

## 1. Research Questions

| ID | Question | Decision Rule (refutes claim if…) |
|----|----------|-----------------------------------|
| RQ1 | Does the unified skill achieve F1 within 2 pp of the two-skill baseline at strictly lower per-case latency? | Unified F1 < two-skill F1 − 2 pp, OR unified latency ≥ two-skill latency. |
| RQ2 | Is per-case TN stability ≥ 90% while per-case TP stability < 50% across the SecPriv-Sonnet runs on the TN subset? | TN stability < 90%, OR TP stability ≥ 50%. |
| RQ3 | Does per-category recall correlate with construct-locality on both surfaces (Spearman ρ ≥ 0.5)? | ρ < 0.5 on either surface. |
| RQ4 | Does the unified skill suppress ≥ 50% of single-skill false positives on cross-domain cases? | Cross-domain FP reduction < 50%. |
| RQ5 | Does Haiku achieve F1 within 15 pp of Sonnet at ≤ 25% of the per-case latency? | Haiku F1 < Sonnet F1 − 15 pp, OR Haiku latency > 25% of Sonnet latency. |
| RQ6 | Does TN-rate on the held-out subset stay within 10 pp of TN-rate on the calibration subset? | Held-out TN-rate < calibration TN-rate − 10 pp (indicates the suppression rules over-fit the calibration cases). |
| RQ7 | Does the unified skill cover ≥ 50% of MITRE Top 25 (2024) categories applicable to Python and 100% of GDPR Enforcement Tracker top-10 articles applicable to code? | Coverage < 50% (security) or < 100% (privacy). |

---

## 2. Benchmark Construction (128 cases)

The benchmark composition is fixed at design time and documented in `ground_truth.json`. Each case is a self-contained Python file of 30–80 LOC with realistic framework imports (Flask, FastAPI, SQLAlchemy, Redis, Jinja2, etc.). Rationale for size: predecessor benchmarks established that single-function cases are too easy and that multi-file cases require a different harness; 30–80 LOC sits at the realistic-but-bounded sweet spot.

The category list and source-rank justification are in `category_sources.md`. Quick reference:

- **20 security categories**: 14 from MITRE Top 25 (2024) applicable to Python + 5 OWASP Top 10 (2021) categories not in MITRE Top 25 + 1 novel agentic-systems category (`agent_csrf`)
- **10 privacy categories**: all 10 GDPR Enforcement Tracker top-10 articles applicable to code, with `right_to_erasure` additionally backed by CCPA §1798.105
- **3 cases per category** — within-category construct variants (see `category_sources.md` §"Within-category construct variants")

### 2.1 Security True Positives (60 cases, 60 expected findings)

20 categories × 3 construct variants per category. Each row in the table below is one construct variant; the canonical category, CWE, and source rank are shared across the three variants of each category.

A representative subset (full list maintained in `ground_truth.json`):

| Category (CWE) | Variant A | Variant B | Variant C |
|---|---|---|---|
| sql_injection (CWE-89) | f-string | `.format()` | raw `text()` in SQLAlchemy |
| command_injection (CWE-78) | `shell=True` | `os.popen` | `os.system` |
| path_traversal (CWE-22) | raw concat | `Path(user)/file` | zip-slip during extract |
| xss (server-side, CWE-79) | Jinja `\|safe` | raw `Markup(user)` | template `string.Template().substitute(user=…)` |
| xss_dom (CWE-79 DOM) | `innerHTML = user` | `document.write(user)` | jQuery `$.html(user)` |
| auth_bypass (CWE-287/863) | missing decorator | IDOR (no ownership check) | JWT alg=none |
| hardcoded_secret (CWE-798) | API key literal | DB password literal | JWT signing-key literal |
| deserialization (CWE-502) | `pickle.loads` | `yaml.load` (unsafe) | `joblib.load` |
| eval_injection (CWE-94) | `eval` | `exec` | dynamic `__import__` |
| infinite_loop (CWE-835) | redirect cycle | unbounded recursion | retry without max-attempts |
| second_order_sqli (CWE-89) | stored username → raw query | stored URL → SSRF | stored template → SSTI |
| ssrf (CWE-918) | arbitrary URL fetch | cloud metadata IP | `file://` scheme |
| open_redirect (CWE-601) | unvalidated `redirect(user)` | JS `location = user` | OAuth callback `state` not validated |
| crypto_misuse (CWE-327/330) | MD5 password hashing | hardcoded IV | `random.random()` for tokens |
| xxe (CWE-611) | `lxml.parse` w/o `resolve_entities=False` | SOAP w/ entity expansion | XInclude on user XML |
| ssti (CWE-1336) | `Jinja2.Template(user)` | Mako template w/ user input | Twig render w/ user expr |
| csrf (CWE-352) | missing CSRF token | SameSite=None cookie | GET-mutation endpoint |
| race_condition (CWE-362) | TOCTOU file check | balance update without lock | duplicate-key insert without unique index |
| insecure_logging (CWE-532) | secret in log | exception with token | debug dump in error path |
| agent_csrf (LLM-agent CWE-352 variant) | URL-param trigger | webhook trigger | deep-link trigger |

### 2.2 Privacy True Positives (30 cases, 30 expected findings)

10 categories × 3 construct variants per category. Source rank in `category_sources.md`.

| Category (GDPR Article) | Variant A | Variant B | Variant C |
|---|---|---|---|
| insecure_storage (Art. 32) | unencrypted PII column | plaintext password | DB connection without TLS |
| consent_bypass (Art. 6+7) | missing consent check | temporal misorder (check after) | commented-out verification |
| purpose_creep (Art. 5(1)(b)) | shipping → ad targeting | support transcripts → training | loyalty data → credit scoring |
| pii_leakage (Art. 5(1)(f)) | log statement | error response body | metric label |
| data_minimization (Art. 5(1)(c)) | excessive collection | unused PII column | oversized request scope |
| data_retention (Art. 5(1)(e)) | no TTL on cache | indefinite audit log | schema column without retention |
| third_party_sharing (Art. 28) | analytics endpoint | ad SDK | CRM upload |
| cross_border_transfer (Art. 44–49) | EU→US w/o SCCs | EU→US w/o adequacy decision | EU→US w/o BCR |
| re_identification_risk (Art. 4(5)) | unsalted hash | quasi-identifier export | base64 sold as anonymization |
| right_to_erasure (Art. 17 / CCPA §1798.105) | no delete endpoint | soft-delete only | missing cascade delete |

### 2.3 Near-Miss True Negatives (30 cases, 0 expected findings; 20 calibration + 10 held-out)

Each TN targets a specific discrimination boundary, paired with one of the TP construct variants by single-edit transformation. The full list is in `ground_truth.json` with two flags per case:

- `holdout: false` (20 cases) — visible during suppression-rule calibration
- `holdout: true` (10 cases) — **never inspected during rule editing**; used solely to estimate the generalization gap

The 10 held-out cases are split 5 security + 5 privacy. Their existence is recorded in this plan and in `ground_truth.json` before the suppression rules are revised; the contents are not opened until the final TN-rate measurement.

**Security TNs (15 = 10 calibration + 5 held-out)** — a representative subset:

| TP construct → TN construct | Boundary tested | Set |
|---|---|---|
| f-string SQL → SQLAlchemy ORM `where()` | parameterization | calibration |
| `subprocess(shell=True)` → list-arg `subprocess.run([...])` | shell vs. argv | calibration |
| `yaml.load` → `yaml.safe_load` | safe loader | calibration |
| `dangerouslySetInnerHTML` → JSX rendering with auto-escape | framework escape | calibration |
| `requests.get(user_url)` → URL allowlist + private-IP check | SSRF defense | calibration |
| `redirect(user_url)` → `redirect(url_for(name))` | open-redirect defense | calibration |
| MD5(password) → bcrypt(password) + per-record salt | password hashing | calibration |
| `lxml.parse(xml)` → `etree.parse(xml, resolver=…)` w/ `resolve_entities=False` | XXE defense | calibration |
| missing decorator → `@require_admin` | auth presence | calibration |
| TOCTOU check → atomic `os.O_EXCL \| os.O_CREAT` open | race-condition defense | calibration |
| `random.random()` token → `secrets.token_urlsafe()` | CSPRNG | held-out |
| inline secret → `os.environ` lookup | secret externalization | held-out |
| `eval(user)` → `ast.literal_eval(user)` | safe eval | held-out |
| missing CSRF token → Django `@csrf_protect` | CSRF defense | held-out |
| stored field used in raw query → stored field passed to ORM `where()` | second-order defense | held-out |

**Privacy TNs (15 = 10 calibration + 5 held-out)**:

| TP construct → TN construct | Boundary tested | Set |
|---|---|---|
| unsalted SHA-256 of email → PBKDF2 + per-record salt | salted vs. unsalted | calibration |
| analytics POST raw email → analytics POST hashed (k-anon) email | anonymization adequacy | calibration |
| no consent gate → `if user.consents_to(...): ...` | consent placement | calibration |
| same-purpose reuse (registration email → password reset) | not purpose-creep | calibration |
| `db.cache.set(key, pii)` → `db.cache.set(key, pii, ex=300)` | TTL presence | calibration |
| EU→US transfer raw → EU→US transfer w/ documented SCCs | cross-border safeguard | calibration |
| no `delete_user()` → `delete_user()` cascades to all PII tables | erasure presence | calibration |
| `subscribe()` collects 8 fields → `subscribe()` collects only `email` | minimization adherence | calibration |
| plaintext password column → `bcrypt`-hashed password column | encryption at rest | calibration |
| metric label = raw IP → metric label = country code | high-cardinality defense | calibration |
| audit log indefinite → audit log w/ rotation policy | retention compliance | held-out |
| third-party POST raw → third-party POST tokenized via vault | tokenization | held-out |
| processing without consent → processing under documented legitimate interest | lawful-basis alternative | held-out |
| email field in CSV export → email field omitted from CSV export | minimization at sink | held-out |
| `redis.set(pii)` → `redis.set(encrypt(pii))` | encryption-in-cache | held-out |

### 2.4 Cross-Domain Cases (8 cases)

Eight cases that exercise the unification claim — the same code line or flow simultaneously constitutes a security weakness and a privacy violation.

| ID | TP/TN | Spans |
|---|---|---|
| X-TP-01 | TP | auth_bypass + third_party_sharing |
| X-TP-02 | TP | auth_bypass + pii_leakage |
| X-TP-03 | TP | second_order_sqli + pii_leakage on stored field |
| X-TN-01 | TN | JWT auth + salted hash + declared 3rd-party URL |
| X-TN-02 | TN | HMAC signature + salted-hash payload summary |
| X-TN-03 | TN | confirmation-gated agent + explicit consent + declared sink |
| X-TN-04 | TN | parameterized SQL returning hashed identifiers under documented legitimate interest |
| X-TN-05 | TN | DPA-bound processor + encrypted-at-rest + decorator-protected admin |

The TPs require the unified skill to emit cross-referenced findings (shared `flow_id`); the TNs require simultaneous suppression on both surfaces.

---

## 3. Configurations and Run Plan

Five configurations are evaluated. The run plan is **asymmetric**: the primary configuration runs once on the full benchmark and additionally twice on the TN subset (where TN-stability is the headline finding); all baseline configurations run once. This concentrates the multi-run budget on the only place where N>1 yields a finding — N=2 across the full benchmark cannot statistically support a standard deviation, so we do not pay that cost.

| ID | Configuration | Backbone | Skill methodology | Suppression layer | Runs |
|----|---------------|----------|-------------------|-------------------|------|
| C1 | **SecPriv-Sonnet** (primary) | Claude Sonnet 4.x | Full unified 5-phase | Shared, R1–R7 | 1 × 128 cases + 2 × 30 TN cases |
| C2 | **Two-skill-Sonnet** | Claude Sonnet 4.x | SecReview + PrivReview run separately, outputs unioned | Per-skill, no sharing | 1 × 128 cases |
| C3 | **No-skill-Sonnet** | Claude Sonnet 4.x | Minimal prompt: "review this code for security and privacy issues; return JSON" | None | 1 × 128 cases |
| C4 | **SecPriv-Haiku** | Claude Haiku 4.5 | Full unified 5-phase | Shared, R1–R7 | 1 × 128 cases |
| C5 | **Detector-only-Sonnet** | Claude Sonnet 4.x | Phases 1–3 only (validator + standards mapping disabled) | None | 1 × 128 cases |

**Run protocol per configuration:**

1. For each case, invoke the model with the methodology as the system prompt and the case file as the user message. Temperature = 0. 300-second timeout per case.
2. Parse the JSON output. If parsing fails, retry once with a stricter prompt; if it fails again, record an "unparseable" outcome (counts as 0 findings).
3. Apply alias normalization (Section 4.2).
4. Match findings against ground truth (Section 4.3) under both strict and permissive rubrics.
5. Record total cost (input + output tokens × API list price at `results/PRICES.md` snapshot) and wall-clock latency.
6. For C1, repeat steps 1–5 on the 30 TN cases two additional times.

**Cost and time budget:**

| Item | Invocations | Time | API cost |
|---|---|---|---|
| C1 SecPriv-Sonnet (full) | 128 | 2.8 h | $7.30 |
| C1 SecPriv-Sonnet (TN extras) | 60 | 0.8 h | $2.10 |
| C2 Two-skill-Sonnet (2 calls/case) | 256 | 5.0 h | $7.30 |
| C3 No-skill-Sonnet | 128 | 1.2 h | $1.10 |
| C4 SecPriv-Haiku | 128 | 1.6 h | $1.65 |
| C5 Detector-only-Sonnet | 128 | 3.4 h | $3.10 |
| Re-scoring + aggregation (no API) | — | 0.2 h | $0 |
| **Total** | **828** | **~14 h** | **~$22.55** |

API price snapshot: Sonnet 4 input $3/M tokens, output $15/M tokens; Haiku 4.5 input $1/M, output $5/M.

---

## 4. Output Parsing, Normalization, and Matching

### 4.1 Output Schema

Every finding emitted by the skill must be a JSON object with the following required fields:

```json
{
  "surface": "security" | "privacy",
  "category": "<one of 30 canonical categories>",
  "severity": "HIGH" | "MEDIUM" | "LOW",
  "confidence": 0.0,
  "file": "string",
  "line": 0,
  "description": "string",
  "remediation": "string"
}
```

Optional fields: `exploitation_path` (security), `regulatory_basis` (privacy, e.g., `"GDPR Art. 5(1)(f)"`), `cwe` (security, e.g., `"CWE-89"`), `flow_id` (cross-referenced findings).

### 4.2 Category Alias Table

A 150-entry table in `runner/aliases.json` maps model-emitted sub-categories to one of 30 canonical labels. Representative entries include:

```
ssrf_internal           → ssrf
ssrf_metadata           → ssrf
server_side_request     → ssrf

open_redirect_url       → open_redirect
unvalidated_redirect    → open_redirect

weak_crypto             → crypto_misuse
md5_password            → crypto_misuse
hardcoded_iv            → crypto_misuse
weak_random             → crypto_misuse

xml_external_entity     → xxe
billion_laughs          → xxe

template_injection      → ssti
server_side_template    → ssti

cross_site_request      → csrf

toctou                  → race_condition
time_of_check           → race_condition

log_injection           → insecure_logging
sensitive_in_log        → insecure_logging

unencrypted_storage     → insecure_storage
plaintext_password      → insecure_storage
no_tls                  → insecure_storage

international_transfer  → cross_border_transfer
schrems                 → cross_border_transfer

erasure_failure         → right_to_erasure
no_delete               → right_to_erasure
soft_delete_only        → right_to_erasure
right_to_be_forgotten   → right_to_erasure
```

### 4.3 Match Rule (Strict and Permissive)

Two scoring rubrics are computed per run:

**Strict.** A finding is a true positive if BOTH:
1. Its `category` (after alias normalization) equals the canonical `expected_findings` category for the case.
2. Its `line` is within ±10 lines of the corresponding ground-truth line.

A finding that does not match any ground-truth entry is a false positive. A ground-truth entry not matched by any finding is a false negative.

**Permissive.** A finding additionally counts as a true positive if it lines up with an `acceptable_findings` entry (multi-label ground truth). The acceptable list is curated by two-pass annotation under a stricter rubric (see `runner/_second_pass_audit.py` and `runner/_add_acceptable.py`) and is fixed before re-scoring.

**Held-out subset reporting.** TN-rate is computed three ways: (a) on the full 30 TN cases, (b) on the 20 calibration TNs only, and (c) on the 10 held-out TNs only. The held-out vs. calibration delta is the headline metric for RQ6.

---

## 5. Metrics

### 5.1 Primary Metrics

For each configuration C:

- **Precision_C** (strict and permissive)
- **Recall_C** (strict and permissive)
- **F1_C** (strict and permissive)
- **TN-rate_C** (full / calibration / held-out)

For C1 (SecPriv-Sonnet) on the TN subset, also report mean and per-run values across the 3 TN-subset runs.

### 5.2 Secondary Metrics

- **Per-category recall** (30 categories, per configuration) — supports RQ3 hierarchy claim
- **Per-case TN stability** (across 3 SecPriv-Sonnet TN-subset runs): fraction of TN cases producing identical (zero-finding) outcomes across all 3 runs
- **Per-case TP stability** — TP cases run only once each, so per-case TP stability is reported only on the subset of TP cases included in the TN-subset re-runs; primary TP-stability evidence comes from cross-configuration consistency
- **Cross-domain F1** (computed on the 8 cross-domain cases only) — supports RQ4
- **Mean cost (USD/case)** and **mean latency (s/case)** per configuration
- **Held-out generalization gap** (TN-rate calibration − TN-rate held-out) — supports RQ6

### 5.3 Failure-Mode Categorization

Each missed TP (false negative on a TP case) is hand-labeled as:

- **Adversarial-evasion**: case uses safety-sounding language that trips a suppression rule
- **Semantic-understanding**: case requires reasoning about removed/modified construct behavior or cross-module intent
- **Absence-enumeration**: case requires recognizing the absence of a required protective construct

Distribution is reported in §5.5 of the paper.

### 5.4 Coverage Statistics

Reported once for the benchmark itself, not per configuration:

- **MITRE Top 25 (2024) coverage**: $14$ of $25$ categories represented in the benchmark, $4$ excluded by Python scope, $7$ remaining gaps justified in `category_sources.md`
- **OWASP Top 10 (2021) coverage**: $8$ of $10$ categories represented
- **GDPR Enforcement Tracker top-10 article coverage**: $10$ of $10$ articles applicable to code represented
- **CCPA top-3 enforcement category coverage**: $1$ of $3$ (Art. 17 / §1798.105 right-to-erasure)

---

## 6. Statistical Analysis

### 6.1 Significance Tests

- **F1 difference (C1 vs. C2)**: paired bootstrap on the 128-case outcome vector; report 95% CI. The unification claim survives if the CI on (C1 − C2) excludes [−2 pp, +2 pp].
- **Per-category recall ordering (Spearman ρ)**: rank the 30 canonical categories by mean recall and by structural locality (1 = single-construct; 2 = single-file flow; 3 = multi-construct/absence; 4 = cross-module/intent). Report ρ separately for security ($n=20$) and privacy ($n=10$). The hierarchy claim survives if both ρ ≥ 0.5.
- **Held-out vs. calibration TN-rate (proportion test)**: McNemar test on the 20 calibration vs. 10 held-out TN outcomes. The held-out-validation claim survives if the held-out TN-rate is within 10 pp of the calibration TN-rate.
- **Cross-domain FP reduction (C1 vs. C2)**: report (C2_FP − C1_FP) / C2_FP on the 8-case cross-domain subset. The reinforcement claim survives if this ratio ≥ 0.5.

### 6.2 Power Analysis

The 30 TN cases support a binomial test of TN-rate ≥ 90% with power 0.8 at α = 0.05 against the alternative TN-rate ≤ 70%. Per-category recall has 3 cases per category; this supports a Spearman ρ test at $n=20$ (security) and $n=10$ (privacy) with detectable effect sizes of approximately ρ ≥ 0.45 at α = 0.05 and power 0.8.

The 8 cross-domain cases remain too few for a per-case significance test; the cross-domain finding is reported as an effect-size observation, not a significance result.

---

## 7. Repository Layout

```
secpriv_eval/experiment/
├── eval_plan.md                ← this document
├── category_sources.md         ← category-selection rationale + citations
├── ground_truth.json           ← 128-row strict ground truth
├── aliases.json                ← 150-entry alias table (in runner/)
├── test_cases/
│   ├── security/               ← 60 TP files + 15 TN files (10 calibration + 5 held-out)
│   ├── privacy/                ← 30 TP files + 15 TN files (10 + 5)
│   └── cross/                  ← 8 cross-domain files
├── runner/
│   ├── evaluate.py             ← runs one configuration end-to-end
│   ├── parse.py                ← JSON parser with retry
│   ├── alias.py                ← alias normalization
│   ├── match.py                ← line-proximity matching (strict + permissive)
│   ├── rescore.py              ← re-score cached emissions under a different rubric
│   ├── aggregate.py            ← stats across runs
│   ├── analyze_failures.py     ← failure-mode classification
│   ├── _generate_cases.py      ← benchmark generator
│   ├── _generate_sec.py        ← security cases sub-generator
│   ├── _generate_priv.py       ← privacy cases sub-generator
│   ├── _generate_cross.py      ← cross-domain cases sub-generator
│   ├── _add_acceptable.py      ← acceptable-finding additions for permissive scoring
│   └── _second_pass_audit.py   ← second-pass annotation rationales
├── results/
│   ├── C1_secpriv_sonnet/      ← 1 full-benchmark run + 2 TN-subset extra runs
│   ├── C2_two_skill/
│   ├── C3_no_skill/
│   ├── C4_secpriv_haiku/
│   ├── C5_detector_only/
│   ├── PRICES.md               ← API price snapshot at run time
│   ├── inter_annotator.json    ← second-pass agreement rates
│   ├── aggregate.json          ← cross-config aggregation
│   └── rescored.json           ← strict + permissive scores per run
└── analysis/
    ├── per_category.ipynb      ← Table 2 (paper)
    ├── stability.ipynb         ← TN-stability + asymmetry analysis
    ├── cross_domain.ipynb      ← Table 4 (paper)
    ├── holdout_gap.ipynb       ← held-out TN-rate vs. calibration TN-rate
    ├── coverage.ipynb          ← MITRE / OWASP / GDPR-Tracker coverage tables
    └── failure_modes.ipynb     ← failure-mode distribution
```

---

## 8. Reproducibility Checklist

- [ ] All 128 test cases generated by `runner/_generate_cases.py`, checked into `test_cases/`, with frozen line numbers.
- [ ] `ground_truth.json` reviewed by 2 annotators on the cases authored in this iteration; cases inherited under their original filenames inherit prior annotation.
- [ ] `category_sources.md` lists every category's public source rank (MITRE / OWASP / GDPR Tracker / CCPA / Novel) before any test case is written.
- [ ] `runner/aliases.json` frozen before C1 runs (no mid-experiment additions).
- [ ] Held-out TN flag set in `ground_truth.json` BEFORE the suppression rules are inspected; held-out TN content NOT opened until final TN-rate measurement.
- [ ] Each configuration uses the same temperature (0.0), same timeout (300 s), and same JSON-parser retry policy (1 retry).
- [ ] Cost computed using a single fixed API price snapshot (record date in `results/PRICES.md`).
- [ ] Failure-mode labels assigned by a single annotator; spot-check by a second annotator on 20% of misses.
- [ ] All runs completed for all 5 configurations before any statistical analysis.
- [ ] The validator's R1–R7 ruleset and the alias table are not modified after C1 results are observed (no train-on-test on the calibration set, and no inspection of held-out at all).
- [ ] Inter-pass agreement reported on every permissive `acceptable_findings` entry; second-annotator audit on the 8 acceptable co-findings carried over from earlier benchmark iterations.

---

## 9. Threats to the Experiment Itself (Distinct from Paper "Threats to Validity")

- **Annotator agreement**: cases authored in this iteration have 2-annotator review; cases inherited under their original filenames have single-annotator origin (audited in this iteration's verification). A full re-annotation of inherited cases is left for future work.
- **Budget**: 5 configurations × 128 cases at ~$0.04 mean (Sonnet) ≈ $25 + ~$8 of TN-subset re-run extras + retries = ~$45 ceiling.
- **Held-out validity**: the held-out subset is small (10 cases); a wider gap might appear at larger held-out scale. This is a known limitation of small-benchmark held-out testing and is acknowledged in the paper's threats to validity.
- **Construct-variant generalization**: 3 cases per category covers 3 surface forms but cannot exhaust the construct space (real SQL injection has dozens of surface forms). Per-category recall numbers should be read as "recall against these 3 representative variants," not as absolute category coverage.
- **No human reviewer baseline**: we do not compare against a human reviewer's precision/recall on the same benchmark.
- **Model version drift**: API behaviour can change between Sonnet/Haiku versions. The model versions used are recorded in `results/PRICES.md`; future replications on different model versions may produce different per-run numbers.

---

## 10. Timeline (Roughly 2 Weeks)

| Day | Milestone |
|------|-----------|
| 1 | Freeze category list (`category_sources.md`); finalize generator (`runner/_generate_cases.py`). |
| 2 | Generate 128 test cases; dual-annotate the cases authored in this iteration. |
| 3 | Update alias table to 150 entries; smoke-test runner on 10 cases per configuration. |
| 4–5 | Full C1 run + C1 TN-subset extras × 2; inspect outputs for parsing/format issues. |
| 6 | Full C2 run (two-skill, longest at ~5 h). |
| 7 | Full C3 + C4 + C5 runs in parallel. |
| 8 | Re-scoring under strict + permissive rubrics; aggregate metrics. |
| 9 | Failure-mode labeling; held-out vs. calibration analysis; coverage tables. |
| 10 | Statistical tests (paired bootstrap, Spearman ρ, McNemar). |
| 11–12 | Paper write-up updates: regenerate Tables 1–4 from `results/aggregate.json`. |
| 13 | Final cross-check that reported numbers match `results/`. |
| 14 | Submission. |

---

## 11. Pointers Back to the Paper

- §4 (Framework) — the architectural design that this experiment validates.
- §5 (Combined Benchmark) — the prose summary of §2 of this plan.
- §6 (Experimental Setup) — the prose summary of §3 of this plan.
- §7 (Results) — Tables 1, 2, 3, 4 in the paper correspond to §5.1, §5.2, §5.3, and the cross-domain row of §5.2 here.
- §8 (Discussion) — the interpretive narrative built on this experiment.
- §9 (Threats to Validity) — the paper-side companion to §9 of this document.
- §10 (Ethical Considerations) — required by ACSAC; the experiment itself raises no IRB concerns (synthetic code, no human subjects, no real PII).
