# SecPriv — Category Selection and Sourcing

This document records, for every category in the benchmark, the public popularity / severity ranking that justifies its inclusion. Reviewers and replicators can verify each ranking against the cited public source. All rankings are stated as of the cited source's publication date; re-running this benchmark in a future year may warrant re-checking the rankings.

---

## Sourcing principles

Every category in the benchmark is backed by **at least one** of the following:

- **MITRE CWE Top 25 Most Dangerous Software Weaknesses (2024)** — the authoritative ranking of software-weakness severity weighted by exploit prevalence. Source: <https://cwe.mitre.org/top25/>
- **OWASP Top 10 Web Application Risks (2021)** — the most widely-cited community ranking of web-application vulnerability classes. Source: <https://owasp.org/Top10/>
- **GDPR Enforcement Tracker** — public dataset of GDPR fines maintained by CMS Hasche Sigle. Article-frequency rankings are derived from this dataset. Source: <https://www.enforcementtracker.com/>
- **CCPA enforcement actions** by the California Attorney General (2020–2024). Source: <https://oag.ca.gov/privacy/ccpa/enforcement>
- **Novel category** (no popularity ranking applies) — explicitly justified by the agentic-systems threat model. Currently only `agent_csrf` falls into this bucket; it was introduced in the predecessor SecReview skill.

A category that no public ranking endorses is excluded unless the "novel" rationale is explicitly invoked.

---

## Security categories (20 total)

Three cases per category. Inclusion criterion: any category appearing in either MITRE Top 25 (2025) or OWASP Top 10 (2021) and applicable to Python. Memory-safety categories (CWE-787, -125, -416, -120) are excluded by language scope, not by ranking.

| # | Category | CWE | Source rank |
|---|---|---|---|
| 1 | sql_injection | CWE-89 | MITRE Top 25 #2 (2025); OWASP A03:2021 |
| 2 | command_injection | CWE-78 | MITRE Top 25 #9 (2025) |
| 3 | path_traversal | CWE-22 | MITRE Top 25 #6 (2025) |
| 4 | xss (server-side) | CWE-79 | MITRE Top 25 #1 (2025); OWASP A03:2021 |
| 5 | xss_dom | CWE-79 (DOM-based) | OWASP A03:2021 (XSS family) |
| 6 | auth_bypass | CWE-287 / CWE-863 | MITRE Top 25 #17 (2025, CWE-863); OWASP A01:2021 |
| 7 | hardcoded_secret | CWE-798 | OWASP A05:2021 |
| 8 | deserialization | CWE-502 | MITRE Top 25 #15 (2025); OWASP A08:2021 |
| 9 | eval_injection | CWE-94 | MITRE Top 25 #10 (2025) |
| 10 | infinite_loop | CWE-835 | OWASP API4:2023 (rate limiting) |
| 11 | second_order_sqli | CWE-89 (retrieval-side) | OWASP A03:2021 (SQL family); multi-construct context |
| 12 | ssrf | CWE-918 | MITRE Top 25 #22 (2025); OWASP A10:2021 |
| 13 | open_redirect | CWE-601 | OWASP A05:2021 cat. |
| 14 | crypto_misuse | CWE-327 / CWE-330 | OWASP A02:2021 |
| 15 | xxe | CWE-611 | OWASP A05:2021 cat. (formerly OWASP A04:2017) |
| 16 | ssti | CWE-1336 | OWASP A03:2021 (injection family) |
| 17 | csrf | CWE-352 | MITRE Top 25 #3 (2025); OWASP A01:2021 |
| 18 | race_condition | CWE-362 | OWASP (general) |
| 19 | insecure_logging | CWE-532 | Related to CWE-200 (MITRE Top 25 #20, 2025) |
| 20 | agent_csrf | CWE-352 (LLM-agent variant) | **Novel category** — no public ranking. Explicitly justified by the agentic-systems threat model (ACSAC 2026 hard-topic theme); introduced in the predecessor SecReview skill. |

**Excluded by language scope** (would otherwise be in scope by ranking): CWE-787 (out-of-bounds write, MITRE #5 in 2025), CWE-125 (out-of-bounds read, #8), CWE-416 (use-after-free, #7), CWE-120 (classic buffer overflow, #11). These are memory-safety bugs that do not arise in the Python harness; the paper's threats to validity notes this exclusion.

**Excluded by review-out-of-scope**: CWE-863 (incorrect authorization — hard to distinguish from auth_bypass at the file level), CWE-269 (improper privilege management — typically OS-level, not application-code-level).

---

## Privacy categories (10 total)

Three cases per category. Inclusion criterion: any GDPR article appearing in the top-10 most-cited articles in the GDPR Enforcement Tracker public dataset (as of the most recent annual analysis), filtered to those that map to a code-level construct rather than a policy-text or organizational obligation.

The Enforcement Tracker rankings below are approximate and based on the public dataset's article-frequency distribution; the exact ordering shifts year-to-year. Practitioners reproducing this benchmark should re-derive the ranking against the current Enforcement Tracker dump.

| # | Category | GDPR Article | Source rank | Code-level applicability |
|---|---|---|---|---|
| 1 | insecure_storage | Art. 32 (security of processing) | Enforcement Tracker most frequently cited article | Direct: storage encryption, transport-layer security, password hashing |
| 2 | consent_bypass | Art. 6 (lawful basis) + Art. 7 (consent conditions) | Enforcement Tracker top-3  | Direct: consent gate, opt-in flow, lawful-basis check |
| 3 | purpose_creep | Art. 5(1)(b) (purpose limitation) | Enforcement Tracker top-5 | Direct: cross-purpose data flow, scope leakage |
| 4 | pii_leakage | Art. 5(1)(f) (integrity & confidentiality) | Enforcement Tracker top-5 | Direct: log statement, error response, metric label |
| 5 | data_minimization | Art. 5(1)(c) (data minimization) | Enforcement Tracker top-5 | Direct: collection scope, schema PII columns |
| 6 | data_retention | Art. 5(1)(e) (storage limitation) | Enforcement Tracker top-10 | Direct: TTL on caches, deletion logic, retention metadata |
| 7 | third_party_sharing | Art. 28 (processors) | Enforcement Tracker top-10 | Direct: outbound API call with personal data |
| 8 | cross_border_transfer | Art. 44–49 (international transfers) | Enforcement Tracker top-10 (boosted by Schrems II rulings 2020+) | Direct: outbound API call with destination outside EEA |
| 9 | re_identification_risk | Art. 4(5) (pseudonymisation definition) | Derived from Art. 32 fines that cite weak anonymization | Direct: hash function selection, quasi-identifier exports |
| 10 | right_to_erasure | Art. 17 (right to be forgotten) + CCPA §1798.105 | Enforcement Tracker top-10; **CCPA top-3 enforcement category** | Direct: deletion endpoint, cascade-delete, soft-delete |

**Excluded by review-out-of-scope** (code review cannot verify):

- Art. 13–14 (information to data subjects): UI/policy text concern, not code
- Art. 15–22 (data subject access rights generally): require ops processes beyond what a code reviewer sees, except for Art. 17 erasure which is code-implementable
- Art. 33–34 (breach notification): organizational process, not code
- Art. 35 (data protection impact assessments): policy-process artifact

**Coverage gap acknowledged**: HIPAA, PCI-DSS, GLBA, and sector-specific privacy regulations are not represented. The benchmark is GDPR + CCPA focused. Extending to sector-specific regulations is future work.

---

## Cross-domain cases (8 total)

Cross-domain cases exercise the unification claim — the central architectural thesis of SecPriv. They are not ranked by external popularity; their selection criterion is that the same code line or flow simultaneously constitutes a security weakness *and* a privacy violation, such that a two-skill (separate sec + separate priv) deployment would emit two uncoordinated findings while SecPriv emits one cross-referenced finding.

| ID | Spans (security ∩ privacy) | Source rationale |
|---|---|---|
| X-TP-01 | auth_bypass (admin endpoint) + third_party_sharing (raw PII to audit) | admin-endpoint exfil is the canonical industry breach pattern |
| X-TP-02 | auth_bypass (unsigned webhook) + pii_leakage (payload logged) | Stripe/Twilio/GitHub webhook breach pattern |
| X-TP-03 | second_order_sqli (stored field → raw query) + pii_leakage (stored field is PII) | the most architecturally-novel cross-flow |
| X-TN-01 | JWT auth + salted hash + declared third-party URL | suppression on both surfaces |
| X-TN-02 | HMAC signature + salted-hash payload summary | suppression on both surfaces |
| X-TN-03 | Confirmation-gated agent + explicit consent + declared sink | agent-CSRF + consent intersection |
| X-TN-04 | Parameterized SQL returning hashed identifiers under documented legitimate interest | exercises both R5 (transformation adequacy) and R2 (framework auto-protection) |
| X-TN-05 | DPA-bound processor + encrypted-at-rest + decorator-protected admin | three protective constructs in scope simultaneously |

---

## Within-category construct variants (3 cases per category)

For each category, the three TP cases must exercise *structurally distinct* construct variants — not just three minor restatements of the same pattern. The variant-selection criterion is: each variant reflects a real-world API or framework usage pattern that an engineer would plausibly write.

The within-category variant set addresses an empirical finding from the predecessor SecReview skill: within-category recall variation is as large as between-category variation. F-string SQL injection is detected reliably; `.format()` SQL injection is not; both are technically the same CWE-89.

A representative selection (full list in the ground truth):

- **sql_injection**: f-string · `.format()` · raw `text()` in SQLAlchemy
- **command_injection**: `shell=True` · `os.popen` · `os.system`
- **path_traversal**: raw concat · `Path(user)/file` · zip-slip during extract
- **xss**: Jinja `\|safe` · `dangerouslySetInnerHTML` · raw `Markup(user)`
- **auth_bypass**: missing decorator · IDOR (no ownership check) · JWT alg=none
- **hardcoded_secret**: API key literal · DB password literal · JWT signing key literal
- **deserialization**: `pickle.loads` · `yaml.load` (unsafe) · `joblib.load`
- **ssrf**: arbitrary URL fetch · cloud metadata IP fetch · `file://` scheme
- **crypto_misuse**: MD5 password hashing · hardcoded IV · `random.random()` for tokens
- **insecure_storage**: PII column without encryption · plaintext password · DB connection without TLS
- **right_to_erasure**: no delete endpoint · soft-delete only · missing cascade delete

---

## Held-out validation set (10 of 30 TNs)

To prevent suppression-rule calibration from inflating the reported TN-rate, 10 of the 30 TN cases are designated held-out:

- 5 security TNs that exercise discrimination boundaries the rule set has *not* been tuned against
- 5 privacy TNs likewise

The held-out subset is fixed in `ground_truth.json` with a `holdout: true` flag; the boolean is set at benchmark-creation time and **must not be inspected during suppression-rule editing**. The paper will report TN-rate both on the full 30-case TN set and on the 20-case calibration subset and the 10-case held-out subset separately, so reviewers can directly read the generalization gap.

---

## Coverage statistics

| Dimension | Coverage |
|---|---|
| MITRE Top 25 (2025) categories covered | 8 of 25 |
| MITRE Top 25 categories excluded by Python scope | 4 (memory-safety) |
| MITRE Top 25 categories *not yet* covered | 7 |
| OWASP Top 10 (2021) categories covered | 8 of 10 |
| GDPR Enforcement Tracker top-10 articles covered | 10 of 10 |
| CCPA top-3 enforcement categories covered | 1 of 3 (Art. 17 / §1798.105) |
| Cross-jurisdiction coverage | GDPR + partial CCPA |

The remaining 7 MITRE Top 25 categories not covered (mostly hardware-, kernel-, and C-language-specific weaknesses) are out of scope for an application-code reviewer. The 2 of 3 CCPA categories not covered (right to opt-out of sale; right to non-discrimination for exercising rights) require business-process artifacts beyond what a code reviewer can verify.

---

## Update procedure

This document and the benchmark should be re-checked annually against:

1. The current MITRE CWE Top 25 (released ~Q3 each year)
2. The current OWASP Top 10 (released approximately every four years; 2021 is current as of 2026)
3. The current Enforcement Tracker dataset (continuously updated)

Categories that drop out of the source rankings should be reviewed for continued inclusion; new categories appearing in the rankings should be added.

---

## References

- MITRE Corporation. *2024 CWE Top 25 Most Dangerous Software Weaknesses*. <https://cwe.mitre.org/top25/>
- OWASP Foundation. *OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks*. <https://owasp.org/Top10/>
- CMS Hasche Sigle. *GDPR Enforcement Tracker*. <https://www.enforcementtracker.com/>
- California Office of the Attorney General. *CCPA Enforcement Actions*. <https://oag.ca.gov/privacy/ccpa/enforcement>
- European Parliament and Council. *Regulation (EU) 2016/679 (General Data Protection Regulation)*. *Official Journal of the European Union*, 2016.
- California State Legislature. *California Consumer Privacy Act of 2018 (CCPA)*. Cal. Civ. Code §§ 1798.100–1798.199, 2018.
