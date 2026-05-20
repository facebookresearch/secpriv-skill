<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# SecPriv — Unified Security and Privacy Code Review Skill

## Purpose

Perform a single-pass code review that surfaces both **security weaknesses** (CWE-mapped) and **privacy violations** (GDPR-mapped). The skill executes a five-phase methodology with a detector-validator decomposition: a detector phase enumerates candidate findings across both surfaces, and a validator phase applies seven shared suppression rules and a confidence threshold. The skill prioritizes precision over recall — only report findings with high confidence and a concrete violation path.

## When to Use

Invoke when reviewing code (single files, diffs, or pull requests) that may contain security weaknesses, privacy violations, or both. Optimized for Python and JavaScript/TypeScript; rules generalize to Java, Go, and Rust.

## Output Format

Return a JSON array of findings. Each entry MUST contain:

```json
{
  "surface": "security" | "privacy",
  "category": "<one of 30 canonical categories listed below>",
  "severity": "HIGH" | "MEDIUM" | "LOW",
  "confidence": 0.0,
  "file": "path/to/file.py",
  "line": 42,
  "description": "Concrete description of the violation in this file",
  "remediation": "Concrete fix",
  "cwe": "CWE-89",                    // security only
  "regulatory_basis": "GDPR Art. 5(1)(f)",  // privacy only
  "exploitation_path": "...",         // security only
  "flow_id": "string"                 // optional, links cross-domain findings
}
```

If no issues are found, return an empty array `[]`. Do not return findings with `confidence < 0.8`.

---

## Phase 1: Repository Context Research

Before assessing any change, establish three context items.

**1.1 Framework detection.** Identify what protective frameworks are in use by reading import statements:
- ORM layers (SQLAlchemy, Django ORM, Prisma, GORM) — auto-parameterize SQL
- Input sanitizers (DOMPurify, bleach, html.escape) — neutralize XSS
- Auth middleware (JWT decorators, session middleware, OAuth)
- Template engines with auto-escape (Jinja2 default, React JSX, Angular)
- Consent libraries / privacy SDKs

**1.2 Trust boundaries.**
- **Untrusted**: HTTP request fields (params, headers, body, cookies, URL paths)
- **Semi-trusted**: database values, cache entries, application config tables, feature flags (these may have admin-API write paths)
- **Trusted**: OS environment variables, compile-time constants

**Critical rule**: Application-level config (feature flags, settings tables, admin-editable) is **NOT** trusted — only OS env vars and compile-time constants are.

**1.3 Personal-data inventory.** Identify what categories of personal data appear (PII identifiers, financial, health, location), what consent mechanisms are present, and what regulations apply.

---

## Phase 2: Source / Sink and Transformation Flow Mapping

Trace data from sources to sinks. For each flow, record the source category, the sink category, and the **transformation state** of the data as it reaches the sink.

**Source categories.**
- Untrusted-input source: HTTP fields, file uploads, webhook payloads, query strings
- Personal-data source (Tang et al. taxonomy): account, contact, national ID, personal ID, online ID, location, health, financial

**Sink categories.**
- Security-sensitive sinks: SQL execution, shell execution, eval/exec, template rendering, file open, network request, auth check
- Personal-data sinks: data manipulation, transportation, creation/deletion, database write, encryption, log

**Transformation state at sink.**
| State | Adequate? |
|-------|-----------|
| `raw` | NO — likely violation |
| `salted_hash` (with random per-record salt) | YES for logging/identifiers |
| `unsalted_hash` (e.g., SHA-256 of email) | NO — re-identification risk via rainbow tables |
| `aggregated` with k ≥ 5 grouping | YES |
| `encrypted` with KMS-managed key | YES (verify key handling) |
| `tokenized` via vault | YES |
| `base64`, `hex`, `rot13`, plain encoding | NO — reversible, not anonymization |

This single transformation classifier serves both surfaces. A `salted_hash` PII output suppresses both `pii_leakage` and any stored-XSS candidate that would arise from rendering the same field.

---

## Phase 3: Dual-Surface Vulnerability Assessment

Assess against **30 canonical categories: 20 security and 10 privacy**.

### 3.1 Security Categories (20)

**`sql_injection`** (CWE-89): user input reaching SQL via f-string, `.format()`, string concatenation, or SQLAlchemy `text()` with `+`/format. Safe: ORM `.where()` / `.filter_by()`, parameterized queries with `?`/`%s` placeholders, SQLAlchemy `text()` with `:bind` parameters.

**`command_injection`** (CWE-78): user input in `subprocess.run(..., shell=True)`, `os.system`, `os.popen`, or any `Popen` with `shell=True`. Safe: `subprocess.run([cmd, arg1, ...])` with list args (no shell).

**`path_traversal`** (CWE-22): user input in file paths without sanitization, including raw concatenation, `pathlib.Path(BASE) / user_input` without resolve-and-contain, and zip-slip during `extractall()`. Safe: `os.path.realpath()` + prefix containment check; `pathlib.Path.resolve()` then verify the resolved path stays within an expected base directory.

**`xss`** (server-side, CWE-79): user input rendered in server-rendered HTML without escaping. Patterns: Jinja2 `|safe` filter on user input, `Markup(user_input)`, server-side `string.Template().substitute()` into HTML, raw template-string interpolation. Safe: React JSX rendering (auto-escapes), default Jinja2 mode (auto-escapes), Angular sanitization, `html.escape()` before insertion.

**`xss_dom`** (CWE-79 DOM-based): client-side JavaScript writes attacker-influenced data into the DOM without escaping. Patterns: `element.innerHTML = userInput`, `document.write(userInput)`, jQuery `$elt.html(userInput)`, `outerHTML` assignment. Safe: `textContent`, `setAttribute` with safe attrs, framework-managed rendering.

**`auth_bypass`** (CWE-287 / CWE-863): admin endpoints without auth middleware; missing permission checks; JWT validation bypass (e.g., `algorithms=None`, `verify_signature=False`); IDOR (no ownership check on resource access); missing webhook signature verification.

**`hardcoded_secret`** (CWE-798): literal API keys (`sk_live_…`, `SG.…`), DB passwords in connection strings, JWT signing keys, `aws_secret_access_key=…` literals. Safe: read from `os.environ`, `process.env`, secret manager APIs, KMS-managed credentials.

**`deserialization`** (CWE-502): `pickle.loads()` on attacker-controlled data; `yaml.load()` without `SafeLoader`; `joblib.load()` of attacker-supplied files; `marshal.loads()`. Safe: `yaml.safe_load()`, `json.loads()`, `pickle.loads()` only on internally-produced bytes with path validation.

**`eval_injection`** (CWE-94): `eval()` / `exec()` on user input; dynamic `__import__(user_input)` followed by attribute access. Safe: `ast.literal_eval()` for parsing literals, an explicit allowlisted dispatch table.

**`infinite_loop`** (CWE-835 / CWE-674): self-referential redirects, recursion without termination, retry loops without max-attempts cap, recursive directory walks without depth bounds or symlink-cycle detection.

**`agent_csrf`** (CWE-352 generalized for LLM agents): URL parameter, webhook payload, or deep link auto-triggering an agent write/exec without an interstitial confirmation step. Safe: confirmation dialog with explicit submit token, read-only preview followed by separate execution endpoint.

**`second_order_sqli`** (CWE-89 retrieval-side): user-controlled value stored in DB/cache/config, later retrieved and concatenated into a raw query, template, or outbound URL without sanitization. Includes stored-SSRF and stored-SSTI variants where the stored value's ultimate sink is a network fetch or template render rather than SQL.

**`ssrf`** (CWE-918): user-controlled URL passed to a server-side fetch (`requests.get`, `urllib.urlopen`, `httpx.get`) without scheme allowlist, host allowlist, or private-IP-range check. Particularly dangerous: cloud-metadata IPs (`169.254.169.254`), `file://` scheme, internal-only hostnames. Safe: explicit URL allowlist + DNS resolution + private-IP rejection.

**`open_redirect`** (CWE-601): user-controlled value passed to `redirect()`, `Location` header, server-rendered JS `location=`, or OAuth callback `redirect_uri` without validation. Safe: `url_for(name)` with a fixed allowlist of named routes.

**`crypto_misuse`** (CWE-327 / CWE-329 / CWE-330): broken or risky cryptographic primitive — MD5/SHA-1 for password hashing, hardcoded IV in CBC mode, ECB mode for non-trivial data, `random.random()` / `random.choice()` for tokens or session IDs. Safe: bcrypt/argon2/scrypt for passwords, random per-message IV, `secrets.token_urlsafe()` / `secrets.token_bytes()` for tokens.

**`xxe`** (CWE-611): XML parser configured with default entity resolution on attacker-controlled input — `lxml.etree.fromstring()` without `resolve_entities=False`, explicit `xinclude()` on user XML. Safe: `etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`.

**`ssti`** (CWE-1336): server-side template injection — `Template(user_input).render(...)` for Jinja2 / Mako / Twig with attacker-controlled template body, or `str.format(obj)` with user-controlled format spec walking attribute chains (`"{0.api_key}"`).

**`csrf`** (CWE-352): state-changing endpoint (POST/PUT/DELETE) without CSRF token check; session cookie set with `SameSite=None` and no token; mutating action exposed on a GET endpoint. Safe: framework CSRF middleware (`@csrf_protect`, Flask-WTF, Django CSRF), `SameSite=Strict` or `Lax` cookies.

**`race_condition`** (CWE-362 / CWE-367): TOCTOU file checks (`os.path.exists()` then `open()`); read-then-write balance updates without a transaction or row-level lock; check-then-insert without a unique index. Safe: atomic file-open flags (`O_EXCL | O_CREAT`), `BEGIN IMMEDIATE` / `SELECT ... FOR UPDATE`, unique constraints.

**`insecure_logging`** (CWE-532): secrets, tokens, full PII payloads, or full request headers (which include `Authorization`) written to application logs. Particularly dangerous in exception handlers that dump `request.headers` or full payload bodies. Safe: log identifiers as salted hashes, redact `Authorization` and other sensitive headers before logging.

### 3.2 Privacy Categories (10)

**`pii_leakage`** (GDPR Art. 5(1)(f)): personal data in logs, error responses, metric labels, stack traces. Includes indirect identifiers that combine into PII (zip + DOB + gender).

**`data_retention`** (Art. 5(1)(e)): PII stored without TTL; missing deletion logic; indefinite caches; audit logs without retention; schema columns without retention metadata or scheduled-purge job.

**`consent_bypass`** (Art. 6, 7): processing without verified consent, OR consent check located AFTER the processing it should gate, OR commented-out consent verification.

**`third_party_sharing`** (Art. 28): personal data sent to external services without anonymization or appropriate safeguards. Distinguish from `cross_border_transfer` — this category is about *any* third-party send; that one is specifically about sends across the EEA boundary.

**`re_identification_risk`** (Art. 4(5)): unsalted hashing of identifiers, quasi-identifier exports (zip + DOB + gender uniquely identifies 87% of the US population), reversible encoding (base64, hex, ROT13) labelled as anonymization.

**`data_minimization`** (Art. 5(1)(c)): collecting more PII than the operation needs; storing PII columns that are never read by application code; OAuth scope requests broader than needed (`full_profile` when only `email` is used).

**`purpose_creep`** (Art. 5(1)(b)): personal data collected for one purpose used for an unrelated purpose without re-consent. Look for cross-module data transfers and parameter names that mismatch the sink (e.g., `shipping_address` reaching `ad_targeting_engine`, `support_transcript` reaching `training_corpus`).

**`insecure_storage`** (Art. 32): PII stored without encryption-at-rest in a sensitive column (e.g., `ssn`, `password` as plain `String`); database connection string with `sslmode=disable` carrying PII over the wire. Safe: KMS-managed encryption-at-rest, TLS-enforced connection strings, bcrypt-hashed password columns.

**`cross_border_transfer`** (Art. 44–49): PII transferred from the EEA to a third country with no documented safeguard — no Standard Contractual Clauses (SCCs), no adequacy decision, no Binding Corporate Rules (BCR). Safe: explicit reference to a documented SCC / BCR / adequacy basis adjacent to the transfer call.

**`right_to_erasure`** (Art. 17 / CCPA §1798.105): user-account API exposes create/read/update but no delete endpoint; `delete_user()` only sets a deleted-at flag (soft-delete) with PII fields persisting; user row deleted but PII in derived tables (comments, activity_log, payment_history) not cascaded. Safe: explicit cascade-delete across all PII-bearing tables triggered by an erasure endpoint.

### 3.3 Cross-Surface Findings

If a single line/flow constitutes both a security AND a privacy issue (e.g., a logging statement that exposes both a session token and an email), emit TWO findings — one per surface — sharing the same `flow_id`. This preserves the option to deduplicate downstream.

---

## Phase 4: Validator and False-Positive Filtering

Each candidate finding is independently checked against seven suppression rules. Suppress if ANY rule fires (except R7 unsuppressible-evidence, which overrides).

**R1. Concrete violation path.** Construct an end-to-end path from source to sink with no protective transformation. If you cannot, suppress.

**R2. Framework auto-protection.** Suppress if a framework or established defensive primitive neutralizes the pattern in scope. Examples: ORM-parameterized SQL via `.where()` / `:bind` placeholders; React JSX rendering (no `dangerouslySetInnerHTML`); default Jinja2 auto-escape; declared consent-library gating; declared URL allowlist + private-IP rejection (SSRF defense); `url_for(name)` with named-route allowlist (open-redirect defense); bcrypt/argon2 with per-record salt (crypto defense); `XMLParser(resolve_entities=False, no_network=True)` (XXE defense); atomic file flags `O_EXCL | O_CREAT` or row-level lock (race-condition defense); framework CSRF middleware (`@csrf_protect`, Flask-WTF); `ast.literal_eval` (eval defense); `secrets.token_urlsafe()` for tokens; salted-hash + declared third-party URL (sharing defense); cascade-delete across all PII tables (erasure defense); documented SCC / BCR / adequacy reference adjacent to cross-border transfer.

**R3. Test/documentation scope.** Suppress credentials and PII findings in `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`, `*_test.py`, `*.spec.ts` — but NOT logic findings (auth bypass in a test endpoint may indicate production flaw).

**R4. Trusted source.** Values from `os.environ`, `process.env`, `std::env`, compile-time constants are not hardcoded secrets.

**R5. Transformation adequacy (privacy).** If the transformation state at the sink is `salted_hash`, k-aggregated (k ≥ 5), `encrypted` with KMS-managed key, or `tokenized` via vault, suppress the privacy finding. `unsalted_hash`, `base64`, `hex` are NOT adequate.

**R6. Same-purpose reuse.** Personal data reused for the same purpose for which it was collected (registration email → password reset) is not purpose creep. Different purpose (registration email → ad-targeting cohort) is.

**R7. Unsuppressible evidence.** The following are HIGH severity regardless of context:
- Literal `SECRET_KEY = "..."`, `PRIVATE_KEY = "..."`, `aws_secret_access_key = "..."`
- Plain-text national-ID numbers (SSN format `\d{3}-\d{2}-\d{4}`)
- Plain-text passwords stored or transmitted without hashing

**Confidence threshold.** Findings with `confidence < 0.8` are NOT included in the output. Findings between 0.6 and 0.8 should be omitted entirely (do not emit them as advisory).

---

## Phase 5: Standards Mapping

For each surviving finding, attach the appropriate reference identifier:
- Security: CWE-ID (e.g., `"cwe": "CWE-89"`)
- Privacy: GDPR article reference (e.g., `"regulatory_basis": "GDPR Art. 5(1)(f)"`)

Provide a one-paragraph remediation directly actionable by the developer.

---

## Category Alias Normalization

When you decide on a category, use exactly one of these **30 canonical strings**:

*Security (20):* `sql_injection`, `command_injection`, `path_traversal`, `xss`, `xss_dom`, `auth_bypass`, `hardcoded_secret`, `deserialization`, `eval_injection`, `infinite_loop`, `agent_csrf`, `second_order_sqli`, `ssrf`, `open_redirect`, `crypto_misuse`, `xxe`, `ssti`, `csrf`, `race_condition`, `insecure_logging`.

*Privacy (10):* `pii_leakage`, `data_retention`, `consent_bypass`, `third_party_sharing`, `re_identification_risk`, `data_minimization`, `purpose_creep`, `insecure_storage`, `cross_border_transfer`, `right_to_erasure`.

Do NOT emit sub-categories like `sql_injection_fstring`, `logging_pii`, `weak_md5`, or `right_to_be_forgotten` — map to the canonical category and use that string. The runner's alias table maps common surface forms back to the canonical labels, but you should emit the canonical string directly when possible.

---

## Output Discipline

- Return ONLY a JSON array. No prose, no markdown fences, no explanation outside the JSON.
- Empty array `[]` if the file has no high-confidence findings.
- One finding per (file, line, category) triple. For cross-surface findings on the same line, use the shared `flow_id` mechanism (Phase 3.3).
- Do not over-explain. The `description` field is one sentence. The `remediation` field is one sentence.
