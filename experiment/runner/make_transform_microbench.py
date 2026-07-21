# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Generate the transformation-adequacy micro-benchmark (C1-vs-C7 ablation).

The 128-case and real-CVE sets are dominated by raw->sink bugs, so SecPriv's
Phase-2 transformation classifier (+ rule R5) is dormant and the C1-vs-C7 ablation
reads neutral. This micro-benchmark concentrates the classifier's *trigger* cases:
every case sends personal data to a sink (log / store / export / send / render), so
a classifier-blind pass is tempted to flag it -- but whether it is a real finding
depends entirely on the transformation state at the sink.

Three groups:
  * ADEQUATE (TN): salted-hash / KMS-encrypt / k>=5 aggregate / vault-tokenize /
    bcrypt. The finding should be SUPPRESSED. C1 (classifier + R5) should stay
    silent; C7 (ablated) is expected to over-flag -> false positives.
  * INADEQUATE (TP, controls): base64 / unsalted-hash / hex / raw. Reversible or
    absent -> the finding MUST fire in both C1 and C7 (proves the classifier
    discriminates, not merely suppresses).
  * CROSS-SURFACE: one transformation decision governs BOTH a privacy and a
    security finding on the same field (SKILL.md line 88).

Writes test_cases/transform/*.py + ground_truth_transform.json. Hand-written =>
this is a MECHANISM demonstration, not an external-validity claim.
"""

from __future__ import annotations

import json
from pathlib import Path

EXPERIMENT = Path(__file__).resolve().parent.parent
OUT_DIR = EXPERIMENT / "test_cases" / "transform"
GT_OUT = EXPERIMENT / "ground_truth_transform.json"

LICENSE = "# Copyright (c) Meta Platforms, Inc. and affiliates.\n"

# Each entry: (id, kind, filename, expected[list of (surface,category)], boundary, code)
# Expected line is filled in automatically from a `# <<SINK` marker in the code.
CASES: list[tuple] = [
    # ---------- ADEQUATE transformation -> true negatives ----------
    (
        "TA-01",
        "privacy_tn",
        "ta_salted_hash_store.py",
        [],
        "salted_hash (random per-record salt) vs raw email at DB write",
        """import hashlib
import secrets

def store_user_pseudonym(email: str, db) -> None:
    # random per-record salt -> irreversible pseudonym, not the address
    salt = secrets.token_bytes(16)
    pseudonym = hashlib.pbkdf2_hmac("sha256", email.encode(), salt, 200_000)
    db.insert("users", salt=salt.hex(), pseudonym=pseudonym.hex())  # <<SINK
""",
    ),
    (
        "TA-02",
        "privacy_tn",
        "ta_kms_encrypt_store.py",
        [],
        "KMS-encrypted SSN vs cleartext at DB write",
        """import os

from cryptography.fernet import Fernet

_cipher = Fernet(os.environ["KMS_FERNET_KEY"].encode())

def save_patient(ssn: str, db) -> None:
    # encrypted-at-rest with a KMS-managed key
    ciphertext = _cipher.encrypt(ssn.encode())
    db.insert("patients", ssn_enc=ciphertext)  # <<SINK
""",
    ),
    (
        "TA-03",
        "privacy_tn",
        "ta_kanon_export.py",
        [],
        "k>=5 aggregation vs per-user rows at export",
        """def export_region_stats(db) -> list:
    # only groups with k>=5 members leave the system
    return db.query(
        "SELECT region, COUNT(*) AS n FROM users "
        "GROUP BY region HAVING COUNT(*) >= 5"  # <<SINK
    )
""",
    ),
    (
        "TA-04",
        "privacy_tn",
        "ta_vault_tokenize.py",
        [],
        "vault-tokenized card vs raw PAN in log",
        """import logging

logger = logging.getLogger(__name__)

def record_payment(card_number: str, vault) -> None:
    # PAN replaced by an opaque vault token before it ever reaches the log
    token = vault.tokenize(card_number)
    logger.info("charged card token=%s", token)  # <<SINK
""",
    ),
    (
        "TA-05",
        "privacy_tn",
        "ta_encrypt_thirdparty.py",
        [],
        "encrypted-to-recipient payload vs cleartext PII to third party",
        """import os

import requests
from cryptography.fernet import Fernet

_partner = Fernet(os.environ["PARTNER_KMS_KEY"].encode())

def sync_profile(profile: dict) -> None:
    # encrypted for the recipient before leaving our boundary
    blob = _partner.encrypt(str(profile).encode())
    requests.post("https://partner.example.com/ingest", data=blob)  # <<SINK
""",
    ),
    (
        "TA-06",
        "security_tn",
        "ta_bcrypt_password.py",
        [],
        "bcrypt+salt vs cleartext password at store",
        """import bcrypt

def register(password: str, db) -> None:
    # per-record salt + adaptive KDF
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    db.insert("accounts", pw_hash=hashed)  # <<SINK
""",
    ),
    # ---------- INADEQUATE transformation -> true positives (controls) ----------
    (
        "TB-01",
        "privacy_tp",
        "tb_base64_log.py",
        [("privacy", "pii_leakage")],
        "base64 (reversible) email in log",
        """import base64
import logging

logger = logging.getLogger(__name__)

def audit(email: str) -> None:
    # base64 is encoding, not anonymization -> still a leak
    encoded = base64.b64encode(email.encode()).decode()
    logger.info("user %s", encoded)  # <<SINK
""",
    ),
    (
        "TB-02",
        "privacy_tp",
        "tb_unsalted_hash_store.py",
        [("privacy", "pii_leakage")],
        "unsalted SHA-256 (rainbow-table reversible) email at store",
        """import hashlib

def index_user(email: str, db) -> None:
    # unsalted hash of a low-entropy identifier -> re-identifiable
    digest = hashlib.sha256(email.encode()).hexdigest()
    db.insert("user_index", email_hash=digest)  # <<SINK
""",
    ),
    (
        "TB-03",
        "privacy_tp",
        "tb_hex_ssn_store.py",
        [("privacy", "insecure_storage")],
        "hex-encoded (reversible) SSN at store",
        """def save_ssn(ssn: str, db) -> None:
    # hex is a reversible encoding, not encryption
    db.insert("people", ssn_hex=ssn.encode().hex())  # <<SINK
""",
    ),
    (
        "TB-04",
        "privacy_tp",
        "tb_raw_log.py",
        [("privacy", "pii_leakage")],
        "raw PII (no transformation) in log",
        """import logging

logger = logging.getLogger(__name__)

def audit(email: str, ssn: str) -> None:
    logger.info("user=%s ssn=%s", email, ssn)  # <<SINK
""",
    ),
    # ---------- CROSS-SURFACE: one transformation, both surfaces ----------
    (
        "TC-01",
        "cross_tn",
        "tc_salted_render_safe.py",
        [],
        "salted_hash field is inert -> neither pii_leak nor stored-XSS",
        """import hashlib
import secrets

def profile_badge(display_name: str) -> str:
    # hashed field is opaque hex: not personal data AND not renderable markup
    salt = secrets.token_bytes(16)
    tag = hashlib.pbkdf2_hmac("sha256", display_name.encode(), salt, 200_000).hex()
    return f"<span class='badge'>{tag}</span>"  # <<SINK
""",
    ),
    (
        "TC-02",
        "cross_tp",
        "tc_raw_render_unsafe.py",
        [("privacy", "pii_leakage"), ("security", "xss")],
        "raw user field -> both stored-XSS and pii_leak on the same flow",
        """import logging

logger = logging.getLogger(__name__)

def profile_page(display_name: str) -> str:
    logger.info("render profile for %s", display_name)
    return f"<h1>Welcome {display_name}</h1>"  # <<SINK
""",
    ),
]


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    gt_cases = []
    for cid, kind, fname, expected, boundary, code in CASES:
        body = LICENSE + "\n" + code
        (OUT_DIR / fname).write_text(body)
        sink_line = next(
            i + 1 for i, ln in enumerate(body.splitlines()) if "<<SINK" in ln
        )
        findings = [
            {"surface": s, "category": c, "line": sink_line} for (s, c) in expected
        ]
        case = {
            "case_id": cid,
            "file": f"test_cases/transform/{fname}",
            "kind": kind,
            "expected_findings": findings,
        }
        if not findings:
            case["boundary"] = boundary
        gt_cases.append(case)
    GT_OUT.write_text(
        json.dumps(
            {
                "description": "transformation-adequacy micro-benchmark",
                "cases": gt_cases,
            },
            indent=2,
        )
        + "\n"
    )
    tn = sum(1 for c in gt_cases if not c["expected_findings"])
    print(
        f"wrote {len(gt_cases)} cases ({tn} TN / {len(gt_cases) - tn} TP) -> {GT_OUT}"
    )


if __name__ == "__main__":
    main()
