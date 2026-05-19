# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Cross-domain cases: 8 total = 4 inherited + 4 new.
"""

from __future__ import annotations


def build_cross(cases: list[dict], add_case) -> None:  # type: ignore[no-untyped-def]
    # ============================================================
    # Inherited cross-domain (4)
    # ============================================================
    add_case(
        cases,
        "X-TP-01",
        "cross",
        "x_admin_pii.py",
        "",
        "cross_tp",
        [
            {
                "surface": "security",
                "category": "auth_bypass",
                "line": 14,
                "cwe": "CWE-287",
                "severity": "HIGH",
                "flow_id": "x01-admin",
            },
            {
                "surface": "privacy",
                "category": "third_party_sharing",
                "line": 18,
                "regulatory_basis": "GDPR Art. 28",
                "severity": "HIGH",
                "flow_id": "x01-admin",
            },
        ],
        inherited=True,
        acceptable=[
            {
                "surface": "privacy",
                "category": "pii_leakage",
                "line": 17,
                "severity": "HIGH",
            }
        ],
    )
    add_case(
        cases,
        "X-TP-02",
        "cross",
        "x_webhook_unsigned.py",
        "",
        "cross_tp",
        [
            {
                "surface": "security",
                "category": "auth_bypass",
                "line": 12,
                "cwe": "CWE-287",
                "severity": "HIGH",
                "flow_id": "x02-webhook",
            },
            {
                "surface": "privacy",
                "category": "pii_leakage",
                "line": 14,
                "regulatory_basis": "GDPR Art. 5(1)(f)",
                "severity": "HIGH",
                "flow_id": "x02-webhook",
            },
        ],
        inherited=True,
    )
    add_case(
        cases,
        "X-TN-01",
        "cross",
        "x_safe_admin_hashed.py",
        "",
        "cross_tn",
        [],
        boundary="auth + salted-hash + declared third-party = no security or privacy violation",
        inherited=True,
    )
    add_case(
        cases,
        "X-TN-02",
        "cross",
        "x_safe_webhook_signed.py",
        "",
        "cross_tn",
        [],
        boundary="signed webhook + hashed-summary log = no security or privacy violation",
        inherited=True,
    )

    # ============================================================
    # Additional cross-domain (4)
    # ============================================================

    # X-TP-03: stored field is both attacker-controlled (second-order SQLi) and PII
    add_case(
        cases,
        "X-TP-03",
        "cross",
        "x_so_pii.py",
        '''
        """User profile bio is stored, then later concatenated into a raw analytics
        query AND surfaced to a public dashboard — second-order SQLi + PII leakage."""
        from flask import Flask, request, jsonify
        import sqlite3

        app = Flask(__name__)


        @app.route("/profile/bio", methods=["POST"])
        def save_bio():
            body = request.json
            sqlite3.connect("app.db").execute(
                "UPDATE users SET bio=?, email=? WHERE id=?",
                (body["bio"], body["email"], body["user_id"]),
            )
            return jsonify({"ok": True})


        @app.route("/admin/users")
        def admin_users():
            conn = sqlite3.connect("app.db")
            row = conn.execute("SELECT bio, email FROM users WHERE id=1").fetchone()
            stored_bio, stored_email = row[0], row[1]
            # Stored bio reused in a raw query — second-order SQL injection,
            # AND the email is returned to the dashboard in clear text — PII leakage.
            stats = conn.execute(
                "SELECT COUNT(*) FROM activity WHERE tag='" + stored_bio + "'"
            ).fetchone()
            return jsonify({"email": stored_email, "activity": stats[0]})
        ''',
        "cross_tp",
        [
            {
                "surface": "security",
                "category": "second_order_sqli",
                "line": 26,
                "cwe": "CWE-89",
                "severity": "HIGH",
                "flow_id": "x03-so-pii",
            },
            {
                "surface": "privacy",
                "category": "pii_leakage",
                "line": 29,
                "regulatory_basis": "GDPR Art. 5(1)(f)",
                "severity": "HIGH",
                "flow_id": "x03-so-pii",
            },
        ],
    )

    # X-TN-03: confirmation-gated agent + explicit consent + declared sink
    add_case(
        cases,
        "X-TN-03",
        "cross",
        "x_safe_agent_consent.py",
        '''
        """Agent action that requires both a confirmation step AND explicit consent."""
        from flask import Flask, request, jsonify, abort

        app = Flask(__name__)
        DECLARED_DOWNSTREAM = {"https://crm.example.com/sync"}


        def has_consent(user_id: str, scope: str) -> bool:
            return True


        def run_agent_action(action: str, target: str) -> dict:
            return {"ok": True}


        @app.route("/agent/preview")
        def preview_agent_action():
            # Step 1: returns a preview but does not execute. Confirmation
            # required before /agent/run is callable.
            return jsonify({"preview": request.args.to_dict(), "confirm_token": "abc"})


        @app.route("/agent/run", methods=["POST"])
        def run_agent_with_confirm():
            body = request.json
            if body.get("confirm_token") != "abc":
                abort(400, "missing confirmation")
            user_id = body["user_id"]
            if not has_consent(user_id, body.get("scope", "")):
                abort(403, "no consent")
            target = body.get("target", "")
            if target not in DECLARED_DOWNSTREAM:
                abort(400, "undeclared target")
            return jsonify(run_agent_action(body["action"], target))
        ''',
        "cross_tn",
        [],
        boundary="confirmation + consent + declared sink: not agent_csrf, not consent_bypass, not third_party_sharing",
    )

    # X-TN-04: parameterized SQL returning hashed identifiers under documented legitimate interest
    add_case(
        cases,
        "X-TN-04",
        "cross",
        "x_safe_sql_hashed_li.py",
        '''
        """Fraud-detection lookup using parameterized SQL and salted-hash response
        under documented legitimate interest."""
        from flask import Flask, request, jsonify
        import hashlib
        import os
        from sqlalchemy import create_engine, text

        app = Flask(__name__)
        engine = create_engine("postgresql://app@db/app")
        # Legitimate-interest assessment on file: docs/privacy/lia-fraud-2024.pdf.
        LIA_REF = "docs/privacy/lia-fraud-2024.pdf"


        def _salted_hash(value: str) -> str:
            salt = os.urandom(16)
            h = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 100_000)
            return salt.hex() + ":" + h.hex()


        @app.route("/fraud/check")
        def fraud_check():
            ip = request.args.get("ip", "")
            with engine.connect() as conn:
                # Parameterized query — no SQLi.
                rows = conn.execute(
                    text("SELECT user_id FROM logins WHERE ip = :ip LIMIT 5"),
                    {"ip": ip},
                ).fetchall()
            # Hashed user IDs returned — no raw PII.
            return jsonify({
                "matches": [_salted_hash(str(r[0])) for r in rows],
                "lawful_basis": LIA_REF,
            })
        ''',
        "cross_tn",
        [],
        boundary="parameterized SQL + salted hash + LIA: not sql_injection, not pii_leakage, not consent_bypass",
    )

    # X-TN-05: DPA-bound processor + encrypted-at-rest + decorator-protected admin
    add_case(
        cases,
        "X-TN-05",
        "cross",
        "x_safe_dpa_encrypted.py",
        '''
        """Admin export endpoint with auth, KMS-encrypted storage,
        and a documented DPA with the third-party processor."""
        from flask import Flask, request, jsonify
        from functools import wraps
        from cryptography.fernet import Fernet
        import os
        import requests

        app = Flask(__name__)
        # Wrapped under cloud KMS; resolved at runtime.
        FERNET_KEY = os.environ["KMS_FERNET_KEY"].encode()
        cipher = Fernet(FERNET_KEY)
        # DPA reference for the export processor:
        # docs/legal/dpa-2024-export-processor.pdf
        DPA_REF = "docs/legal/dpa-2024-export-processor.pdf"
        DECLARED_PROCESSOR = "https://processor.example.com/import"


        def require_admin(fn):
            @wraps(fn)
            def w(*a, **kw):
                tok = request.headers.get("Authorization", "")
                if not (tok.startswith("Bearer ") and _verify(tok[7:])):
                    return jsonify({"error": "forbidden"}), 403
                return fn(*a, **kw)
            return w


        def _verify(t: str) -> bool:
            return True


        @app.route("/admin/export", methods=["POST"])
        @require_admin
        def export():
            payload = request.get_data()
            # Encrypt before sending. The processor decrypts under DPA terms.
            ct = cipher.encrypt(payload)
            requests.post(DECLARED_PROCESSOR, data=ct,
                          headers={"X-DPA-Ref": DPA_REF})
            return jsonify({"sent": True})
        ''',
        "cross_tn",
        [],
        boundary="auth + encryption-at-rest + declared DPA processor: no security or privacy violation",
    )
