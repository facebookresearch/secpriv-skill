"""
Privacy cases: 30 TPs (10 categories x 3 variants each) + 15 near-miss
TNs (10 calibration + 5 held-out).

Cases inherited from earlier benchmark iterations are kept under their
original filenames; the rest are authored here.
"""

from __future__ import annotations


def build_privacy(cases: list[dict], add_case) -> None:  # type: ignore[no-untyped-def]
    # ============================================================
    # Inherited TPs (10)
    # ============================================================
    add_case(
        cases,
        "P-TP-01",
        "privacy",
        "p_log_email.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "pii_leakage",
                "line": 19,
                "regulatory_basis": "GDPR Art. 5(1)(f)",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "P-TP-02",
        "privacy",
        "p_log_metric.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "pii_leakage",
                "line": 11,
                "regulatory_basis": "GDPR Art. 5(1)(f)",
                "severity": "MEDIUM",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "P-TP-03",
        "privacy",
        "p_retention_cache.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "data_retention",
                "line": 9,
                "regulatory_basis": "GDPR Art. 5(1)(e)",
                "severity": "MEDIUM",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "P-TP-04",
        "privacy",
        "p_consent_missing.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "consent_bypass",
                "line": 22,
                "regulatory_basis": "GDPR Art. 6",
                "severity": "HIGH",
            }
        ],
        inherited=True,
        acceptable=[
            {
                "surface": "privacy",
                "category": "purpose_creep",
                "line": 22,
                "severity": "MEDIUM",
            }
        ],
    )
    add_case(
        cases,
        "P-TP-05",
        "privacy",
        "p_consent_temporal.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "consent_bypass",
                "line": 19,
                "regulatory_basis": "GDPR Art. 7",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "P-TP-06",
        "privacy",
        "p_3p_analytics.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "third_party_sharing",
                "line": 17,
                "regulatory_basis": "GDPR Art. 28",
                "severity": "HIGH",
            }
        ],
        inherited=True,
        acceptable=[
            {
                "surface": "privacy",
                "category": "consent_bypass",
                "line": 17,
                "severity": "HIGH",
            }
        ],
    )
    add_case(
        cases,
        "P-TP-07",
        "privacy",
        "p_reid_unsalted.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "re_identification_risk",
                "line": 9,
                "regulatory_basis": "GDPR Art. 4(5)",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "P-TP-08",
        "privacy",
        "p_reid_quasi.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "re_identification_risk",
                "line": 9,
                "regulatory_basis": "GDPR Art. 4(5)",
                "severity": "HIGH",
            }
        ],
        inherited=True,
        acceptable=[
            {
                "surface": "privacy",
                "category": "pii_leakage",
                "line": 11,
                "severity": "HIGH",
            }
        ],
    )
    add_case(
        cases,
        "P-TP-09",
        "privacy",
        "p_minimization.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "data_minimization",
                "line": 17,
                "regulatory_basis": "GDPR Art. 5(1)(c)",
                "severity": "MEDIUM",
            }
        ],
        inherited=True,
        acceptable=[
            {
                "surface": "privacy",
                "category": "consent_bypass",
                "line": 18,
                "severity": "MEDIUM",
            },
            {
                "surface": "privacy",
                "category": "data_retention",
                "line": 18,
                "severity": "MEDIUM",
            },
        ],
    )
    add_case(
        cases,
        "P-TP-10",
        "privacy",
        "p_purpose_creep.py",
        "",
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "purpose_creep",
                "line": 22,
                "regulatory_basis": "GDPR Art. 5(1)(b)",
                "severity": "MEDIUM",
            }
        ],
        inherited=True,
        acceptable=[
            {
                "surface": "privacy",
                "category": "consent_bypass",
                "line": 24,
                "severity": "HIGH",
            }
        ],
    )

    # ============================================================
    # Additional TPs to bring each pre-existing category to 3 cases (11)
    # ============================================================

    # pii_leakage variant C (have A=p_log_email, B=p_log_metric)
    add_case(
        cases,
        "P-TP-11",
        "privacy",
        "p_log_stack.py",
        '''
        """Stack trace exposes user email in 5xx response body."""
        from flask import Flask, request, jsonify
        import traceback

        app = Flask(__name__)


        def find_user(email: str) -> dict:
            raise KeyError("not found: " + email)


        @app.route("/lookup")
        def lookup():
            email = request.args.get("email", "")
            try:
                return jsonify(find_user(email))
            except Exception:
                # The KeyError repr embeds the email; returning the trace to the
                # client leaks PII into the user-visible response.
                return jsonify({"trace": traceback.format_exc()}), 500
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "pii_leakage",
                "line": 19,
                "regulatory_basis": "GDPR Art. 5(1)(f)",
                "severity": "HIGH",
            }
        ],
    )

    # data_retention variant B and C (have A=p_retention_cache)
    add_case(
        cases,
        "P-TP-12",
        "privacy",
        "p_retention_audit.py",
        '''
        """Audit log appended on every action with no rotation or TTL."""
        from datetime import datetime


        AUDIT_FILE = "/var/log/app/audit.log"


        def record_action(user_id: str, action: str, details: dict) -> None:
            # Append-only log with no rotation, no retention policy, no TTL.
            line = f"{datetime.utcnow().isoformat()} user={user_id} action={action} details={details}\\n"
            with open(AUDIT_FILE, "a") as f:
                f.write(line)
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "data_retention",
                "line": 11,
                "regulatory_basis": "GDPR Art. 5(1)(e)",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-13",
        "privacy",
        "p_retention_schema.py",
        '''
        """User-events table schema — no retention column, no scheduled deletion."""
        from sqlalchemy import Column, Integer, String, DateTime, create_engine
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()


        class UserEvent(Base):
            __tablename__ = "user_events"
            id = Column(Integer, primary_key=True)
            user_id = Column(String, nullable=False)
            event_type = Column(String)
            ip_address = Column(String)
            created_at = Column(DateTime)
            # No retention metadata, no expires_at, no purge job referenced anywhere.


        engine = create_engine("postgresql://app@db/app")
        Base.metadata.create_all(engine)
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "data_retention",
                "line": 9,
                "regulatory_basis": "GDPR Art. 5(1)(e)",
                "severity": "MEDIUM",
            }
        ],
    )

    # consent_bypass variant C (have A=missing, B=temporal)
    add_case(
        cases,
        "P-TP-14",
        "privacy",
        "p_consent_commented.py",
        '''
        """Marketing email send with the consent check commented out."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        def has_marketing_consent(email: str) -> bool:
            return True


        def send_marketing(email: str, body: str) -> None:
            pass


        @app.route("/marketing/send", methods=["POST"])
        def send():
            email = request.json["email"]
            # if not has_marketing_consent(email):    # TODO re-enable after migration
            #     return jsonify({"queued": False}), 200
            send_marketing(email, "Big sale today!")
            return jsonify({"queued": True})
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "consent_bypass",
                "line": 18,
                "regulatory_basis": "GDPR Art. 7",
                "severity": "HIGH",
            }
        ],
    )

    # third_party_sharing variant B and C (have A=analytics)
    add_case(
        cases,
        "P-TP-15",
        "privacy",
        "p_3p_ad.py",
        '''
        """Ad SDK call carrying the user's IP and email."""
        from flask import Flask, request
        import requests

        app = Flask(__name__)
        AD_SDK_URL = "https://ads.example.com/track"


        def current_user_email() -> str:
            return "alice@example.org"


        @app.route("/page")
        def page():
            email = current_user_email()
            ip = request.remote_addr
            # Forwards email and IP — both are PII — to the ad provider.
            requests.post(AD_SDK_URL, json={"email": email, "ip": ip, "event": "page_view"})
            return ""
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "third_party_sharing",
                "line": 17,
                "regulatory_basis": "GDPR Art. 28",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-16",
        "privacy",
        "p_3p_crm.py",
        '''
        """Nightly export of full user records to a CRM, no minimization."""
        import requests


        CRM_URL = "https://crm.example.com/sync"


        def all_users() -> list[dict]:
            return [
                {"id": 1, "email": "a@example.org", "phone": "+1...", "address": "..."},
                {"id": 2, "email": "b@example.org", "phone": "+1...", "address": "..."},
            ]


        def nightly_sync() -> None:
            users = all_users()
            # Pushes the full PII record set to a third party with no anonymization.
            requests.post(CRM_URL, json={"users": users})
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "third_party_sharing",
                "line": 17,
                "regulatory_basis": "GDPR Art. 28",
                "severity": "HIGH",
            }
        ],
    )

    # re_identification_risk variant C (have A=unsalted, B=quasi)
    add_case(
        cases,
        "P-TP-17",
        "privacy",
        "p_reid_b64.py",
        '''
        """`pseudonymize()` is base64 of the email — fully reversible."""
        import base64


        def pseudonymize(email: str) -> str:
            # base64 is reversible, not anonymization. Anyone with the output
            # can recover the input.
            return base64.b64encode(email.encode()).decode()


        def emit(email: str, score: float) -> None:
            _publish({"pid": pseudonymize(email), "score": score})


        def _publish(rec: dict) -> None:
            pass
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "re_identification_risk",
                "line": 9,
                "regulatory_basis": "GDPR Art. 4(5)",
                "severity": "HIGH",
            }
        ],
    )

    # data_minimization variant B and C (have A=excess collection)
    add_case(
        cases,
        "P-TP-18",
        "privacy",
        "p_min_unused_columns.py",
        '''
        """User table with PII columns that no application code reads."""
        from sqlalchemy import Column, Integer, String, Date, create_engine
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()


        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            email = Column(String, nullable=False)
            display_name = Column(String)
            # date_of_birth and home_address were added "in case we need them"
            # but no code reads them. Storing PII without a purpose violates
            # data-minimization.
            date_of_birth = Column(Date)
            home_address = Column(String)


        engine = create_engine("postgresql://app@db/app")
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "data_minimization",
                "line": 14,
                "regulatory_basis": "GDPR Art. 5(1)(c)",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-19",
        "privacy",
        "p_min_oversized_scope.py",
        '''
        """Newsletter signup requests scope=full_profile but only needs email."""
        from flask import Flask, request, redirect

        app = Flask(__name__)
        OAUTH_URL = "https://auth.example.com/authorize"


        @app.route("/newsletter/connect")
        def connect_newsletter():
            # The newsletter only sends to the user's email; requesting
            # full_profile + contacts + calendar scopes is over-collection.
            url = (
                f"{OAUTH_URL}?client_id=app"
                "&scope=email%20full_profile%20contacts%20calendar"
                "&response_type=code"
            )
            return redirect(url)
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "data_minimization",
                "line": 14,
                "regulatory_basis": "GDPR Art. 5(1)(c)",
                "severity": "MEDIUM",
            }
        ],
    )

    # purpose_creep variant B and C (have A=shipping->ad)
    add_case(
        cases,
        "P-TP-20",
        "privacy",
        "p_purpose_train.py",
        '''
        """Customer-support transcripts forwarded into the model-training pipeline."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        def store_transcript(user_id: str, transcript: str) -> None:
            # Collected for: helping the user resolve their support ticket.
            pass


        def add_to_training_corpus(transcript: str) -> None:
            """Pushes the transcript into the next model fine-tune dataset."""
            pass


        @app.route("/support/close", methods=["POST"])
        def close_ticket():
            user_id = request.json["user_id"]
            transcript = request.json["transcript"]
            store_transcript(user_id, transcript)
            # Repurposing support text for ML training without re-consent.
            add_to_training_corpus(transcript)
            return jsonify({"closed": True})
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "purpose_creep",
                "line": 24,
                "regulatory_basis": "GDPR Art. 5(1)(b)",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-21",
        "privacy",
        "p_purpose_credit.py",
        '''
        """Loyalty-program purchase data fed into a credit-scoring model."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        def record_purchase(user_id: str, amount: float, items: list) -> None:
            # Collected for: loyalty-points accrual.
            pass


        def update_credit_score(user_id: str, history: list) -> None:
            """Recompute internal credit score from purchase history."""
            pass


        @app.route("/checkout/done", methods=["POST"])
        def checkout_done():
            uid = request.json["user_id"]
            amt = request.json["amount"]
            items = request.json["items"]
            record_purchase(uid, amt, items)
            # Reusing loyalty data for credit decisions is a purpose change.
            update_credit_score(uid, [{"amt": amt, "items": items}])
            return jsonify({"ok": True})
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "purpose_creep",
                "line": 23,
                "regulatory_basis": "GDPR Art. 5(1)(b)",
                "severity": "MEDIUM",
            }
        ],
    )

    # ============================================================
    # Additional categories (3 categories x 3 variants = 9 TPs)
    # ============================================================

    # insecure_storage x3
    add_case(
        cases,
        "P-TP-22",
        "privacy",
        "p_storage_unencrypted.py",
        '''
        """User profile schema stores PII columns in plaintext."""
        from sqlalchemy import Column, Integer, String, create_engine
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()


        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            email = Column(String, nullable=False)
            # SSN stored in plaintext — a clear Art. 32 (security of processing)
            # violation. Should be encrypted at rest and field-level access controlled.
            ssn = Column(String)
            phone = Column(String)


        engine = create_engine("postgresql://app@db/app")
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "insecure_storage",
                "line": 13,
                "regulatory_basis": "GDPR Art. 32",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-23",
        "privacy",
        "p_storage_plaintext_pw.py",
        '''
        """User table stores passwords as plaintext."""
        from sqlalchemy import Column, Integer, String, create_engine
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()


        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            email = Column(String, nullable=False)
            # Plaintext password storage — both a security and Art. 32 violation.
            password = Column(String, nullable=False)


        engine = create_engine("postgresql://app@db/app")
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "insecure_storage",
                "line": 13,
                "regulatory_basis": "GDPR Art. 32",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-24",
        "privacy",
        "p_storage_no_tls.py",
        '''
        """Database connection string disables TLS."""
        from sqlalchemy import create_engine


        # sslmode=disable means PII flows over the wire in cleartext between
        # the app and the database — Art. 32 violation on the transport leg.
        engine = create_engine(
            "postgresql://app:pw@db.example.com:5432/app?sslmode=disable"
        )


        def get_engine():
            return engine
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "insecure_storage",
                "line": 7,
                "regulatory_basis": "GDPR Art. 32",
                "severity": "HIGH",
            }
        ],
    )

    # cross_border_transfer x3
    add_case(
        cases,
        "P-TP-25",
        "privacy",
        "p_xborder_nosccs.py",
        '''
        """Daily PII export from EU-resident customers to a US-based CRM."""
        import requests


        US_CRM_URL = "https://crm.example-us.com/import"


        def eu_customers() -> list[dict]:
            return [{"id": 1, "email": "alice@example.de", "country": "DE"}]


        def nightly_export() -> None:
            data = eu_customers()
            # Cross-border transfer EU -> US with no Standard Contractual
            # Clauses, no Binding Corporate Rules, no adequacy decision —
            # GDPR Art. 44-49 violation.
            requests.post(US_CRM_URL, json={"customers": data})
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "cross_border_transfer",
                "line": 15,
                "regulatory_basis": "GDPR Art. 44",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-26",
        "privacy",
        "p_xborder_no_adequacy.py",
        '''
        """User profile sync to a non-adequacy-decision country."""
        import requests


        def sync_profile(user: dict) -> None:
            # The destination country has no GDPR adequacy decision and the
            # transfer relies on no documented safeguards. Art. 45 violation.
            requests.post("https://api.example-no-adequacy.com/users", json=user)


        def on_user_update(user: dict) -> None:
            sync_profile(user)
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "cross_border_transfer",
                "line": 9,
                "regulatory_basis": "GDPR Art. 45",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-27",
        "privacy",
        "p_xborder_intragroup.py",
        '''
        """Intra-group transfer to a non-EU subsidiary with no BCRs in place."""
        import requests


        def push_to_us_subsidiary(records: list[dict]) -> None:
            # Even within the same corporate group, EU->US transfers require
            # BCRs (Art. 47), SCCs (Art. 46), or adequacy. Code shows none
            # of those mechanisms; raw PII is just POSTed.
            requests.post("https://intra.example-us.com/replicate", json={"records": records})


        def replicate_users() -> None:
            push_to_us_subsidiary([{"id": 1, "email": "a@example.de"}])
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "cross_border_transfer",
                "line": 10,
                "regulatory_basis": "GDPR Art. 47",
                "severity": "HIGH",
            }
        ],
    )

    # right_to_erasure x3
    add_case(
        cases,
        "P-TP-28",
        "privacy",
        "p_erasure_missing.py",
        '''
        """User-account API exposes create/read/update — but no delete endpoint."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        @app.route("/users", methods=["POST"])
        def create_user():
            return jsonify({"id": 1})


        @app.route("/users/<int:uid>")
        def get_user(uid: int):
            return jsonify({"id": uid})


        @app.route("/users/<int:uid>", methods=["PUT"])
        def update_user(uid: int):
            return jsonify({"id": uid})


        # No DELETE handler. GDPR Art. 17 / CCPA §1798.105 require an
        # erasure path; this API has no way to honor a deletion request.
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "right_to_erasure",
                "line": 21,
                "regulatory_basis": "GDPR Art. 17",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-29",
        "privacy",
        "p_erasure_softdelete.py",
        '''
        """`delete_user` only marks the row inactive; PII fields persist."""
        import sqlite3


        def delete_user(user_id: int) -> None:
            conn = sqlite3.connect("app.db")
            # Soft-delete only sets a flag; email, name, address remain in the
            # row indefinitely. Right-to-erasure requires actual erasure.
            conn.execute("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
            conn.commit()
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "right_to_erasure",
                "line": 9,
                "regulatory_basis": "GDPR Art. 17",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "P-TP-30",
        "privacy",
        "p_erasure_no_cascade.py",
        '''
        """`delete_user` deletes the user row but not their data in other tables."""
        import sqlite3


        def delete_user(user_id: int) -> None:
            conn = sqlite3.connect("app.db")
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            # Comments, activity_log, payment_history, and audit_trail all
            # contain user_id and PII fields, but no cascade delete is issued.
            # Art. 17 erasure must be applied to all derived tables.
            conn.commit()
        ''',
        "privacy_tp",
        [
            {
                "surface": "privacy",
                "category": "right_to_erasure",
                "line": 8,
                "regulatory_basis": "GDPR Art. 17",
                "severity": "HIGH",
            }
        ],
    )

    # ============================================================
    # Privacy TNs (15 = 5 inherited + 10 new; 10 calibration + 5 held-out)
    # ============================================================
    add_case(
        cases,
        "P-TN-01",
        "privacy",
        "p_safe_salted.py",
        "",
        "privacy_tn",
        [],
        boundary="salted vs. unsalted hash",
        inherited=True,
    )
    add_case(
        cases,
        "P-TN-02",
        "privacy",
        "p_safe_aggregate.py",
        "",
        "privacy_tn",
        [],
        boundary="k-aggregated counts vs. individual records",
        inherited=True,
    )
    add_case(
        cases,
        "P-TN-03",
        "privacy",
        "p_safe_consent.py",
        "",
        "privacy_tn",
        [],
        boundary="consent verified before send vs. after",
        inherited=True,
    )
    add_case(
        cases,
        "P-TN-04",
        "privacy",
        "p_safe_same_purpose.py",
        "",
        "privacy_tn",
        [],
        boundary="same-purpose reuse vs. cross-purpose sharing",
        inherited=True,
    )
    add_case(
        cases,
        "P-TN-05",
        "privacy",
        "p_safe_ttl.py",
        "",
        "privacy_tn",
        [],
        boundary="cache with TTL vs. cache without TTL",
        inherited=True,
    )

    # Additional calibration priv TNs (5)
    add_case(
        cases,
        "P-TN-06",
        "privacy",
        "p_safe_3p_hashed.py",
        '''
        """Analytics endpoint receives only a salted hash of the email."""
        import requests
        import hashlib
        import os


        ANALYTICS_URL = "https://analytics.example.com/event"


        def _salted_hash(value: str) -> str:
            salt = os.urandom(16)
            h = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 100_000)
            return salt.hex() + ":" + h.hex()


        def track_page_view(email: str, path: str) -> None:
            # Only the salted hash is shared with the third party — no raw PII.
            requests.post(ANALYTICS_URL,
                          json={"id_hash": _salted_hash(email), "path": path})
        ''',
        "privacy_tn",
        [],
        boundary="hashed identifier sent to 3rd party vs. raw email",
    )

    add_case(
        cases,
        "P-TN-07",
        "privacy",
        "p_safe_xborder.py",
        '''
        """EU->US transfer documented under SCCs."""
        import requests


        # SCCs (Standard Contractual Clauses) signed and stored under
        # docs/legal/scc-2022-eu-us-crm.pdf, referenced here for traceability.
        SCC_REFERENCE = "docs/legal/scc-2022-eu-us-crm.pdf"
        US_CRM_URL = "https://crm.example-us.com/import"


        def export_to_us_crm(rows: list[dict]) -> None:
            # Transfer is permitted under documented SCCs. The reference is
            # tracked so legal review can verify compliance.
            requests.post(US_CRM_URL, json={"rows": rows, "scc_ref": SCC_REFERENCE})
        ''',
        "privacy_tn",
        [],
        boundary="EU->US transfer with documented SCCs vs. unsafeguarded",
    )

    add_case(
        cases,
        "P-TN-08",
        "privacy",
        "p_safe_erasure_cascade.py",
        '''
        """`delete_user` cascades to all PII-bearing tables."""
        import sqlite3


        PII_TABLES = ["comments", "activity_log", "payment_history", "audit_trail"]


        def delete_user(user_id: int) -> None:
            conn = sqlite3.connect("app.db")
            cur = conn.cursor()
            # Cascade-delete the user from every PII-bearing table.
            for tbl in PII_TABLES:
                cur.execute(f"DELETE FROM {tbl} WHERE user_id = ?", (user_id,))
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        ''',
        "privacy_tn",
        [],
        boundary="cascade delete vs. row-only / soft delete",
    )

    add_case(
        cases,
        "P-TN-09",
        "privacy",
        "p_safe_minimized.py",
        '''
        """Newsletter signup collects only email and a coarse country code."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        @app.route("/newsletter/signup", methods=["POST"])
        def signup():
            body = request.json
            # Only what is strictly necessary for the digest delivery and
            # localization. No name, no address, no DOB.
            record = {"email": body["email"], "country": body.get("country", "")}
            _save(record)
            return jsonify({"subscribed": True})


        def _save(rec: dict) -> None:
            pass
        ''',
        "privacy_tn",
        [],
        boundary="minimized collection vs. excessive collection",
    )

    add_case(
        cases,
        "P-TN-10",
        "privacy",
        "p_safe_storage_bcrypt.py",
        '''
        """User table stores bcrypt-hashed passwords."""
        from sqlalchemy import Column, Integer, String, create_engine
        from sqlalchemy.orm import declarative_base
        import bcrypt

        Base = declarative_base()


        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            email = Column(String, nullable=False)
            # Stored as bcrypt hash (per-record salted), not plaintext.
            password_hash = Column(String, nullable=False)


        def set_password(user: User, plaintext: str) -> None:
            user.password_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(12)).decode()
        ''',
        "privacy_tn",
        [],
        boundary="bcrypt password column vs. plaintext password column",
    )

    # Held-out priv TNs (5) -- not inspected during rule calibration
    add_case(
        cases,
        "P-TN-11",
        "privacy",
        "p_holdout_audit_rotation.py",
        '''
        """Audit log written via TimedRotatingFileHandler with 30-day retention."""
        import logging
        from logging.handlers import TimedRotatingFileHandler


        audit = logging.getLogger("audit")
        audit.setLevel(logging.INFO)
        # Daily rotation, 30-day retention — bounded retention, not indefinite.
        handler = TimedRotatingFileHandler("/var/log/app/audit.log",
                                           when="midnight", backupCount=30)
        audit.addHandler(handler)


        def record_action(user_id: str, action: str) -> None:
            audit.info("user=%s action=%s", user_id, action)
        ''',
        "privacy_tn",
        [],
        boundary="audit log with rotation policy vs. indefinite",
        holdout=True,
    )

    add_case(
        cases,
        "P-TN-12",
        "privacy",
        "p_holdout_token_vault.py",
        '''
        """Customer ID is tokenized via a vault before use in analytics."""
        import requests


        ANALYTICS_URL = "https://analytics.example.com/event"
        VAULT_URL = "https://vault.example.internal/tokenize"


        def _tokenize(customer_id: str) -> str:
            # The vault returns an irreversible token; only authorized callers
            # holding the vault key can de-tokenize.
            return requests.post(VAULT_URL, json={"id": customer_id},
                                 headers={"X-Vault-Auth": "..."}).json()["token"]


        def track_event(customer_id: str, event: str) -> None:
            requests.post(ANALYTICS_URL,
                          json={"token": _tokenize(customer_id), "event": event})
        ''',
        "privacy_tn",
        [],
        boundary="tokenized via vault vs. raw identifier",
        holdout=True,
    )

    add_case(
        cases,
        "P-TN-13",
        "privacy",
        "p_holdout_legitimate.py",
        '''
        """Fraud-detection processing of IP addresses under documented legitimate interest."""
        from datetime import datetime


        # Legitimate-interest assessment (LIA) on file:
        # docs/privacy/lia-fraud-detection-2024.pdf
        # The LIA balances the need to detect account-takeover against the
        # privacy impact of processing IP and device fingerprints.
        LIA_REF = "docs/privacy/lia-fraud-detection-2024.pdf"


        def score_login(user_id: str, ip: str, ua: str) -> float:
            # GDPR Art. 6(1)(f) legitimate-interest basis, documented in LIA_REF.
            features = {"ip": ip, "ua": ua, "ts": datetime.utcnow().isoformat()}
            return _model_score(features)


        def _model_score(f: dict) -> float:
            return 0.0
        ''',
        "privacy_tn",
        [],
        boundary="documented legitimate interest vs. unconsented processing",
        holdout=True,
    )

    add_case(
        cases,
        "P-TN-14",
        "privacy",
        "p_holdout_csv_omit.py",
        '''
        """Public CSV export drops the email column."""
        import csv


        EXPORT_FIELDS = ["id", "country", "signup_year"]


        def export_users(rows: list[dict], path: str) -> None:
            # Email and other PII fields are explicitly excluded from the
            # public export — minimization at the sink.
            with open(path, "w") as f:
                w = csv.DictWriter(f, fieldnames=EXPORT_FIELDS)
                w.writeheader()
                for r in rows:
                    w.writerow({k: r.get(k, "") for k in EXPORT_FIELDS})
        ''',
        "privacy_tn",
        [],
        boundary="email omitted from export vs. exported in clear",
        holdout=True,
    )

    add_case(
        cases,
        "P-TN-15",
        "privacy",
        "p_holdout_encrypt_cache.py",
        '''
        """PII cached only after envelope-encryption with a KMS-managed key."""
        import json
        import redis
        from cryptography.fernet import Fernet


        # Key wrapped under the cloud KMS; rotation handled by KMS.
        FERNET_KEY = b"<wrapped-by-KMS-at-runtime>"
        _cipher = Fernet(FERNET_KEY) if FERNET_KEY != b"<wrapped-by-KMS-at-runtime>" else None
        r = redis.Redis(host="cache.example.com")


        def cache_profile(user_id: str, profile: dict) -> None:
            blob = json.dumps(profile).encode()
            # Fernet provides authenticated symmetric encryption; the cache
            # never sees plaintext PII.
            r.set(f"profile:{user_id}", _cipher.encrypt(blob) if _cipher else blob, ex=300)
        ''',
        "privacy_tn",
        [],
        boundary="KMS-encrypted cache vs. plaintext cache",
        holdout=True,
    )
