# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Security cases: 60 TPs (20 categories x 3 variants each) + 15 near-miss
TNs (10 calibration + 5 held-out).

Cases inherited from earlier benchmark iterations are kept under their
original filenames; the rest are authored here.
"""

from __future__ import annotations


def build_security(cases: list[dict], add_case) -> None:  # type: ignore[no-untyped-def]
    # ============================================================
    # Inherited TPs (10) -- variant A of each existing category
    # ============================================================
    add_case(
        cases,
        "S-TP-01",
        "security",
        "s_sql_fstring.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "sql_injection",
                "line": 19,
                "cwe": "CWE-89",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-02",
        "security",
        "s_cmd_subprocess.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "command_injection",
                "line": 16,
                "cwe": "CWE-78",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-03",
        "security",
        "s_path_traversal.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "path_traversal",
                "line": 11,
                "cwe": "CWE-22",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-04",
        "security",
        "s_xss_jinja.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xss",
                "line": 9,
                "cwe": "CWE-79",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-05",
        "security",
        "s_auth_bypass.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "auth_bypass",
                "line": 26,
                "cwe": "CWE-287",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-06",
        "security",
        "s_secret_hardcoded.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "hardcoded_secret",
                "line": 5,
                "cwe": "CWE-798",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-07",
        "security",
        "s_pickle.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "deserialization",
                "line": 14,
                "cwe": "CWE-502",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-08",
        "security",
        "s_eval.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "eval_injection",
                "line": 12,
                "cwe": "CWE-94",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-09",
        "security",
        "s_loop.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "infinite_loop",
                "line": 15,
                "cwe": "CWE-835",
                "severity": "MEDIUM",
            }
        ],
        inherited=True,
    )
    add_case(
        cases,
        "S-TP-10",
        "security",
        "s_agent_csrf.py",
        "",
        "security_tp",
        [
            {
                "surface": "security",
                "category": "agent_csrf",
                "line": 16,
                "cwe": "CWE-352",
                "severity": "HIGH",
            }
        ],
        inherited=True,
    )

    # ============================================================
    # Variants B and C for each pre-existing category (20 TPs)
    # ============================================================

    # sql_injection variant B: .format()
    add_case(
        cases,
        "S-TP-11",
        "security",
        "s_sql_format.py",
        '''
        """User search via .format() SQL."""
        from flask import Flask, request, jsonify
        import sqlite3

        app = Flask(__name__)


        @app.route("/items/search")
        def search_items():
            tag = request.args.get("tag", "")
            conn = sqlite3.connect("app.db")
            cur = conn.cursor()
            # .format() interpolation directly into SQL — same vulnerability as f-string.
            query = "SELECT id, name FROM items WHERE tag = '{}'".format(tag)
            cur.execute(query)
            return jsonify(cur.fetchall())
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "sql_injection",
                "line": 14,
                "cwe": "CWE-89",
                "severity": "HIGH",
            }
        ],
    )

    # sql_injection variant C: SQLAlchemy raw text()
    add_case(
        cases,
        "S-TP-12",
        "security",
        "s_sql_text.py",
        '''
        """SQLAlchemy raw text() with user input."""
        from flask import Flask, request, jsonify
        from sqlalchemy import create_engine, text

        engine = create_engine("sqlite:///app.db")
        app = Flask(__name__)


        @app.route("/orders")
        def list_orders():
            status = request.args.get("status", "open")
            with engine.connect() as conn:
                # text() with user input concatenation defeats the ORM's parameterization.
                stmt = text("SELECT * FROM orders WHERE status = '" + status + "'")
                rows = conn.execute(stmt).fetchall()
                return jsonify([dict(r._mapping) for r in rows])
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "sql_injection",
                "line": 14,
                "cwe": "CWE-89",
                "severity": "HIGH",
            }
        ],
    )

    # command_injection variant B: os.popen
    add_case(
        cases,
        "S-TP-13",
        "security",
        "s_cmd_popen.py",
        '''
        """Tail a log via os.popen with user-controlled filename."""
        from flask import Flask, request, jsonify
        import os

        app = Flask(__name__)


        @app.route("/logs/tail")
        def tail_log():
            name = request.args.get("name", "app")
            # os.popen passes the string to a shell — command injection via name.
            with os.popen("tail -n 50 /var/log/" + name + ".log") as p:
                return jsonify({"output": p.read()})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "command_injection",
                "line": 12,
                "cwe": "CWE-78",
                "severity": "HIGH",
            }
        ],
    )

    # command_injection variant C: os.system
    add_case(
        cases,
        "S-TP-14",
        "security",
        "s_cmd_system.py",
        '''
        """Trigger a backup via os.system with user input."""
        from flask import Flask, request, jsonify
        import os

        app = Flask(__name__)


        @app.route("/backup")
        def backup():
            target = request.args.get("target", "default")
            # os.system delegates to /bin/sh — target=foo;rm -rf / executes rm.
            rc = os.system("rsync -a /data /backup/" + target)
            return jsonify({"rc": rc})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "command_injection",
                "line": 12,
                "cwe": "CWE-78",
                "severity": "HIGH",
            }
        ],
    )

    # path_traversal variant B: pathlib.Path / user
    add_case(
        cases,
        "S-TP-15",
        "security",
        "s_path_pathlib.py",
        '''
        """Serve a user-asset via pathlib without containment check."""
        from flask import Flask, request, send_file, abort
        from pathlib import Path

        app = Flask(__name__)
        ASSETS = Path("/srv/assets")


        @app.route("/asset")
        def asset():
            name = request.args.get("name", "")
            # Path / user — no resolution check; ../../etc/passwd escapes ASSETS.
            target = ASSETS / name
            if not target.exists():
                abort(404)
            return send_file(str(target))
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "path_traversal",
                "line": 13,
                "cwe": "CWE-22",
                "severity": "HIGH",
            }
        ],
    )

    # path_traversal variant C: zip-slip
    add_case(
        cases,
        "S-TP-16",
        "security",
        "s_path_zipslip.py",
        '''
        """Extract a user-uploaded zip to a directory; vulnerable to zip-slip."""
        from flask import Flask, request, jsonify
        import zipfile
        import os

        app = Flask(__name__)
        EXTRACT_DIR = "/tmp/extracted"


        @app.route("/upload-zip", methods=["POST"])
        def upload_zip():
            f = request.files["archive"]
            with zipfile.ZipFile(f) as zf:
                # extractall does not validate member paths; an entry named
                # ../../etc/cron.d/evil escapes EXTRACT_DIR — zip-slip.
                zf.extractall(EXTRACT_DIR)
            return jsonify({"extracted": True})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "path_traversal",
                "line": 15,
                "cwe": "CWE-22",
                "severity": "HIGH",
            }
        ],
    )

    # xss variant B: raw Markup(user)
    add_case(
        cases,
        "S-TP-17",
        "security",
        "s_xss_markup.py",
        '''
        """Render a user comment via Markup(), bypassing Jinja auto-escape."""
        from flask import Flask, request, render_template_string
        from markupsafe import Markup

        app = Flask(__name__)
        TPL = "<div class='comment'>{{ content }}</div>"


        @app.route("/comment")
        def show_comment():
            user_html = request.args.get("c", "")
            # Markup() marks the string as already-safe HTML — Jinja will not escape it.
            return render_template_string(TPL, content=Markup(user_html))
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xss",
                "line": 13,
                "cwe": "CWE-79",
                "severity": "HIGH",
            }
        ],
    )

    # xss variant C: string.Template().substitute() (template injection-flavored XSS)
    add_case(
        cases,
        "S-TP-18",
        "security",
        "s_xss_substitute.py",
        '''
        """Render a user-provided greeting into HTML via string.Template."""
        from flask import Flask, request, Response
        from string import Template

        app = Flask(__name__)


        @app.route("/greet")
        def greet():
            name = request.args.get("name", "guest")
            # Direct substitution into HTML body with no escaping.
            html = Template("<html><body><h1>Hello, $name!</h1></body></html>").substitute(name=name)
            return Response(html, mimetype="text/html")
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xss",
                "line": 13,
                "cwe": "CWE-79",
                "severity": "HIGH",
            }
        ],
    )

    # auth_bypass variant B: IDOR (no ownership check)
    add_case(
        cases,
        "S-TP-19",
        "security",
        "s_auth_idor.py",
        '''
        """User can fetch any other user's invoice by guessing the ID."""
        from flask import Flask, request, jsonify, g

        app = Flask(__name__)


        def current_user_id() -> int:
            return 1


        def fetch_invoice(invoice_id: int) -> dict:
            return {"id": invoice_id, "owner_id": 42, "amount": 100}


        @app.route("/invoice/<int:invoice_id>")
        def get_invoice(invoice_id: int):
            inv = fetch_invoice(invoice_id)
            # No check that current_user_id() == inv["owner_id"] — IDOR.
            return jsonify(inv)
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "auth_bypass",
                "line": 19,
                "cwe": "CWE-639",
                "severity": "HIGH",
            }
        ],
    )

    # auth_bypass variant C: JWT alg=none
    add_case(
        cases,
        "S-TP-20",
        "security",
        "s_auth_jwt_none.py",
        '''
        """Verify JWT without checking the algorithm header."""
        from flask import Flask, request, jsonify
        import jwt

        app = Flask(__name__)
        SECRET = "k"


        @app.route("/me")
        def me():
            tok = request.headers.get("Authorization", "")[7:]
            # algorithms=None lets the client present an unsigned (alg=none) token.
            claims = jwt.decode(tok, SECRET, algorithms=None, options={"verify_signature": False})
            return jsonify({"user": claims.get("sub")})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "auth_bypass",
                "line": 13,
                "cwe": "CWE-287",
                "severity": "HIGH",
            }
        ],
    )

    # hardcoded_secret variant B: DB password
    add_case(
        cases,
        "S-TP-21",
        "security",
        "s_secret_dbpass.py",
        '''
        """DB password embedded in the connection string literal."""
        from sqlalchemy import create_engine

        # Hardcoded production database password in source.
        engine = create_engine("postgresql://app_user:Pr0d-DB-PaSSw0rd-2024@db.example.com:5432/app")


        def get_engine():
            return engine
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "hardcoded_secret",
                "line": 5,
                "cwe": "CWE-798",
                "severity": "HIGH",
            }
        ],
    )

    # hardcoded_secret variant C: JWT signing key
    add_case(
        cases,
        "S-TP-22",
        "security",
        "s_secret_jwtkey.py",
        '''
        """JWT signing key as a module-level literal."""
        import jwt
        import time

        # Production JWT signing key embedded in source.
        JWT_SIGNING_KEY = "WLFZx2-prod-jwt-signing-key-9c91-do-not-commit"


        def issue_token(user_id: int) -> str:
            return jwt.encode({"sub": user_id, "iat": int(time.time())},
                              JWT_SIGNING_KEY, algorithm="HS256")
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "hardcoded_secret",
                "line": 7,
                "cwe": "CWE-798",
                "severity": "HIGH",
            }
        ],
    )

    # deserialization variant B: yaml.load
    add_case(
        cases,
        "S-TP-23",
        "security",
        "s_yaml_load.py",
        '''
        """Load a user-uploaded YAML config with the unsafe loader."""
        from flask import Flask, request, jsonify
        import yaml

        app = Flask(__name__)


        @app.route("/config", methods=["POST"])
        def load_config():
            text = request.data.decode("utf-8")
            # yaml.load (without SafeLoader) executes arbitrary !!python/object tags.
            cfg = yaml.load(text, Loader=yaml.Loader)
            return jsonify({"keys": list(cfg.keys()) if isinstance(cfg, dict) else None})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "deserialization",
                "line": 13,
                "cwe": "CWE-502",
                "severity": "HIGH",
            }
        ],
    )

    # deserialization variant C: joblib.load
    add_case(
        cases,
        "S-TP-24",
        "security",
        "s_joblib.py",
        '''
        """Load a user-uploaded scikit-learn model file via joblib."""
        from flask import Flask, request, jsonify
        import joblib
        import io

        app = Flask(__name__)


        @app.route("/predict", methods=["POST"])
        def predict():
            blob = request.files["model"].read()
            # joblib.load uses pickle internally — attacker-controlled bytes = RCE.
            model = joblib.load(io.BytesIO(blob))
            x = request.form.get("x", "0")
            return jsonify({"prediction": float(model.predict([[float(x)]])[0])})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "deserialization",
                "line": 14,
                "cwe": "CWE-502",
                "severity": "HIGH",
            }
        ],
    )

    # eval_injection variant B: exec
    add_case(
        cases,
        "S-TP-25",
        "security",
        "s_exec.py",
        '''
        """Macros endpoint that exec()s a user-supplied snippet."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        @app.route("/macro", methods=["POST"])
        def run_macro():
            code = request.json["code"]
            ns: dict = {}
            # exec on attacker-controlled code — arbitrary execution.
            exec(code, ns)
            return jsonify({"result": ns.get("result")})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "eval_injection",
                "line": 13,
                "cwe": "CWE-94",
                "severity": "HIGH",
            }
        ],
    )

    # eval_injection variant C: dynamic __import__
    add_case(
        cases,
        "S-TP-26",
        "security",
        "s_dynamic_import.py",
        '''
        """Load a plugin by user-supplied module name and call entry()."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        @app.route("/plugin/run", methods=["POST"])
        def run_plugin():
            mod_name = request.json["module"]
            # __import__ with attacker-controlled name + getattr lets the caller
            # invoke any importable module's entry() function (e.g. os.system).
            mod = __import__(mod_name)
            return jsonify({"result": getattr(mod, "entry")()})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "eval_injection",
                "line": 13,
                "cwe": "CWE-94",
                "severity": "HIGH",
            }
        ],
    )

    # infinite_loop variant B: unbounded recursion
    add_case(
        cases,
        "S-TP-27",
        "security",
        "s_loop_recursion.py",
        '''
        """Recursive directory listing without a depth bound."""
        import os


        def list_all(path: str) -> list:
            out = []
            for entry in os.listdir(path):
                full = os.path.join(path, entry)
                # No depth limit and no symlink check — symlink loops produce
                # unbounded recursion until the stack overflows.
                if os.path.isdir(full):
                    out.extend(list_all(full))
                else:
                    out.append(full)
            return out
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "infinite_loop",
                "line": 12,
                "cwe": "CWE-674",
                "severity": "MEDIUM",
            }
        ],
    )

    # infinite_loop variant C: retry without max-attempts
    add_case(
        cases,
        "S-TP-28",
        "security",
        "s_loop_retry.py",
        '''
        """HTTP fetch with retry-on-error and no maximum-attempt cap."""
        import requests
        import time


        def fetch_until_ok(url: str) -> str:
            while True:
                try:
                    r = requests.get(url, timeout=2)
                    if r.status_code == 200:
                        return r.text
                except requests.RequestException:
                    pass
                # No retry counter, no exponential backoff cap; can spin indefinitely
                # if the upstream is permanently down.
                time.sleep(1)
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "infinite_loop",
                "line": 13,
                "cwe": "CWE-835",
                "severity": "MEDIUM",
            }
        ],
    )

    # agent_csrf variant B: webhook trigger
    add_case(
        cases,
        "S-TP-29",
        "security",
        "s_agent_webhook.py",
        '''
        """Inbound webhook auto-runs an agent task with no confirmation."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        def run_agent(task: dict) -> dict:
            return {"ok": True, "task": task["name"]}


        @app.route("/wh/agent", methods=["POST"])
        def webhook_agent():
            task = request.get_json()
            # Webhook payload directly drives a privileged agent action without
            # any inline confirmation step or sign-off field.
            return jsonify(run_agent(task))
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "agent_csrf",
                "line": 16,
                "cwe": "CWE-352",
                "severity": "HIGH",
            }
        ],
    )

    # agent_csrf variant C: deep-link trigger
    add_case(
        cases,
        "S-TP-30",
        "security",
        "s_agent_deeplink.py",
        '''
        """Deep-link in an email opens the app and immediately runs an action."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        @app.route("/open")
        def open_deep_link():
            action = request.args.get("a", "")
            target = request.args.get("t", "")
            # No interstitial / preview screen — the deep link triggers the action
            # the moment the user opens it from an email.
            return jsonify({"ran": _do(action, target)})


        def _do(action: str, target: str) -> str:
            return f"{action}:{target}"
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "agent_csrf",
                "line": 13,
                "cwe": "CWE-352",
                "severity": "HIGH",
            }
        ],
    )

    # ============================================================
    # Additional categories (10 categories x 3 variants = 30 TPs)
    # ============================================================

    # second_order_sqli x3
    add_case(
        cases,
        "S-TP-31",
        "security",
        "s_so_username.py",
        '''
        """Stored username later used in a raw query."""
        from flask import Flask, request, jsonify
        import sqlite3

        app = Flask(__name__)


        @app.route("/register", methods=["POST"])
        def register():
            name = request.json["name"]
            conn = sqlite3.connect("app.db")
            conn.execute("INSERT INTO users(name) VALUES(?)", (name,))
            conn.commit()
            return jsonify({"ok": True})


        @app.route("/admin/lookup")
        def admin_lookup():
            conn = sqlite3.connect("app.db")
            row = conn.execute("SELECT name FROM users LIMIT 1").fetchone()
            stored_name = row[0]
            # Stored attacker-controlled name pasted into a raw query — second-order SQLi.
            return jsonify(conn.execute("SELECT * FROM audit WHERE who='" + stored_name + "'").fetchall())
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "second_order_sqli",
                "line": 23,
                "cwe": "CWE-89",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-32",
        "security",
        "s_so_url.py",
        '''
        """Stored profile URL later used as an outbound request — stored SSRF."""
        from flask import Flask, request, jsonify
        import requests
        import sqlite3

        app = Flask(__name__)


        @app.route("/profile/url", methods=["POST"])
        def set_profile_url():
            url = request.json["avatar_url"]
            conn = sqlite3.connect("app.db")
            conn.execute("UPDATE profile SET avatar_url=? WHERE id=1", (url,))
            return jsonify({"ok": True})


        @app.route("/avatar/preview")
        def preview():
            conn = sqlite3.connect("app.db")
            stored_url = conn.execute("SELECT avatar_url FROM profile WHERE id=1").fetchone()[0]
            # Server fetches the stored URL — attacker can point it at internal services.
            return jsonify({"data": requests.get(stored_url, timeout=3).text[:200]})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "second_order_sqli",
                "line": 22,
                "cwe": "CWE-89",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-33",
        "security",
        "s_so_template.py",
        '''
        """Stored notification template later rendered as Jinja — stored SSTI."""
        from flask import Flask, request, jsonify
        from jinja2 import Template
        import sqlite3

        app = Flask(__name__)


        @app.route("/templates", methods=["POST"])
        def save_tpl():
            tpl = request.json["template"]
            sqlite3.connect("app.db").execute(
                "INSERT INTO tpl(body) VALUES(?)", (tpl,))
            return jsonify({"ok": True})


        @app.route("/render/<int:tid>")
        def render(tid: int):
            row = sqlite3.connect("app.db").execute(
                "SELECT body FROM tpl WHERE id=?", (tid,)).fetchone()
            # Stored attacker-controlled template body rendered with full Jinja
            # context — server-side template injection (stored variant).
            return Template(row[0]).render(user="alice", admin=True)
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "second_order_sqli",
                "line": 23,
                "cwe": "CWE-89",
                "severity": "HIGH",
            }
        ],
    )

    # ssrf x3
    add_case(
        cases,
        "S-TP-34",
        "security",
        "s_ssrf_url.py",
        '''
        """Fetch endpoint that proxies an arbitrary user-controlled URL."""
        from flask import Flask, request, jsonify
        import requests

        app = Flask(__name__)


        @app.route("/fetch")
        def fetch():
            target = request.args.get("url", "")
            # No allowlist, no scheme check, no IP-range check — full SSRF.
            r = requests.get(target, timeout=3)
            return jsonify({"status": r.status_code, "body": r.text[:200]})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "ssrf",
                "line": 12,
                "cwe": "CWE-918",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-35",
        "security",
        "s_ssrf_metadata.py",
        '''
        """Image-by-URL importer — vulnerable to AWS metadata SSRF."""
        from flask import Flask, request, jsonify
        import requests

        app = Flask(__name__)


        @app.route("/images/import", methods=["POST"])
        def import_image():
            src = request.json["src"]
            # Attacker can submit src=http://169.254.169.254/latest/meta-data/iam/security-credentials/
            # to exfiltrate cloud-instance IAM credentials.
            data = requests.get(src, timeout=3).content
            return jsonify({"size": len(data)})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "ssrf",
                "line": 14,
                "cwe": "CWE-918",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-36",
        "security",
        "s_ssrf_file.py",
        '''
        """Webhook test endpoint that follows a user-supplied URL with no scheme filter."""
        from flask import Flask, request, jsonify
        import urllib.request

        app = Flask(__name__)


        @app.route("/webhook/test", methods=["POST"])
        def test_webhook():
            url = request.json["url"]
            # urllib.request.urlopen accepts file:// — attacker can read local files
            # via file:///etc/passwd.
            with urllib.request.urlopen(url, timeout=3) as r:
                return jsonify({"head": r.read(200).decode("utf-8", "replace")})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "ssrf",
                "line": 14,
                "cwe": "CWE-918",
                "severity": "HIGH",
            }
        ],
    )

    # open_redirect x3
    add_case(
        cases,
        "S-TP-37",
        "security",
        "s_redirect_url.py",
        '''
        """Login post-redirect that honours an arbitrary `next` URL."""
        from flask import Flask, request, redirect

        app = Flask(__name__)


        @app.route("/login")
        def login():
            next_url = request.args.get("next", "/")
            # Attacker sends victims to /login?next=https://evil.example.com/phish.
            return redirect(next_url)
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "open_redirect",
                "line": 11,
                "cwe": "CWE-601",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-38",
        "security",
        "s_redirect_js.py",
        '''
        """Server-rendered JavaScript redirect using user input."""
        from flask import Flask, request, Response

        app = Flask(__name__)


        @app.route("/go")
        def go():
            target = request.args.get("to", "/")
            html = f"<script>location='{target}'</script>"
            # User-controlled `target` interpolated into a JS string — also XSS,
            # but primarily an open redirect.
            return Response(html, mimetype="text/html")
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "open_redirect",
                "line": 12,
                "cwe": "CWE-601",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-39",
        "security",
        "s_redirect_oauth.py",
        '''
        """OAuth callback that does not validate `state` and trusts `redirect_uri`."""
        from flask import Flask, request, redirect

        app = Flask(__name__)


        @app.route("/oauth/cb")
        def oauth_callback():
            code = request.args.get("code")
            redirect_uri = request.args.get("redirect_uri", "/")
            # No `state` validation against session, no allowlist on redirect_uri.
            _exchange_code(code)
            return redirect(redirect_uri)


        def _exchange_code(code):
            return None
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "open_redirect",
                "line": 13,
                "cwe": "CWE-601",
                "severity": "MEDIUM",
            }
        ],
    )

    # crypto_misuse x3
    add_case(
        cases,
        "S-TP-40",
        "security",
        "s_crypto_md5.py",
        '''
        """User password hashed with MD5."""
        import hashlib


        def hash_password(plaintext: str) -> str:
            # MD5 is broken for password hashing: fast and unsalted, so rainbow
            # tables and brute-force are trivial.
            return hashlib.md5(plaintext.encode()).hexdigest()


        def store_user(email: str, password: str) -> None:
            row = {"email": email, "pw_hash": hash_password(password)}
            _save(row)


        def _save(row: dict) -> None:
            pass
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "crypto_misuse",
                "line": 8,
                "cwe": "CWE-327",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-41",
        "security",
        "s_crypto_iv.py",
        '''
        """AES-CBC encryption with a hardcoded zero IV."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        KEY = b"0123456789abcdef0123456789abcdef"
        # Hardcoded all-zero IV — enables chosen-plaintext attacks on CBC mode.
        IV = b"\\x00" * 16


        def encrypt(data: bytes) -> bytes:
            cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
            enc = cipher.encryptor()
            pad = 16 - (len(data) % 16)
            return enc.update(data + bytes([pad]) * pad) + enc.finalize()
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "crypto_misuse",
                "line": 7,
                "cwe": "CWE-329",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-42",
        "security",
        "s_crypto_random.py",
        '''
        """Generate a session token using random.random()."""
        import random
        import string


        def new_session_token() -> str:
            # random.random() is the Python Mersenne Twister — predictable and
            # not cryptographically secure. Use secrets.token_urlsafe instead.
            chars = string.ascii_letters + string.digits
            return "".join(random.choice(chars) for _ in range(32))
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "crypto_misuse",
                "line": 9,
                "cwe": "CWE-330",
                "severity": "HIGH",
            }
        ],
    )

    # xxe x3
    add_case(
        cases,
        "S-TP-43",
        "security",
        "s_xxe_lxml.py",
        '''
        """Parse a user-uploaded XML file with default lxml settings."""
        from flask import Flask, request, jsonify
        from lxml import etree

        app = Flask(__name__)


        @app.route("/xml/parse", methods=["POST"])
        def parse_xml():
            blob = request.data
            # Default lxml parser resolves external entities; <!ENTITY x SYSTEM "file:///etc/passwd">
            # exfiltrates local files.
            doc = etree.fromstring(blob)
            return jsonify({"root": doc.tag})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xxe",
                "line": 14,
                "cwe": "CWE-611",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-44",
        "security",
        "s_xxe_soap.py",
        '''
        """SOAP request handler using xml.etree without entity protection."""
        from flask import Flask, request, jsonify
        import xml.etree.ElementTree as ET

        app = Flask(__name__)


        @app.route("/soap", methods=["POST"])
        def soap():
            body = request.data
            # ET.fromstring uses the default expat parser; while modern Python
            # disables entity expansion by default, the fact that the server
            # accepts raw XML with no schema validation means malicious DTDs
            # ship straight through. This mirrors the historical SOAP XXE pattern.
            tree = ET.fromstring(body)
            return jsonify({"action": tree.find(".//action").text})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xxe",
                "line": 16,
                "cwe": "CWE-611",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-45",
        "security",
        "s_xxe_xinclude.py",
        '''
        """XML processor that explicitly resolves XInclude on user input."""
        from flask import Flask, request, jsonify
        from lxml import etree

        app = Flask(__name__)


        @app.route("/xml/process", methods=["POST"])
        def process():
            blob = request.data
            doc = etree.fromstring(blob)
            # Explicit XInclude processing on attacker-controlled XML — the
            # included href can be a local file path.
            doc.xinclude()
            return jsonify({"merged": etree.tostring(doc).decode()[:200]})
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xxe",
                "line": 14,
                "cwe": "CWE-611",
                "severity": "HIGH",
            }
        ],
    )

    # ssti x3
    add_case(
        cases,
        "S-TP-46",
        "security",
        "s_ssti_jinja.py",
        '''
        """Render a user-supplied Jinja template string directly."""
        from flask import Flask, request
        from jinja2 import Template

        app = Flask(__name__)


        @app.route("/preview")
        def preview():
            tpl = request.args.get("tpl", "")
            # Attacker template can read globals via {{ config }} or run code via
            # the Jinja sandbox-escape pattern — server-side template injection.
            return Template(tpl).render(user="alice")
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "ssti",
                "line": 13,
                "cwe": "CWE-1336",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-47",
        "security",
        "s_ssti_mako.py",
        '''
        """Render a user-supplied Mako template."""
        from flask import Flask, request
        from mako.template import Template

        app = Flask(__name__)


        @app.route("/mako")
        def mako_preview():
            src = request.args.get("src", "")
            # Mako templates execute Python expressions in ${} — RCE if src is
            # attacker-controlled.
            return Template(src).render(name="bob")
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "ssti",
                "line": 13,
                "cwe": "CWE-1336",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-48",
        "security",
        "s_ssti_format.py",
        '''
        """User-supplied format string interpolated against a real object."""
        from flask import Flask, request

        app = Flask(__name__)


        class Settings:
            api_key = "sk_live_real"


        SETTINGS = Settings()


        @app.route("/fmt")
        def fmt():
            spec = request.args.get("fmt", "")
            # str.format with user-controlled format spec lets the caller walk
            # attribute chains: spec="{0.api_key}" leaks the secret.
            return spec.format(SETTINGS)
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "ssti",
                "line": 18,
                "cwe": "CWE-1336",
                "severity": "HIGH",
            }
        ],
    )

    # csrf x3
    add_case(
        cases,
        "S-TP-49",
        "security",
        "s_csrf_missing.py",
        '''
        """State-changing endpoint with no CSRF token check."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        @app.route("/account/email", methods=["POST"])
        def update_email():
            new_email = request.form["email"]
            # No CSRF token verification; an attacker page can submit a hidden
            # form against the victim's session cookie.
            _save_email(new_email)
            return jsonify({"updated": True})


        def _save_email(e: str) -> None:
            pass
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "csrf",
                "line": 12,
                "cwe": "CWE-352",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-50",
        "security",
        "s_csrf_samesite.py",
        '''
        """Session cookie set with SameSite=None and no CSRF token."""
        from flask import Flask, make_response

        app = Flask(__name__)


        @app.route("/login", methods=["POST"])
        def login():
            resp = make_response("ok")
            # SameSite=None allows the cookie to be sent on cross-site requests;
            # combined with no CSRF token, every POST is forgeable.
            resp.set_cookie("session", "abc", samesite="None", secure=True)
            return resp
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "csrf",
                "line": 12,
                "cwe": "CWE-352",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-51",
        "security",
        "s_csrf_get_mutation.py",
        '''
        """Account-deletion exposed on a GET endpoint."""
        from flask import Flask, request, jsonify

        app = Flask(__name__)


        @app.route("/account/delete")
        def delete_account():
            user_id = request.args.get("uid")
            # GET endpoint that mutates server state — any <img src="..."> tag in
            # an attacker page deletes the victim's account.
            _delete_user(user_id)
            return jsonify({"deleted": user_id})


        def _delete_user(uid: str) -> None:
            pass
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "csrf",
                "line": 12,
                "cwe": "CWE-352",
                "severity": "HIGH",
            }
        ],
    )

    # race_condition x3
    add_case(
        cases,
        "S-TP-52",
        "security",
        "s_race_toctou.py",
        '''
        """TOCTOU file existence check followed by open."""
        import os


        def write_unique(path: str, data: str) -> None:
            # Time-of-check (exists?) is separate from time-of-use (open).
            # Between the two, an attacker can create a symlink to /etc/cron.d.
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write(data)
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "race_condition",
                "line": 9,
                "cwe": "CWE-367",
                "severity": "MEDIUM",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-53",
        "security",
        "s_race_balance.py",
        '''
        """Balance update without a transaction or row-level lock."""
        import sqlite3


        def transfer(from_id: int, to_id: int, amt: int) -> None:
            conn = sqlite3.connect("app.db")
            cur = conn.cursor()
            # Read-then-write without BEGIN IMMEDIATE / row lock — concurrent
            # transfers can both pass the balance check and double-spend.
            balance = cur.execute("SELECT balance FROM acct WHERE id=?", (from_id,)).fetchone()[0]
            if balance >= amt:
                cur.execute("UPDATE acct SET balance=balance-? WHERE id=?", (amt, from_id))
                cur.execute("UPDATE acct SET balance=balance+? WHERE id=?", (amt, to_id))
            conn.commit()
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "race_condition",
                "line": 11,
                "cwe": "CWE-362",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-54",
        "security",
        "s_race_unique.py",
        '''
        """Sign-up that checks-then-inserts username without a unique index."""
        import sqlite3


        def signup(name: str, password_hash: str) -> bool:
            conn = sqlite3.connect("app.db")
            cur = conn.cursor()
            # Check-then-insert race: two concurrent signups with the same name
            # both pass the EXISTS check and both insert.
            exists = cur.execute("SELECT 1 FROM users WHERE name=?", (name,)).fetchone()
            if exists:
                return False
            cur.execute("INSERT INTO users(name, pw) VALUES(?,?)", (name, password_hash))
            conn.commit()
            return True
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "race_condition",
                "line": 10,
                "cwe": "CWE-362",
                "severity": "MEDIUM",
            }
        ],
    )

    # insecure_logging x3
    add_case(
        cases,
        "S-TP-55",
        "security",
        "s_log_secret.py",
        '''
        """API key logged on every request."""
        from flask import Flask, request
        import logging

        app = Flask(__name__)
        log = logging.getLogger("api")


        @app.route("/v1/data")
        def get_data():
            api_key = request.headers.get("X-API-Key", "")
            # API key written into application logs — logs are commonly persisted
            # to less-protected backends.
            log.info("request received api_key=%s", api_key)
            return ""
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "insecure_logging",
                "line": 14,
                "cwe": "CWE-532",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-56",
        "security",
        "s_log_token.py",
        '''
        """Exception handler dumps the full request, including Authorization header."""
        from flask import Flask, request
        import logging
        import traceback

        app = Flask(__name__)
        log = logging.getLogger("api")


        @app.route("/account")
        def account():
            try:
                return _load_account()
            except Exception:
                # request.headers includes Authorization: Bearer <token>; logging
                # them captures bearer tokens in the error log.
                log.error("account error: headers=%s\\n%s", dict(request.headers), traceback.format_exc())
                return "error", 500


        def _load_account():
            raise RuntimeError("db down")
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "insecure_logging",
                "line": 17,
                "cwe": "CWE-532",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-57",
        "security",
        "s_log_debug_dump.py",
        '''
        """Debug dump endpoint logs the full Stripe payload including PAN."""
        import logging
        import json

        log = logging.getLogger("debug")


        def handle_payment(payload: dict) -> None:
            # Payload contains card_number, cvv, exp; dumping it to the log is
            # both a CWE-532 logging violation and a PCI-DSS violation.
            log.debug("payment payload: %s", json.dumps(payload))
            _process(payload)


        def _process(p: dict) -> None:
            pass
        ''',
        "security_tp",
        [
            {
                "surface": "security",
                "category": "insecure_logging",
                "line": 11,
                "cwe": "CWE-532",
                "severity": "HIGH",
            }
        ],
    )

    # xss_dom x3
    add_case(
        cases,
        "S-TP-58",
        "security",
        "s_xssdom_inner.html",
        """
        <!doctype html>
        <html>
          <body>
            <div id="msg"></div>
            <script>
              const params = new URLSearchParams(location.search);
              const note = params.get("note") || "";
              // Direct innerHTML assignment of an unsanitized URL parameter —
              // DOM XSS executes payloads like ?note=<img src=x onerror=alert(1)>.
              document.getElementById("msg").innerHTML = note;
            </script>
          </body>
        </html>
        """,
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xss_dom",
                "line": 10,
                "cwe": "CWE-79",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-59",
        "security",
        "s_xssdom_write.html",
        """
        <!doctype html>
        <html>
          <body>
            <script>
              const ref = new URLSearchParams(location.search).get("ref");
              // document.write of a user-controlled query parameter — DOM XSS.
              document.write("Welcome from " + ref);
            </script>
          </body>
        </html>
        """,
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xss_dom",
                "line": 7,
                "cwe": "CWE-79",
                "severity": "HIGH",
            }
        ],
    )

    add_case(
        cases,
        "S-TP-60",
        "security",
        "s_xssdom_jquery.html",
        """
        <!doctype html>
        <html>
          <head><script src="https://code.jquery.com/jquery-3.6.0.min.js"></script></head>
          <body>
            <div id="bio"></div>
            <script>
              const bio = new URLSearchParams(location.search).get("bio") || "";
              // jQuery .html() interprets the argument as HTML; user-controlled
              // input here is DOM XSS.
              $("#bio").html(bio);
            </script>
          </body>
        </html>
        """,
        "security_tp",
        [
            {
                "surface": "security",
                "category": "xss_dom",
                "line": 10,
                "cwe": "CWE-79",
                "severity": "HIGH",
            }
        ],
    )

    # ============================================================
    # Security TNs (15 = 5 inherited + 10 new; 10 calibration + 5 held-out)
    # ============================================================
    add_case(
        cases,
        "S-TN-01",
        "security",
        "s_safe_orm.py",
        "",
        "security_tn",
        [],
        boundary="ORM-parameterized SQL vs. raw f-string SQL",
        inherited=True,
    )
    add_case(
        cases,
        "S-TN-02",
        "security",
        "s_safe_subprocess.py",
        "",
        "security_tn",
        [],
        boundary="list-arg subprocess vs. shell=True",
        inherited=True,
    )
    add_case(
        cases,
        "S-TN-03",
        "security",
        "s_safe_yaml.py",
        "",
        "security_tn",
        [],
        boundary="yaml.safe_load vs. yaml.load",
        inherited=True,
    )
    add_case(
        cases,
        "S-TN-04",
        "security",
        "s_safe_path.py",
        "",
        "security_tn",
        [],
        boundary="realpath containment vs. raw concatenation",
        inherited=True,
    )
    add_case(
        cases,
        "S-TN-05",
        "security",
        "s_safe_auth.py",
        "",
        "security_tn",
        [],
        boundary="admin endpoint with @require_admin decorator vs. without",
        inherited=True,
    )

    # Additional calibration sec TNs (5)
    add_case(
        cases,
        "S-TN-06",
        "security",
        "s_safe_jsx.tsx",
        """
        // React render path — JSX auto-escapes interpolated text, not XSS.
        import React from "react";

        type Props = { name: string; bio: string };

        export function Profile({ name, bio }: Props) {
          // {name} and {bio} are escaped by React; even <script>alert(1)</script>
          // renders as text. No dangerouslySetInnerHTML used.
          return (
            <section>
              <h1>Hello, {name}</h1>
              <p>{bio}</p>
            </section>
          );
        }
        """,
        "security_tn",
        [],
        boundary="React JSX rendering vs. dangerouslySetInnerHTML",
    )

    add_case(
        cases,
        "S-TN-07",
        "security",
        "s_safe_ssrf.py",
        '''
        """Image fetcher with explicit URL allowlist and private-IP check."""
        from flask import Flask, request, jsonify, abort
        import ipaddress
        import socket
        from urllib.parse import urlparse
        import requests

        app = Flask(__name__)
        ALLOWED_HOSTS = {"images.example.com", "cdn.example.org"}


        def _is_safe(url: str) -> bool:
            p = urlparse(url)
            if p.scheme not in ("http", "https") or p.hostname not in ALLOWED_HOSTS:
                return False
            ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)


        @app.route("/img/fetch")
        def fetch_image():
            url = request.args.get("url", "")
            if not _is_safe(url):
                abort(400)
            r = requests.get(url, timeout=3)
            return jsonify({"size": len(r.content)})
        ''',
        "security_tn",
        [],
        boundary="URL allowlist + private-IP check vs. raw user URL",
    )

    add_case(
        cases,
        "S-TN-08",
        "security",
        "s_safe_redirect.py",
        '''
        """Login post-redirect with a fixed allowlist of next-URL names."""
        from flask import Flask, request, redirect, url_for, abort

        app = Flask(__name__)
        ALLOWED_NEXT = {"home", "profile", "settings"}


        @app.route("/login")
        def login():
            next_name = request.args.get("next", "home")
            if next_name not in ALLOWED_NEXT:
                abort(400)
            # url_for resolves to a server-defined route — no open redirect.
            return redirect(url_for(next_name))
        ''',
        "security_tn",
        [],
        boundary="url_for() with allowlist vs. arbitrary user URL",
    )

    add_case(
        cases,
        "S-TN-09",
        "security",
        "s_safe_crypto.py",
        '''
        """Password hashing with bcrypt and a per-record salt."""
        import bcrypt


        def hash_password(plaintext: str) -> bytes:
            # bcrypt.gensalt() generates a per-record random salt; bcrypt.hashpw
            # is intentionally slow and resistant to rainbow tables.
            return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12))


        def check_password(plaintext: str, stored_hash: bytes) -> bool:
            return bcrypt.checkpw(plaintext.encode(), stored_hash)
        ''',
        "security_tn",
        [],
        boundary="bcrypt + per-record salt vs. MD5/SHA without salt",
    )

    add_case(
        cases,
        "S-TN-10",
        "security",
        "s_safe_xxe.py",
        '''
        """XML parser configured to disable entity resolution."""
        from flask import Flask, request, jsonify
        from lxml import etree

        app = Flask(__name__)
        # Parser explicitly disables external entities, DTDs, and network access.
        SAFE_PARSER = etree.XMLParser(
            resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False
        )


        @app.route("/xml/parse", methods=["POST"])
        def parse_xml():
            doc = etree.fromstring(request.data, SAFE_PARSER)
            return jsonify({"root": doc.tag})
        ''',
        "security_tn",
        [],
        boundary="resolve_entities=False parser vs. default parser",
    )

    # Held-out sec TNs (5) -- not inspected during rule calibration
    add_case(
        cases,
        "S-TN-11",
        "security",
        "s_holdout_csprng.py",
        '''
        """Session-token generator using secrets.token_urlsafe."""
        import secrets


        def new_session_token() -> str:
            # secrets.token_urlsafe is backed by os.urandom — cryptographically
            # secure. Use this rather than random.random().
            return secrets.token_urlsafe(32)
        ''',
        "security_tn",
        [],
        boundary="secrets.token_urlsafe vs. random.random()",
        holdout=True,
    )

    add_case(
        cases,
        "S-TN-12",
        "security",
        "s_holdout_envvar.py",
        '''
        """API key sourced from the OS environment."""
        import os


        # Trusted runtime configuration — env vars are not hardcoded source secrets.
        STRIPE_KEY = os.environ["STRIPE_SECRET_KEY"]


        def stripe_client():
            return {"key": STRIPE_KEY}
        ''',
        "security_tn",
        [],
        boundary="os.environ secret vs. literal in source",
        holdout=True,
    )

    add_case(
        cases,
        "S-TN-13",
        "security",
        "s_holdout_literal_eval.py",
        '''
        """Parse a user-supplied literal with ast.literal_eval, not eval."""
        from flask import Flask, request, jsonify
        import ast

        app = Flask(__name__)


        @app.route("/parse")
        def parse():
            text = request.args.get("v", "0")
            # ast.literal_eval only evaluates Python literal structures (numbers,
            # strings, tuples, lists, dicts, booleans, None) — no code execution.
            try:
                v = ast.literal_eval(text)
            except (ValueError, SyntaxError):
                return jsonify({"error": "bad literal"}), 400
            return jsonify({"value": str(v)})
        ''',
        "security_tn",
        [],
        boundary="ast.literal_eval vs. eval()",
        holdout=True,
    )

    add_case(
        cases,
        "S-TN-14",
        "security",
        "s_holdout_csrf_protect.py",
        '''
        """Django POST endpoint protected by @csrf_protect."""
        from django.http import JsonResponse
        from django.views.decorators.csrf import csrf_protect


        @csrf_protect
        def update_email(request):
            # @csrf_protect rejects requests without a valid CSRF token,
            # so cross-site forgery is prevented.
            email = request.POST["email"]
            _save(email)
            return JsonResponse({"updated": True})


        def _save(e):
            pass
        ''',
        "security_tn",
        [],
        boundary="@csrf_protect vs. missing CSRF token",
        holdout=True,
    )

    add_case(
        cases,
        "S-TN-15",
        "security",
        "s_holdout_so_safe.py",
        '''
        """Stored value re-used through the ORM, not raw SQL."""
        from flask import Flask, request, jsonify
        from sqlalchemy import create_engine, Column, Integer, String, select
        from sqlalchemy.orm import declarative_base, Session

        Base = declarative_base()


        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            name = Column(String)


        class Audit(Base):
            __tablename__ = "audit"
            id = Column(Integer, primary_key=True)
            who = Column(String)


        engine = create_engine("sqlite:///app.db")
        app = Flask(__name__)


        @app.route("/admin/audit/<int:user_id>")
        def lookup_audit(user_id: int):
            with Session(engine) as s:
                user = s.get(User, user_id)
                # Stored user.name passed through ORM where() — parameterized;
                # no second-order SQL injection.
                rows = s.execute(select(Audit).where(Audit.who == user.name)).scalars().all()
                return jsonify([{"id": r.id, "who": r.who} for r in rows])
        ''',
        "security_tn",
        [],
        boundary="stored field via ORM where() vs. via raw query",
        holdout=True,
    )
