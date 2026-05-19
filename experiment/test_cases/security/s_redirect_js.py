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
