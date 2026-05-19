"""Page-view counter with user-IP cardinality."""

from flask import Flask, request
from prometheus_client import Counter

app = Flask(__name__)
PAGE_VIEWS = Counter("page_views_total", "Page views", ["path", "client_ip"])


@app.route("/")
def home():
    # Including raw client IP as a metric label — high-cardinality PII in metrics.
    PAGE_VIEWS.labels(path="/", client_ip=request.remote_addr).inc()
    return "hello"


@app.route("/about")
def about():
    PAGE_VIEWS.labels(path="/about", client_ip=request.remote_addr).inc()
    return "about"
