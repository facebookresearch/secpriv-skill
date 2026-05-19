"""Shipping address is collected for fulfillment then re-used for ad targeting."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def store_shipping_address(user_id: str, address: dict) -> None:
    # Collected for: package delivery.
    pass


def add_to_ad_audience(user_id: str, address: dict) -> None:
    """Builds a geographic ad-targeting cohort from the address."""
    pass


@app.route("/checkout/address", methods=["POST"])
def save_address():
    user_id = request.json["user_id"]
    address = request.json["address"]
    store_shipping_address(user_id, address)
    # Repurposes the shipping address (collected for fulfillment) for
    # ad targeting without re-consent — purpose creep.
    add_to_ad_audience(user_id, address)
    return jsonify({"ok": True})
