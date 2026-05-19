"""Load a user-uploaded scikit-learn model file via joblib."""

import io

import joblib
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/predict", methods=["POST"])
def predict():
    blob = request.files["model"].read()
    # joblib.load uses pickle internally — attacker-controlled bytes = RCE.
    model = joblib.load(io.BytesIO(blob))
    x = request.form.get("x", "0")
    return jsonify({"prediction": float(model.predict([[float(x)]])[0])})
