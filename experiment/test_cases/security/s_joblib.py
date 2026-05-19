# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

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
