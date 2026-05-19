# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

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
