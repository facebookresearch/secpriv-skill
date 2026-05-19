# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

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
