# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Logs a salted hash of the email for failure-rate metrics."""

import hashlib
import logging
import os

log = logging.getLogger("auth")
PER_RECORD_SALT_BYTES = 16


def _salted_hash(email: str) -> str:
    salt = os.urandom(PER_RECORD_SALT_BYTES)
    h = hashlib.pbkdf2_hmac("sha256", email.encode(), salt, 100_000)
    return salt.hex() + ":" + h.hex()


def log_reset_failure(email: str) -> None:
    # Per-record salt is irreversible w.r.t. rainbow tables — adequate.
    log.error("password reset failed for hashed_email=%s", _salted_hash(email))
