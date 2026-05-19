# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Audit log written via TimedRotatingFileHandler with 30-day retention."""

import logging
from logging.handlers import TimedRotatingFileHandler


audit = logging.getLogger("audit")
audit.setLevel(logging.INFO)
# Daily rotation, 30-day retention — bounded retention, not indefinite.
handler = TimedRotatingFileHandler(
    "/var/log/app/audit.log", when="midnight", backupCount=30
)
audit.addHandler(handler)


def record_action(user_id: str, action: str) -> None:
    audit.info("user=%s action=%s", user_id, action)
