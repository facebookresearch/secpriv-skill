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
