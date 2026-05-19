"""Pseudonymizing user identifier for cross-system join."""

import hashlib


def pseudonymize(email: str) -> str:
    """Hash email with SHA-256 to use as a stable pseudonym."""
    # Unsalted SHA-256 of an email is recoverable via rainbow tables and
    # joinable across systems — this is NOT adequate anonymization.
    return hashlib.sha256(email.encode()).hexdigest()


def emit_metric(email: str, metric: str, value: float) -> None:
    pid = pseudonymize(email)
    # pid is treated as anonymous, but is reversible.
    _publish({"pid": pid, "metric": metric, "value": value})


def _publish(record: dict) -> None:
    pass
