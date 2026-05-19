"""User profile sync to a non-adequacy-decision country."""

import requests


def sync_profile(user: dict) -> None:
    # The destination country has no GDPR adequacy decision and the
    # transfer relies on no documented safeguards. Art. 45 violation.
    requests.post("https://api.example-no-adequacy.com/users", json=user)


def on_user_update(user: dict) -> None:
    sync_profile(user)
