"""Session-token generator using secrets.token_urlsafe."""

import secrets


def new_session_token() -> str:
    # secrets.token_urlsafe is backed by os.urandom — cryptographically
    # secure. Use this rather than random.random().
    return secrets.token_urlsafe(32)
