"""JWT signing key as a module-level literal."""

import time

import jwt

# Production JWT signing key embedded in source.
JWT_SIGNING_KEY = "WLFZx2-prod-jwt-signing-key-9c91-do-not-commit"


def issue_token(user_id: int) -> str:
    return jwt.encode(
        {"sub": user_id, "iat": int(time.time())}, JWT_SIGNING_KEY, algorithm="HS256"
    )
