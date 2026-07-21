# Copyright (c) Meta Platforms, Inc. and affiliates.

import hashlib
import secrets


def profile_badge(display_name: str) -> str:
    # hashed field is opaque hex: not personal data AND not renderable markup
    salt = secrets.token_bytes(16)
    tag = hashlib.pbkdf2_hmac("sha256", display_name.encode(), salt, 200_000).hex()
    return f"<span class='badge'>{tag}</span>"  # <<SINK
