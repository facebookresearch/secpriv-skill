# Copyright (c) Meta Platforms, Inc. and affiliates.

import hashlib
import secrets


def store_user_pseudonym(email: str, db) -> None:
    # random per-record salt -> irreversible pseudonym, not the address
    salt = secrets.token_bytes(16)
    pseudonym = hashlib.pbkdf2_hmac("sha256", email.encode(), salt, 200_000)
    db.insert("users", salt=salt.hex(), pseudonym=pseudonym.hex())  # <<SINK
