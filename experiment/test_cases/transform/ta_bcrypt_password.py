# Copyright (c) Meta Platforms, Inc. and affiliates.

import bcrypt


def register(password: str, db) -> None:
    # per-record salt + adaptive KDF
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    db.insert("accounts", pw_hash=hashed)  # <<SINK
