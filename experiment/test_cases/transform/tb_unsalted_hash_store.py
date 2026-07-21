# Copyright (c) Meta Platforms, Inc. and affiliates.

import hashlib


def index_user(email: str, db) -> None:
    # unsalted hash of a low-entropy identifier -> re-identifiable
    digest = hashlib.sha256(email.encode()).hexdigest()
    db.insert("user_index", email_hash=digest)  # <<SINK
