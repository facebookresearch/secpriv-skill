# Copyright (c) Meta Platforms, Inc. and affiliates.


def save_ssn(ssn: str, db) -> None:
    # hex is a reversible encoding, not encryption
    db.insert("people", ssn_hex=ssn.encode().hex())  # <<SINK
