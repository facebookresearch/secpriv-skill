# Copyright (c) Meta Platforms, Inc. and affiliates.

import os

from cryptography.fernet import Fernet

_cipher = Fernet(os.environ["KMS_FERNET_KEY"].encode())


def save_patient(ssn: str, db) -> None:
    # encrypted-at-rest with a KMS-managed key
    ciphertext = _cipher.encrypt(ssn.encode())
    db.insert("patients", ssn_enc=ciphertext)  # <<SINK
