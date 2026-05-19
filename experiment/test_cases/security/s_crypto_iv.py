# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""AES-CBC encryption with a hardcoded zero IV."""

from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

KEY = b"0123456789abcdef0123456789abcdef"
# Hardcoded all-zero IV — enables chosen-plaintext attacks on CBC mode.
IV = b"\x00" * 16


def encrypt(data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    enc = cipher.encryptor()
    pad = 16 - (len(data) % 16)
    return enc.update(data + bytes([pad]) * pad) + enc.finalize()
