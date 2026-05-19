# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Session-token generator using secrets.token_urlsafe."""

import secrets


def new_session_token() -> str:
    # secrets.token_urlsafe is backed by os.urandom — cryptographically
    # secure. Use this rather than random.random().
    return secrets.token_urlsafe(32)
