# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Generate a session token using random.random()."""

import random
import string


def new_session_token() -> str:
    # random.random() is the Python Mersenne Twister — predictable and
    # not cryptographically secure. Use secrets.token_urlsafe instead.
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(32))
