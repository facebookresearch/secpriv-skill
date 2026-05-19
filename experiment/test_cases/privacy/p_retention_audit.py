# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Audit log appended on every action with no rotation or TTL."""

from datetime import datetime


AUDIT_FILE = "/var/log/app/audit.log"


def record_action(user_id: str, action: str, details: dict) -> None:
    # Append-only log with no rotation, no retention policy, no TTL.
    line = f"{datetime.utcnow().isoformat()} user={user_id} action={action} details={details}\n"
    with open(AUDIT_FILE, "a") as f:
        f.write(line)
