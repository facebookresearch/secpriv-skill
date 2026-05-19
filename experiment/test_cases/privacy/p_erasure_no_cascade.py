# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""`delete_user` deletes the user row but not their data in other tables."""

import sqlite3


def delete_user(user_id: int) -> None:
    conn = sqlite3.connect("app.db")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    # Comments, activity_log, payment_history, and audit_trail all
    # contain user_id and PII fields, but no cascade delete is issued.
    # Art. 17 erasure must be applied to all derived tables.
    conn.commit()
