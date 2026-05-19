# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""`delete_user` cascades to all PII-bearing tables."""

import sqlite3


PII_TABLES = ["comments", "activity_log", "payment_history", "audit_trail"]


def delete_user(user_id: int) -> None:
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # Cascade-delete the user from every PII-bearing table.
    for tbl in PII_TABLES:
        cur.execute(f"DELETE FROM {tbl} WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
