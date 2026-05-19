"""`delete_user` only marks the row inactive; PII fields persist."""

import sqlite3


def delete_user(user_id: int) -> None:
    conn = sqlite3.connect("app.db")
    # Soft-delete only sets a flag; email, name, address remain in the
    # row indefinitely. Right-to-erasure requires actual erasure.
    conn.execute(
        "UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,)
    )
    conn.commit()
