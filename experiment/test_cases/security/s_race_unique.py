"""Sign-up that checks-then-inserts username without a unique index."""

import sqlite3


def signup(name: str, password_hash: str) -> bool:
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # Check-then-insert race: two concurrent signups with the same name
    # both pass the EXISTS check and both insert.
    exists = cur.execute("SELECT 1 FROM users WHERE name=?", (name,)).fetchone()
    if exists:
        return False
    cur.execute("INSERT INTO users(name, pw) VALUES(?,?)", (name, password_hash))
    conn.commit()
    return True
