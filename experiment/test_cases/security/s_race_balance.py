"""Balance update without a transaction or row-level lock."""

import sqlite3


def transfer(from_id: int, to_id: int, amt: int) -> None:
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # Read-then-write without BEGIN IMMEDIATE / row lock — concurrent
    # transfers can both pass the balance check and double-spend.
    balance = cur.execute("SELECT balance FROM acct WHERE id=?", (from_id,)).fetchone()[
        0
    ]
    if balance >= amt:
        cur.execute("UPDATE acct SET balance=balance-? WHERE id=?", (amt, from_id))
        cur.execute("UPDATE acct SET balance=balance+? WHERE id=?", (amt, to_id))
    conn.commit()
