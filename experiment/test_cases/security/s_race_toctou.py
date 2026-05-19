"""TOCTOU file existence check followed by open."""

import os


def write_unique(path: str, data: str) -> None:
    # Time-of-check (exists?) is separate from time-of-use (open).
    # Between the two, an attacker can create a symlink to /etc/cron.d.
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(data)
