"""Recursive directory listing without a depth bound."""

import os


def list_all(path: str) -> list:
    out = []
    for entry in os.listdir(path):
        full = os.path.join(path, entry)
        # No depth limit and no symlink check — symlink loops produce
        # unbounded recursion until the stack overflows.
        if os.path.isdir(full):
            out.extend(list_all(full))
        else:
            out.append(full)
    return out
