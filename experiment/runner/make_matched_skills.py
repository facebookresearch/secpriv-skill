# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Derive matched single-surface skills from the unified SKILL.md.

For the fair matched-schema two-skill baseline (config ``two_skill_matched``,
a.k.a. C6): the two derived skills share the unified skill's *full* 30-category
schema, semantic memory, and Phase 2 transformation-state classifier, and differ
ONLY in which surface they are allowed to emit. Running them as two separate
passes and unioning the outputs isolates the *architecture* (two passes vs. one
unified pass) from category-coverage expansion -- the confound raised by ACSAC
reviewer 531A-2 and director point U4. The skills are regenerated from SKILL.md
so they cannot silently drift from it.
"""

from __future__ import annotations

from pathlib import Path

RUNNER_DIR: Path = Path(__file__).resolve().parent
EXPERIMENT_DIR: Path = RUNNER_DIR.parent
PROJECT_ROOT: Path = EXPERIMENT_DIR.parent
UNIFIED_SKILL: Path = PROJECT_ROOT / "SKILL.md"
DERIVED_DIR: Path = EXPERIMENT_DIR / "derived"

_RESTRICTION = """

---

## SURFACE RESTRICTION (matched-schema two-skill baseline)

You are running as the **{surface}-only** reviewer within a two-skill
configuration. Apply the entire methodology above unchanged -- every phase, the
complete 30-category schema, the semantic memory, the Phase 2 transformation-state
classifier, and all Phase 4 suppression rules -- but restrict your emitted output
to the **{surface}** surface ONLY:

- Emit a finding only when its `surface` is `{surface}`.
- Do NOT emit any `{other}` finding, even when an obvious {other} issue is present
  on the same line; the paired {other}-only reviewer is responsible for it.
- If there is no {surface} finding, return `[]`.
"""


def derive(surface: str, other: str) -> str:
    """Unified skill text + a surface-restriction addendum."""
    return UNIFIED_SKILL.read_text() + _RESTRICTION.format(surface=surface, other=other)


def main() -> None:
    DERIVED_DIR.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, str] = {
        "secpriv_sec_only.md": derive("security", "privacy"),
        "secpriv_priv_only.md": derive("privacy", "security"),
    }
    for name, text in outputs.items():
        path = DERIVED_DIR / name
        path.write_text(text)
        print(f"wrote {path} ({len(text)} chars)")


if __name__ == "__main__":
    main()
