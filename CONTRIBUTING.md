<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# Contributing to SecPriv

Contributions welcome: new test cases, new categories, alias-table additions, suppression-rule refinements, runner improvements, and bug fixes.

## Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you change `SKILL.md`, also bump the benchmark and verify the headline metrics haven't regressed. The methodology is the artifact under test — silent changes will produce ungeneralizable results.
3. If you add new test cases, place them under `experiment/test_cases/<surface>/` with a corresponding entry in `experiment/ground_truth.json` (category, line, severity, and the `holdout` flag).
4. If you add a new canonical category, update: (a) `SKILL.md` Phase 3 description, (b) `experiment/runner/aliases.json` if the model is likely to emit sub-category names, (c) `experiment/category_sources.md` with the public ranking / regulatory basis that justifies the category.
5. Run `python3 experiment/runner/evaluate.py --config secpriv_sonnet --max-cases 10` as a smoke test before submitting.
6. Open a pull request against `main` with a clear description of the change and the threat model it addresses.

## Contributor License Agreement (CLA)

In order to accept your pull request, we need you to submit a CLA. You only need to do this once to work on any of Meta's open-source projects.

Complete your CLA here: <https://code.facebook.com/cla>

## Issues

We use GitHub Issues to track public bugs and feature requests. Please ensure your description is clear and has sufficient instructions to reproduce the issue.

For security-sensitive issues, please follow the disclosure process in [SECURITY.md](SECURITY.md) instead.

## Coding Style

- Python: standard library only where possible; `black`-formatted; type hints encouraged on new code.
- Test cases: self-contained files of 30-60 LOC with realistic framework imports. Each TN case must target a specific discrimination boundary, not obviously safe code.
- Held-out cases: never inspect held-out TN content during suppression-rule editing. The `holdout: true` flag in `ground_truth.json` is the contract.

## License

By contributing to SecPriv, you agree that your contributions will be licensed under the MIT License found in [LICENSE](LICENSE).
