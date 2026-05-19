#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Wave 3: two-skill baseline + TN-stability extras
# This script waits for Wave 1+2 to finish, then runs Wave 3 sequentially.

set -e
cd "$(dirname "$0")"

echo "[$(date)] Wave 3 script started. Waiting for Wave 1+2 to finish..."

# Wait until all 4 Wave 1+2 result files exist
while true; do
    count=0
    for f in results/no_skill_sonnet/run1.json results/secpriv_haiku/run1.json results/secpriv_sonnet/run1.json results/detector_only_sonnet/run1.json; do
        [ -f "$f" ] && count=$((count + 1))
    done
    if [ "$count" -eq 4 ]; then
        echo "[$(date)] Wave 1+2 complete. Starting Wave 3."
        break
    fi
    sleep 60
done

# Quick sanity check
echo "[$(date)] Wave 1+2 results summary:"
python3 runner/aggregate.py 2>&1 | head -15

# Wave 3a: Two-skill baseline (longest: ~4.5h)
echo ""
echo "[$(date)] Starting C2: two_skill_sonnet run1..."
python3 runner/evaluate.py --config two_skill_sonnet --run-id run1
echo "[$(date)] C2 done."

# Wave 3b: TN-stability extras for SecPriv-Sonnet
echo ""
echo "[$(date)] Starting C1 TN extras: run2 (TN cases only)..."
python3 runner/evaluate.py --config secpriv_sonnet --run-id run2 --only-kind security_tn
python3 runner/evaluate.py --config secpriv_sonnet --run-id run2 --only-kind privacy_tn
python3 runner/evaluate.py --config secpriv_sonnet --run-id run2 --only-kind cross_tn
echo "[$(date)] run2 TN done."

echo ""
echo "[$(date)] Starting C1 TN extras: run3 (TN cases only)..."
python3 runner/evaluate.py --config secpriv_sonnet --run-id run3 --only-kind security_tn
python3 runner/evaluate.py --config secpriv_sonnet --run-id run3 --only-kind privacy_tn
python3 runner/evaluate.py --config secpriv_sonnet --run-id run3 --only-kind cross_tn
echo "[$(date)] run3 TN done."

# Final aggregation
echo ""
echo "[$(date)] All runs complete. Final aggregation:"
python3 runner/aggregate.py
python3 runner/rescore.py
python3 runner/analyze_failures.py --config secpriv_sonnet --run-id run1

echo ""
echo "[$(date)] EXPERIMENT COMPLETE."
