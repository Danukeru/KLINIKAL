#!/usr/bin/env bash
# Run the proof under LD_PRELOAD, then show wg counters as evidence.
set -euo pipefail
cd "$(dirname "$0")"
export KLINIKAL_WG_CONF="$(pwd)/wg.conf"
LD_PRELOAD="$(pwd)/libklinikal.so" python3 test_preload.py
echo "--- wg0 peer counters (host side) ---"
sudo wg show wg0
