#!/usr/bin/env bash
# Build the LD_PRELOAD shared object (native linux/amd64, no MinGW).
set -euo pipefail
cd "$(dirname "$0")"
go build -buildmode=c-shared -o libklinikal.so
# c-shared links tolerate undefined symbols until load time; catch
# missing internal symbols here instead of at the app's first dlopen
if ldd -r ./libklinikal.so 2>&1 | grep -qi 'undefined symbol'; then
    echo "ERROR: undefined symbols in libklinikal.so:" >&2
    ldd -r ./libklinikal.so 2>&1 | grep -i 'undefined symbol' >&2
    exit 1
fi
echo "built: $(pwd)/libklinikal.so"
