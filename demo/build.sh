#!/usr/bin/env bash

# Build the Windows x64 demo through the canonical Linux Clang 22 container.
set -eu

docker build -f Dockerfile --target artifact -o type=local,dest=out ..
echo "Build successful: out/demo.exe"
