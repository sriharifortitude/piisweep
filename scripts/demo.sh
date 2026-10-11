#!/usr/bin/env bash
# Prints the README's example: each command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${PIISWEEP:-./bin/piisweep}
echo "\$ piisweep testdata/app.log"
"$bin" testdata/app.log | tr -d '\r'
echo
echo "\$ piisweep testdata/app.log --min-confidence low --summary"
"$bin" testdata/app.log --min-confidence low --summary | tr -d '\r'
