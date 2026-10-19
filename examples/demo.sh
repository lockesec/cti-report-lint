#!/bin/sh
# The README's quick start, played in a throwaway directory.
#
#   sh examples/demo.sh        # needs `cti-report-lint` on PATH (pip install .)
#
# CI runs this script, and examples/check_readme.py compares the README
# transcript with this script's output line for line (a mismatch fails CI).
# This script itself exits non-zero if any step does not exit as expected.
set -u

command -v cti-report-lint >/dev/null 2>&1 || { echo "demo: cti-report-lint is not on PATH (pip install .)" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
DEMO=$(mktemp -d "${TMPDIR:-/tmp}/cti-report-lint-demo.XXXXXX")
trap 'rm -rf "$DEMO"' EXIT
cd "$DEMO"
cp "$HERE"/incident-report-before.md "$HERE"/incident-report-after.md .

expect() {  # expect <code> <command...>: show the command, run it, check its exit code
    want=$1; shift
    printf '$ %s\n' "$*"
    "$@"; got=$?
    printf '(exit %s)\n' "$got"
    [ "$got" = "$want" ] || { echo "demo: expected exit $want, got $got" >&2; exit 1; }
}

expect 1 cti-report-lint check incident-report-before.md
expect 0 cti-report-lint check incident-report-after.md
expect 2 cti-report-lint check missing.md
expect 0 cti-report-lint redact incident-report-before.md --map map.json -o red.md
expect 0 cti-report-lint restore red.md --map map.json -o back.md
cmp incident-report-before.md back.md || { echo "demo: round trip is not byte-exact" >&2; exit 1; }
echo "round trip: byte-exact"
