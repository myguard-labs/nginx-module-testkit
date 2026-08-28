#!/usr/bin/env bash
#
# TAP self-test for the raw hostile-H2 response decoder and settle loop. The
# driver owns both attack-side boundaries; its test mode injects malformed
# received bytes and a failed snapshot at those exact boundaries, without
# needing a real server to violate HTTP/2 on demand.
set -euo pipefail

cd "$(dirname "$0")"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/h2-frame-parser.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

PROBER_LIB="$PWD/lib.sh" \
  PROBER_PREFIX="$tmp" \
  PROBER_RESOLVED_PORT=1 \
  H2_HOSTILE_FRAMING_SELF_TEST=1 \
  ./scenarios/h2-hostile-framing/driver.sh
