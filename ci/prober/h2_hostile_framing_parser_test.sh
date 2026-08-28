#!/usr/bin/env bash
#
# TAP self-test for the raw hostile-H2 response decoder. The driver owns this
# parser because it is the attack-side half of its GOAWAY delivery oracle; its
# test mode injects malformed received bytes at that exact boundary, without
# needing a real server to violate HTTP/2 on demand.
set -euo pipefail

cd "$(dirname "$0")"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/h2-frame-parser.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

PROBER_LIB="$PWD/lib.sh" \
  PROBER_PREFIX="$tmp" \
  PROBER_RESOLVED_PORT=1 \
  H2_FRAME_PARSE_TEST=1 \
  ./scenarios/h2-hostile-framing/driver.sh
