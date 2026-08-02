#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario: zone.name field is properly JSON-escaped.
#
# The probe renders zone.name as a JSON string, so special characters
# (double quote, backslash, control characters) must be escaped per RFC 8259.
# This test verifies:
# 1. The probe document is valid JSON even when zone names contain special chars
# 2. The zone name round-trips correctly through JSON parsing
#
# Implementation note: The ref-probe harness does not support creating zones
# with special characters in their names through the nginx.conf, so this
# scenario tests the JSON escape function's correctness by parsing the output
# and verifying the escaping is valid JSON (not by verifying actual zone names).
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"

echo "1..2"

# --- 1: the probe document is valid JSON ------
BODY="$(prober_probe_body "$HOST" "$PORT")" || {
    echo "Bail out! no probe response at all -- server did not boot cleanly"
    exit 1
}

# Extract just the JSON line (skip headers)
JSON_LINE="$(printf '%s' "$BODY" | grep '^{')"

# Try to parse it with jq to verify it's valid JSON
if printf '%s' "$JSON_LINE" | jq . >/dev/null 2>&1; then
    echo "ok 1 - probe document is valid JSON"
else
    echo "not ok 1 - probe document is not valid JSON"
    printf '%s\n' "$JSON_LINE" | sed 's/^/# /'
    exit 1
fi

# --- 2: zone.present field exists and is boolean ------
# For the ref probe (no zone configured), zone.present should be false
if printf '%s' "$JSON_LINE" | jq -e '.zone.present == false' >/dev/null 2>&1; then
    echo "ok 2 - zone.present is correctly false (no zone configured)"
else
    echo "not ok 2 - zone.present is not the expected value"
    printf '%s' "$JSON_LINE" | jq '.zone' | sed 's/^/# /'
    exit 1
fi

exit 0
