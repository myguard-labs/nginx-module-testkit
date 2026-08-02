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
# 1. The probe document is valid JSON even when the zone name contains
#    special characters
# 2. zone.present is true (this scenario's env configures a real zone via
#    `test_ref_zone`, unlike every other scenario against this reference
#    module)
# 3. zone.name, once JSON-decoded, is EXACTLY the raw name the env file
#    configured -- not merely "some valid JSON string". This is the actual
#    regression test: an escaping bug that drops a byte, mis-escapes a
#    character, or truncates the string can still produce syntactically valid
#    JSON, and only comparing against the known raw name catches that.
#
# The raw name (RAW_ZONE_NAME below) must be kept in sync with the
# `test_ref_zone` argument in this scenario's env file by hand -- there is no
# single source of truth to derive it from, since env holds the nginx-conf
# QUOTED source form (with \", \\, \t escapes) and this driver needs the
# UNESCAPED bytes nginx's own lexer produces from it.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"

# The unescaped bytes nginx's config lexer produces from env's
# `test_ref_zone "a\"b\\c\td" 1m;` -- a literal double quote, a literal
# backslash, and a literal TAB (0x09), matching JSON's two forbidden-unescaped
# characters plus a C0 control character.
RAW_ZONE_NAME=$'a"b\\c\td'

echo "1..3"

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

# --- 2: zone.present is true ------
# This scenario's env configures a real zone via test_ref_zone, so unlike
# every other scenario against this reference module, zone.present must be
# true here -- a false here means the zone never got configured at all and
# test 3 below would be vacuously comparing against nothing.
if printf '%s' "$JSON_LINE" | jq -e '.zone.present == true' >/dev/null 2>&1; then
    echo "ok 2 - zone.present is true (test_ref_zone configured)"
else
    echo "not ok 2 - zone.present is not true -- test_ref_zone did not register"
    printf '%s' "$JSON_LINE" | jq '.zone' | sed 's/^/# /'
    exit 1
fi

# --- 3: zone.name round-trips to the exact raw name ------
GOT_NAME="$(printf '%s' "$JSON_LINE" | jq -r '.zone.name')"
if [ "$GOT_NAME" = "$RAW_ZONE_NAME" ]; then
    echo "ok 3 - zone.name round-trips exactly through JSON escaping"
else
    echo "not ok 3 - zone.name does not match the configured raw name"
    printf '%s\n' "$GOT_NAME" | od -c | sed 's/^/# got: /'
    printf '%s\n' "$RAW_ZONE_NAME" | od -c | sed 's/^/# want: /'
    exit 1
fi

exit 0
