#!/usr/bin/env bash
#
# README capability inventory contract. Public gap rows are part of the
# harness API: a consumer deciding whether to adopt this testkit reads them as
# shipped, partial, open or parked work. This test keeps each row tied to a
# concrete scenario, probe field or explicit blocker instead of free prose.
set -euo pipefail

cd "$(dirname "$0")/../.."

README=README.md
TMP="$(mktemp "${TMPDIR:-/tmp}/capability-inventory.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

awk '
    /^<!-- capability-inventory:start -->$/ { in_table = 1; next }
    /^<!-- capability-inventory:end -->$/ { in_table = 0; next }
    in_table && /^\|/ { print }
' "$README" >"$TMP"

ok=0
not_ok=0

check() {
	local msg=$1

	shift
	if "$@"; then
		ok=$((ok + 1))
		printf 'ok %d - %s\n' "$((ok + not_ok))" "$msg"
	else
		not_ok=$((not_ok + 1))
		printf 'not ok %d - %s\n' "$((ok + not_ok))" "$msg"
	fi
}

table_nonempty() {
	[ -s "$TMP" ]
}

require_row() {
	local capability=$1 status=$2

	grep -Eq "^[|] ${status} [|] ${capability} [|]" "$TMP"
}

no_http11_cleartext_claim() {
	! grep -q "Every scenario speaks HTTP/1.1 cleartext" \
		docs/attack-hostile-input.md README.md
}

no_protocol_untouched_claim() {
	! grep -q "TLS, HTTP/2 and HTTP/3 are the largest untouched" \
		docs/README.md docs/attack-hostile-input.md README.md
}

check 'README exposes a capability inventory table' table_nonempty
check 'TLS is not still listed as an open protocol gap' \
	require_row "protocol-tls" "shipped"
check 'HTTP/2 is not still listed as an open protocol gap' \
	require_row "protocol-h2" "shipped"
check 'HTTP/3 remains explicitly open' require_row "protocol-h3" "open"
check 'stream is parked with a blocker' require_row "protocol-stream" "parked"
check 'allocation-count oracle is not still listed as open' \
	require_row "alloc-counter" "shipped"
check 'hostile input rows point at shipped generators' \
	require_row "hostile-input" "shipped"

if awk -F'|' '
    NR <= 2 { next }
    {
        status = $2
        cap = $3
        evidence = $4
        gsub(/^ +| +$/, "", status)
        gsub(/^ +| +$/, "", cap)
        gsub(/^ +| +$/, "", evidence)

        if (status !~ /^(open|partial|shipped|parked)$/) {
            printf("bad status for %s: %s\n", cap, status)
            bad = 1
        }

        if (evidence !~ /(ci\/prober\/scenarios\/|probe field:|blocker:)/) {
            printf("missing evidence for %s\n", cap)
            bad = 1
        }

        if (status == "shipped" && evidence !~ /ci\/prober\/scenarios\//) {
            printf("shipped row has no scenario: %s\n", cap)
            bad = 1
        }

        if ((status == "open" || status == "parked" || status == "partial") && evidence !~ /blocker:/) {
            printf("%s row has no blocker: %s\n", status, cap)
            bad = 1
        }
    }
    END { exit bad ? 1 : 0 }
' "$TMP"; then
	check 'each inventory row has an allowed status and concrete evidence' true
else
	check 'each inventory row has an allowed status and concrete evidence' false
fi

while IFS= read -r path; do
	[ -d "$path" ] || {
		not_ok=$((not_ok + 1))
		printf 'not ok %d - scenario anchor exists: %s\n' "$((ok + not_ok))" "$path"
		continue
	}
	ok=$((ok + 1))
	printf 'ok %d - scenario anchor exists: %s\n' "$((ok + not_ok))" "$path"
done < <(grep -Eo 'ci/prober/scenarios/[A-Za-z0-9._-]+' "$TMP" | sort -u)

check 'public docs no longer claim every scenario is HTTP/1.1 cleartext' \
	no_http11_cleartext_claim
check 'public docs no longer claim TLS and HTTP/2 are untouched' \
	no_protocol_untouched_claim

if [ "$not_ok" -gt 0 ]; then
	exit 1
fi
