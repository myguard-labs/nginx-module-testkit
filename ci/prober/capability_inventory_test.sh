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
REPO_ANCHORS="$(mktemp "${TMPDIR:-/tmp}/capability-repo-anchors.XXXXXX")"
PROBE_FIELDS="$(mktemp "${TMPDIR:-/tmp}/capability-probe-fields.XXXXXX")"
trap 'rm -f "$TMP" "$REPO_ANCHORS" "$PROBE_FIELDS"' EXIT

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

capability_names_unique() {
	awk -F'|' '
		NR <= 2 { next }
		{
			cap = $3
			gsub(/^ +| +$/, "", cap)
			if (seen[cap]++) {
				printf("duplicate capability: %s\n", cap)
				duplicate = 1
			}
		}
		END { exit duplicate ? 1 : 0 }
	' "$TMP"
}

no_http11_cleartext_claim() {
	! grep -q "Every scenario speaks HTTP/1.1 cleartext" \
		docs/attack-hostile-input.md README.md
}

no_protocol_untouched_claim() {
	! grep -q "TLS, HTTP/2 and HTTP/3 are the largest untouched" \
		docs/README.md docs/attack-hostile-input.md README.md
}

extract_repository_anchors() {
	awk '
		function inspect(token) {
			scenario_at = index(token, "ci/prober/scenarios/")
			rule_at = index(token, "rules/stock/")
			if (scenario_at) {
				if (scenario_at != 1) {
					printf("malformed scenario anchor: %s\n", token) > "/dev/stderr"
					bad = 1
					return
				}
				if (token !~ /^ci\/prober\/scenarios\/[A-Za-z0-9._-]+$/) {
					printf("malformed scenario anchor: %s\n", token) > "/dev/stderr"
					bad = 1
				} else {
					print token
				}
			} else if (rule_at) {
				if (rule_at != 1) {
					printf("malformed stock-rule anchor: %s\n", token) > "/dev/stderr"
					bad = 1
					return
				}
				if (token !~ /^rules\/stock\/[A-Za-z0-9._-]+\.rule$/) {
					printf("malformed stock-rule anchor: %s\n", token) > "/dev/stderr"
					bad = 1
				} else {
					print token
				}
			}
		}
		{
			line = $0
			outside = $0
			while (match(line, /`[^`]*`/)) {
				inspect(substr(line, RSTART + 1, RLENGTH - 2))
				line = substr(line, RSTART + RLENGTH)
			}
			gsub(/`[^`]*`/, "", outside)
			if (outside ~ /ci\/prober\/scenarios\/|rules\/stock\//) {
				printf("repository anchor is not a complete backticked token: %s\n", outside) > "/dev/stderr"
				bad = 1
			}
		}
		END { exit bad ? 1 : 0 }
	' "$TMP"
}

extract_probe_fields() {
	awk '
		/probe field:/ {
			line = substr($0, index($0, "probe field:") + length("probe field:"))
			outside = line
			found = 0
			while (match(line, /`[^`]*`/)) {
				token = substr(line, RSTART + 1, RLENGTH - 2)
				if (token !~ /^[A-Za-z][A-Za-z0-9_-]*\.[A-Za-z0-9._-]+$/) {
					printf("malformed probe field anchor: %s\n", token) > "/dev/stderr"
					bad = 1
				} else {
					print token
					found = 1
				}
				line = substr(line, RSTART + RLENGTH)
			}
			gsub(/`[^`]*`/, "", outside)
			gsub(/[[:space:].|]/, "", outside)
			gsub(/and/, "", outside)
			if (outside != "") {
				printf("malformed text after probe field marker: %s\n", outside) > "/dev/stderr"
				bad = 1
			}
			if (!found) {
				printf("probe field marker has no field anchor: %s\n", $0) > "/dev/stderr"
				bad = 1
			}
		}
		END { exit bad ? 1 : 0 }
	' "$TMP"
}

repository_anchor_exists() {
	case $1 in
		ci/prober/scenarios/*) [ -d "$1" ] ;;
		rules/stock/*.rule) [ -f "$1" ] ;;
		*) return 1 ;;
	esac
}

schema_has_probe_field() {
	local field=$1

	awk -v field="$field" '
		/^  "fields": \{/ { in_fields = 1; next }
		in_fields && /^  \}/ { in_fields = 0 }
		in_fields && $1 == "\"" field "\":" { found = 1 }
		END { exit found ? 0 : 1 }
	' probe-schema.json
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
check 'each capability appears exactly once' capability_names_unique

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

if extract_repository_anchors | LC_ALL=C sort -u >"$REPO_ANCHORS" \
	&& [ -s "$REPO_ANCHORS" ]; then
	check 'repository evidence anchors were extracted' true
	while IFS= read -r path; do
		check "repository anchor exists with the expected type: $path" \
			repository_anchor_exists "$path"
	done <"$REPO_ANCHORS"
else
	check 'repository evidence anchors were extracted' false
fi

if extract_probe_fields | LC_ALL=C sort -u >"$PROBE_FIELDS"; then
	check 'probe field evidence anchors were extracted' test -s "$PROBE_FIELDS"
	while IFS= read -r field; do
		check "probe field is declared by the schema: $field" \
			schema_has_probe_field "$field"
	done <"$PROBE_FIELDS"
else
	check 'probe field evidence anchors were extracted' false
fi

check 'public docs no longer claim every scenario is HTTP/1.1 cleartext' \
	no_http11_cleartext_claim
check 'public docs no longer claim TLS and HTTP/2 are untouched' \
	no_protocol_untouched_claim

if [ "$not_ok" -gt 0 ]; then
	exit 1
fi
