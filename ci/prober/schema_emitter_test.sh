#!/usr/bin/env bash
#
# TAP self-test: the schema describes the EMITTER, not just the fixtures.
#
# schema_test.c checks two fixtures against ../../probe-schema.json. Both live in
# this repo and are edited by the same hand, so they can agree with each other
# while having drifted away from the code that actually renders the document:
# rename a member in ngx_test_probe_json() and neither notices. This closes
# that loop by reading the format strings in ../../src/ngx_test_probe.c.
#
# Grep rather than a compile-and-run: the emitter needs real nginx headers and
# a configured build to execute, which is the runtime leg's job. The member
# NAMES, though, are literal text in the format strings, and a rename is
# exactly the drift being guarded against -- so matching them as text catches
# the failure this suite exists for without needing a server.
set -euo pipefail

cd "$(dirname "$0")"

EMITTER=../../src/ngx_test_probe.c
SCHEMA=../../probe-schema.json

PLANNED=34
tests_run=0
failures=0

echo "1..$PLANNED"

ok() {
    tests_run=$((tests_run + 1))
    if [ "$1" -eq 0 ]; then
        echo "ok $tests_run - $2"
    else
        failures=$((failures + 1))
        echo "not ok $tests_run - $2"
    fi
}

# Leaf members, as they appear inside the emitter's format strings. Nested
# paths are checked by their leaf name: the emitter renders `"total":%ui`
# inside the connections object, so the text to look for is `"total"`, while
# the schema spells the same field `connections.total`.
#
#   <schema path>:<leaf name as the emitter writes it>
FIELDS="
flavor:flavor
flavor_version:flavor_version
pid:pid
ppid:ppid
config_generation:config_generation
page_size:page_size
connections:connections
connections.total:total
connections.free:free
fds:fds
timers:timers
fds_by_kind:fds_by_kind
fds_by_kind.socket:socket
fds_by_kind.file:file
fds_by_kind.anon:anon
fds_by_kind.other:other
smaps:smaps
smaps.pss:pss
smaps.private_dirty:private_dirty
pool:pool
pool.cycle_used:cycle_used
pool.cycle_blocks:cycle_blocks
pool.cycle_large:cycle_large
pool.cycle_cleanup:cycle_cleanup
zone:zone
zone.present:present
zone.name:name
zone.size:size
zone.slab_pages_free:slab_pages_free
"

for entry in $FIELDS; do
    path=${entry%%:*}
    leaf=${entry##*:}

    # The emitter writes members as \"leaf\": inside a C string literal.
    if grep -q "\\\\\"$leaf\\\\\":" "$EMITTER" \
        && grep -q "\"$path\"" "$SCHEMA"; then
        ok 0 "\"$path\" is emitted and named by the schema"
    else
        if ! grep -q "\\\\\"$leaf\\\\\":" "$EMITTER"; then
            ok 1 "\"$path\": schema names it but $EMITTER does not emit \"$leaf\""
        else
            ok 1 "\"$path\": emitted but the schema does not name it"
        fi
    fi
done

# R-10: zone.present == false must mean name/size/slab_pages_free are not
# rendered AT ALL, on every path that reaches "present":false, not just the
# zone == NULL one. The emitter has two such paths -- zone == NULL, and
# zone->shm.addr == NULL (a probe racing a reload, which the emitter's own
# comment above ngx_test_probe_json() calls legitimate) -- and both share the
# exact same ",\"zone\":{\"present\":false}}" literal tail, via two separate
# early returns. Before the fix, the shm.addr == NULL path fell through
# instead of returning, and rendered name/size/slab_pages_free with a
# fabricated slab_pages_free of 0 -- so a `delta zone.slab_pages_free == 0`
# rule racing a reload would subtract that fabricated zero and pass. Counting
# the literal's occurrences catches a regression to one early return (the
# old, buggy shape) without needing to parse the C control flow: two returns,
# two copies of the literal; collapse either one away and the count drops.
#
# The grep is anchored to `return ngx_slprintf(` immediately preceding the
# literal, not just the literal's text: a mutation that keeps both copies of
# the string but turns one `return ngx_slprintf(...)` into a fall-through
# `p = ngx_slprintf(...)` (the exact pre-fix shape) leaves the literal count
# at 2 while dropping the return count to 1.
# `|| true`: grep -c prints 0 and exits 1 when nothing matches, and under
# `set -euo pipefail` that status kills the suite at this assignment -- so the
# ONE case that matters most, both returns gone, would abort before ok() could
# report it. Same guard as the bad_ranges count below.
present_false_returns=$(grep -c 'return ngx_slprintf(p, last, ",\\"zone\\":{\\"present\\":false}}");' "$EMITTER" || true)

if [ "$present_false_returns" -eq 2 ]; then
    ok 0 "the emitter has two present:false early returns (zone==NULL and shm.addr==NULL)"
else
    ok 1 "the emitter has two present:false early returns (zone==NULL and shm.addr==NULL), saw $present_false_returns"
fi

# The reverse sweep: any member the emitter renders that the schema never
# mentions. Without this the schema decays into a passing subset -- every
# check above stays green while the document grows fields nobody wrote down.
#
# Module-hook members are rendered by the consuming module via zone_render, not
# by this file, so everything found here is legitimately ours to declare.
#
# Written as a function with two callers -- the real sweep below and the
# self-check further down -- so the self-check exercises THIS code rather than
# a copy of its regex. A duplicated pattern would keep passing when the sweep's
# own pattern is mutated, which is the tautology mutate.sh exists to expose.
#
# The needle is anchored to the whole key or to the tail component after a
# single dot. A bare suffix match is satisfied by any declared key ENDING in
# the leaf, so a stray "pages_free" would hide behind "slab_pages_free".
#
# KNOWN LIMIT, and the reason schema_test.c exists alongside this file: the
# sweep compares BARE LEAF NAMES and cannot see nesting, so a stray top-level
# "size" is indistinguishable from the declared "zone.size" here. What catches
# that is the closed-level check in schema_test.c, which walks the parsed
# document and rejects any member of the top level, connections or pool that
# the schema does not name.
undeclared_members() {
    local schema=$1 emitter=$2 out=""

    while IFS= read -r leaf; do
        [ -n "$leaf" ] || continue
        if ! grep -qE "\"([[:alnum:]_]+\.)?$leaf\"" "$schema"; then
            out="$out $leaf"
        fi
    done < <(grep -oE '\\"[[:alnum:]_]+\\":' "$emitter" | sed 's/\\"//g; s/://' | sort -u)

    printf '%s' "$out"
}

unknown=$(undeclared_members "$SCHEMA" "$EMITTER")

if [ -z "$unknown" ]; then
    ok 0 "the emitter renders no member the schema fails to name"
else
    ok 1 "the emitter renders members the schema does not name:$unknown"
fi

# A bracket range spelled with a letter range is a range over COLLATION order,
# not over ASCII. Under LC_ALL=tr_TR.UTF-8 it stops covering the letters this
# file needs, and matching "<range>*total" fails against a line that plainly
# contains connections.total -- so the reverse sweep above reported every
# member as undeclared. The locale-hostility CI job caught exactly that. POSIX
# classes are defined per-locale and do not have the problem.
#
# Only grep/sed lines are examined, and this check's own line is excluded:
# a guard whose pattern matches itself can never pass, which is a worse failure
# than the one it is meant to prevent.
bad_ranges=$(grep -nE '(grep|sed)[^|]*\[[^]]*[a-y]-[a-z]' "$(basename "$0")" \
    | grep -cv 'bad_ranges=' || true)

if [ "$bad_ranges" -eq 0 ]; then
    ok 0 "no locale-dependent letter range in this file"
else
    ok 1 "locale-dependent letter range in this file (use [[:alnum:]])"
fi

# The anchor, exercised through the sweep itself (undeclared_members above) on
# a synthetic schema/emitter pair. Nothing else in this file would notice the
# anchor being dropped, because no real emitter member currently collides that
# way -- so without this the mutation "reverse-sweep anchor removed" survives.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

printf '%s\n' '{ "fields": { "zone.slab_pages_free": {}, "fds": {} } }' \
    > "$tmpdir/schema.json"
printf '%s\n' 'ngx_slprintf(buf, last, "\"pages_free\":%ui,\"fds\":%i,");' \
    > "$tmpdir/emitter.c"

case " $(undeclared_members "$tmpdir/schema.json" "$tmpdir/emitter.c") " in
    *" pages_free "*)
        ok 0 "the sweep names a suffix-only collision (pages_free vs slab_pages_free)" ;;
    *)
        ok 1 "the sweep names a suffix-only collision (pages_free vs slab_pages_free)" ;;
esac

# ...and does not cry wolf on the legitimate shapes: a dotted path and a bare
# key. An anchor that rejected everything would pass the check above while
# breaking the sweep entirely.
printf '%s\n' '{ "fields": { "zone.size": {}, "fds": {} } }' > "$tmpdir/ok.json"
printf '%s\n' 'ngx_slprintf(buf, last, "\"size\":%uz,\"fds\":%i,");' \
    > "$tmpdir/ok.c"

if [ -z "$(undeclared_members "$tmpdir/ok.json" "$tmpdir/ok.c")" ]; then
    ok 0 "the sweep accepts a dotted path and a bare key"
else
    ok 1 "the sweep accepts a dotted path and a bare key"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    exit 1
fi

[ "$failures" -eq 0 ] || exit 1
