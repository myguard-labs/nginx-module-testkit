#!/usr/bin/env bash
#
# TAP self-test: assert.c's -1-sentinel rejection list stays in step with
# ../src/ngx_test_probe.c's own -1-sentinel fields.
#
# path_is_proc_sentinel_field() in assert.c rejects `delta` over a handful of
# fields the emitter renders as -1 when the underlying kernel data was not
# readable -- so that a genuinely-failed reading (-1) does not cancel to a
# fabricated passing zero across a delta. assert.c cannot #include the emitter
# (opposite sides of the module/harness boundary, and ngx_test_probe.c needs
# real nginx headers to compile), so nothing at compile time stops the two
# from drifting apart -- which is exactly what happened: PR #165 added
# ngx_test_probe_timer_count() with the same -1-sentinel discipline as the fd
# counters, documented with the word "sentinel" in its own doc comment, and
# PR #130 was the last commit to touch assert.c's list. Nobody cross-checked
# them, and "timers" was missing until this test existed.
#
# Grep rather than a compile-and-run, same reasoning as schema_emitter_test.sh:
# the emitter needs a configured nginx/angie build to execute, but the fields
# that use the -1-sentinel discipline are identifiable as plain text -- every
# one of them documents it in its preceding comment block, either with the
# word "sentinel" outright or with the same "fabricated zero" phrase this
# repo's own review vocabulary uses for the failure the discipline prevents.
set -euo pipefail

cd "$(dirname "$0")"

EMITTER=../src/ngx_test_probe.c
ASSERT=assert.c

# The array body ONLY -- path_is_proc_sentinel_field()'s `fields[]` initializer,
# between its opening brace and the closing `};`. Grepping the whole file for
# `"$path",` is satisfied by prose that happens to contain the same quoted
# text followed by a comma: the doc comment above the array says `"fds", every
# "fds_by_kind.*" bucket…`, and a later comment says `(or, for "timers", an`
# -- both would keep this test green even with the field deleted from the
# actual array. Anchoring to the array body means a membership check only
# passes when the field is a live entry, not a stray mention.
sentinel_array=$(awk '
    /static const char \*const fields\[\] = \{/ { in_array = 1; next }
    in_array && /};/ { exit }
    in_array { print }
' "$ASSERT")

# Every emitter function whose preceding doc comment claims the -1-sentinel
# discipline, mapped to the schema path(s) it renders. This map is the part a
# human maintains; the check below is what catches a maintained-but-forgotten
# entry (a function gets the sentinel comment, but nobody added its field to
# assert.c) as well as the reverse (assert.c's list keeps a field that no
# longer exists).
#
#   <function name>:<space-separated schema paths it renders>
FUNCS="
ngx_test_probe_fd_count:fds
ngx_test_probe_fd_kinds:fds_by_kind.socket fds_by_kind.file fds_by_kind.anon fds_by_kind.other
ngx_test_probe_smaps:smaps.pss smaps.private_dirty
ngx_test_probe_timer_count:timers
"

PLANNED=0
while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    paths=${entry#*:}
    # shellcheck disable=SC2086
    set -- $paths
    PLANNED=$((PLANNED + 1 + $#))
done <<< "$FUNCS"

# Plus one row for the reverse sweep: every function in ngx_test_probe.c whose
# comment claims the sentinel discipline must be a key in FUNCS above, so a
# NEW sentinel-documented function that this test's map was never updated for
# is caught rather than silently passing.
PLANNED=$((PLANNED + 1))

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

while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    func=${entry%%:*}
    paths=${entry#*:}

    # The function's doc comment (the ~26 lines above its definition) must
    # actually claim the sentinel discipline -- otherwise this map is stale
    # and the drift it exists to catch is invisible.
    doc=$(awk -v fn="$func" '
        { buf[NR] = $0 }
        $0 ~ ("^" fn "\\(") {
            for (i = (NR > 26 ? NR - 26 : 1); i < NR; i++) print buf[i]
            found = 1
        }
        END { if (!found) exit 1 }
    ' "$EMITTER") || doc=""

    case $doc in
        *sentinel*|*"fabricated zero"*)
            ok 0 "$func's doc comment claims the -1-sentinel discipline" ;;
        *)
            ok 1 "$func's doc comment claims the -1-sentinel discipline" ;;
    esac

    for path in $paths; do
        if printf '%s\n' "$sentinel_array" | grep -q "\"$path\","; then
            ok 0 "assert.c's sentinel list names \"$path\" ($func)"
        else
            ok 1 "assert.c's sentinel list names \"$path\" ($func)"
        fi
    done
done <<< "$FUNCS"

# The reverse sweep: any function in the emitter whose comment claims the
# sentinel discipline but that FUNCS above never names is a maintenance gap in
# THIS test, and would let a future field repeat the "timers" miss silently.
known_funcs=$(printf '%s\n' "$FUNCS" | sed -n 's/^\([a-zA-Z0-9_]*\):.*/\1/p' | tr '\n' ' ')
unmapped=""

while IFS= read -r line; do
    lineno=${line%%:*}
    fn=$(sed -n "${lineno}p" "$EMITTER" | sed -n 's/^\([a-zA-Z0-9_]*\)(.*/\1/p')
    [ -n "$fn" ] || continue

    start=$((lineno - 26))
    [ "$start" -lt 1 ] && start=1
    # Comment lines only -- otherwise a PREVIOUS function's body falling
    # inside the window (e.g. a local variable literally named "sentinel",
    # as ngx_test_probe_timer_count's rbtree walk has) reads as this
    # function's doc comment claiming the discipline.
    # `|| true`: a function with no preceding comment lines is the normal case
    # for most of the emitter, and grep's exit 1 there would kill the suite
    # mid-plan under `set -euo pipefail` -- turning "this function claims no
    # discipline" into "the sweep stopped early", which is the failure this
    # whole file exists to prevent. An empty block falls through the case below.
    block=$(sed -n "${start},$((lineno - 1))p" "$EMITTER" | grep -E '^\s*(/?\*|//)' || true)

    case $block in
        *sentinel*|*"fabricated zero"*)
            case " $known_funcs " in
                *" $fn "*) : ;;
                *) unmapped="$unmapped $fn" ;;
            esac
            ;;
    esac
done < <(grep -nE '^[a-zA-Z0-9_]+\(' "$EMITTER")

if [ -z "$unmapped" ]; then
    ok 0 "no emitter function claims the sentinel discipline without a FUNCS entry"
else
    ok 1 "emitter functions claim the sentinel discipline with no FUNCS entry:$unmapped"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    exit 1
fi

[ "$failures" -eq 0 ] || exit 1
