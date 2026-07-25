#!/usr/bin/env bash
#
# TAP self-test: prober_render_conf() substitutes every placeholder a scenario
# conf is allowed to use.
#
# This exists because @PREFIX@ was NOT substituted for the entire life of the
# scenario tree. Every scenario conf sets `pid`/`error_log` under @PREFIX@, so
# the literal string reached nginx, open() failed, and the config test bailed
# before a single request ran. Nothing in this repo executes the scenario tree
# -- it runs in consuming module repos -- so the breakage was invisible here.
#
# The guard is therefore two-sided: the placeholders the renderer claims to
# handle must actually be replaced (a rendered conf carrying a literal @NAME@
# is the bug), and every @NAME@ appearing in any checked-in scenario conf must
# be one the renderer knows. The second half is what turns a future scenario
# using @UPSTREAM@ into a red test instead of another silent bail.
set -euo pipefail

cd "$(dirname "$0")"

# Cleanup on every exit path, not just the happy one: a failing assertion or an
# unexpected `set -e` exit would otherwise leak the rendered prefix (mktemp -d)
# into TMPDIR on each run.
# The bail and metacharacter assertions render inside subshells, whose
# PROBER_PREFIX never reaches this shell -- so clearing only $PROBER_PREFIX
# leaks one mktemp -d per subshell render, every run. Everything this script
# creates lands under its own scratch dir, so one rm -rf covers every render
# whether the prefix propagated or not, and nothing outside it is touched.
export TMPDIR
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/render_conf_test.XXXXXX")"
SCRATCH="$TMPDIR"

cleanup() {
    [ -n "${SCRATCH:-}" ] && rm -rf "$SCRATCH"
    return 0
}
trap cleanup EXIT

PLANNED=17
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

diag() { printf '# %s\n' "$1"; }

# The placeholders prober_render_conf() is contracted to substitute. Keep in
# sync with the sed in lib.sh; the last test asserts the scenario tree uses
# nothing outside this set.
KNOWN="LOAD BUILD_OBJS PORT PREFIX PROBE PROBE_ZONE BACKEND_PORT"

# shellcheck source=lib.sh
. ./lib.sh

# Minimal stand-ins: the renderer only cares that the variables are set.
PROBER_LOAD="load_module /nowhere/mod.so;"
PROBER_RESOLVED_BUILD="/nowhere/.build/nginx-1.29.0"
PROBER_RESOLVED_PORT=18099
PROBER_PROBE="mod_probe probezone;"
PROBER_PROBE_ZONE="mod_ban_zone probezone:1m;"
PROBER_BACKEND_PORT=41337

TMPL="$(mktemp "${TMPDIR:-/tmp}/render_tmpl.XXXXXX")"
cat > "$TMPL" <<'EOF'
@LOAD@
pid @PREFIX@/nginx.pid;
error_log @PREFIX@/logs/error.log info;
http {
    @PROBE_ZONE@
    server {
        listen 127.0.0.1:@PORT@;
        set $backend 127.0.0.1:@BACKEND_PORT@;
        location /__probe { @PROBE@ }
    }
}
EOF

prober_render_conf "$TMPL"
RENDERED="$PROBER_PREFIX/conf/nginx.conf"

if [ -f "$RENDERED" ]; then ok 0 "the renderer writes a conf"
else ok 1 "the renderer writes a conf"; fi

# No placeholder survives rendering. This is the assertion that was missing.
if grep -q '@[A-Z_]\+@' "$RENDERED"; then
    diag "unsubstituted: $(grep -o '@[A-Z_]\+@' "$RENDERED" | sort -u | tr '\n' ' ')"
    ok 1 "no placeholder survives rendering"
else
    ok 0 "no placeholder survives rendering"
fi

# Every check goes through if/else, never a bare `grep` feeding `ok $?`: under
# `set -e` a non-matching grep exits the script BEFORE ok() runs, so the failure
# prints no "not ok" line and the tests after it never report. A TAP stream that
# stops mid-plan is the "rest passed" trap -- the harness would only work in the
# case where it is not needed.
if grep -q "^load_module /nowhere/mod.so;" "$RENDERED"; then
    ok 0 "@LOAD@ is substituted"
else
    ok 1 "@LOAD@ is substituted"
fi

if grep -q "listen 127.0.0.1:18099;" "$RENDERED"; then
    ok 0 "@PORT@ is substituted"
else
    ok 1 "@PORT@ is substituted"
fi

if grep -q "^pid $PROBER_PREFIX/nginx.pid;" "$RENDERED"; then
    ok 0 "@PREFIX@ is substituted in pid"
else
    ok 1 "@PREFIX@ is substituted in pid"
fi

if grep -q "^error_log $PROBER_PREFIX/logs/error.log info;" "$RENDERED"; then
    ok 0 "@PREFIX@ is substituted on every line it appears"
else
    ok 1 "@PREFIX@ is substituted on every line it appears"
fi

# The prefix must be the real per-run directory, not a literal or a relative
# path: nginx resolves a relative path against its compiled-in prefix, which
# would put the pidfile outside the sandbox.
case "$PROBER_PREFIX" in
    /*) ok 0 "the substituted prefix is absolute" ;;
    *)  diag "prefix is not absolute: $PROBER_PREFIX"
        ok 1 "the substituted prefix is absolute" ;;
esac

if grep -q "location /__probe { mod_probe probezone; }" "$RENDERED"; then
    ok 0 "@PROBE@ is substituted with the consumer's probe directive"
else
    ok 1 "@PROBE@ is substituted with the consumer's probe directive"
fi

if grep -q "^    mod_ban_zone probezone:1m;" "$RENDERED"; then
    ok 0 "@PROBE_ZONE@ is substituted at http level"
else
    ok 1 "@PROBE_ZONE@ is substituted at http level"
fi

# @BACKEND_PORT@ carries the port a fake upstream bound. A scenario conf points
# its proxy_pass/upstream at it, so an unsubstituted placeholder reaches nginx
# as a literal and kills the config test.
if grep -q "set \$backend 127.0.0.1:41337;" "$RENDERED"; then
    ok 0 "@BACKEND_PORT@ is substituted"
else
    ok 1 "@BACKEND_PORT@ is substituted"
fi

# Unlike @PROBE@, an unset PROBER_BACKEND_PORT must render EMPTY rather than
# bail: every scenario checked in today runs without a backend, so a
# bail-if-unset rule here would fail all of them. Asserted explicitly because
# the two placeholders sit on adjacent lines in the same sed and copying
# @PROBE@'s guard across is the obvious wrong move.
UNSET_OUT="$( ( unset PROBER_BACKEND_PORT
                prober_render_conf "$TMPL" >/dev/null 2>&1 \
                && cat "$PROBER_PREFIX/conf/nginx.conf" ) 2>/dev/null || true )"

# shellcheck disable=SC2016  # $backend is an nginx variable, not a shell one
case "$UNSET_OUT" in
    *'set $backend 127.0.0.1:;'*)
        ok 0 "an unset PROBER_BACKEND_PORT renders empty instead of bailing" ;;
    *)  diag "render bailed or left the placeholder: $(printf '%s' "$UNSET_OUT" \
             | grep 'backend' || echo '<no backend line rendered>')"
        ok 1 "an unset PROBER_BACKEND_PORT renders empty instead of bailing" ;;
esac

# sed's replacement side gives `&`, `\` and `#` special meaning. A consumer
# value carrying one must land verbatim: `&` unescaped expands to the matched
# text, rendering "@PROBE@" straight back into the conf, where it reaches nginx
# as a literal -- a silent failure indistinguishable from the bug this pair
# fixes. `#` closes the s### expression and kills the render outright.
# Guarded with `|| true` and a separate file check: with the escaping removed,
# `#` makes sed itself exit non-zero, and an unguarded call would take this
# script down under `set -e` -- printing no "not ok" and silently truncating
# the plan, which reads as "the rest passed". That is the exact trap this
# repo keeps re-learning, so the assertion has to survive its own mutant.
# The render runs in a subshell, so its PROBER_PREFIX never reaches this one;
# the subshell prints the rendered conf on stdout and the parent reads that.
# Reading $PROBER_PREFIX here instead would silently inspect the PREVIOUS
# render and pass on a stale file.
# Both placeholders are exercised in one render: @BACKEND_PORT@ is escaped
# through the same sed_repl as every other value, and asserting only @PROBE@
# would let a raw `-e "s#@BACKEND_PORT@#$PROBER_BACKEND_PORT#"` pass -- which
# renders the placeholder straight back into the conf the moment the value
# holds an `&`.
META_OUT="$( ( PROBER_PROBE='probe_dir a&b#c;' PROBER_BACKEND_PORT='9&9#9' \
               prober_render_conf "$TMPL" >/dev/null 2>&1 \
               && cat "$PROBER_PREFIX/conf/nginx.conf" ) 2>/dev/null || true )"

case "$META_OUT" in
    *'location /__probe { probe_dir a&b#c; }'*)
        ok 0 "sed metacharacters in a consumer value survive substitution" ;;
    *)  diag "render failed or mangled the value: $(printf '%s' "$META_OUT" \
             | grep '__probe' || echo '<no probe location rendered>')"
        ok 1 "sed metacharacters in a consumer value survive substitution" ;;
esac

# shellcheck disable=SC2016  # $backend is an nginx variable, not a shell one
case "$META_OUT" in
    *'set $backend 127.0.0.1:9&9#9;'*)
        ok 0 "sed metacharacters in the backend port survive substitution" ;;
    *)  diag "backend value mangled: $(printf '%s' "$META_OUT" \
             | grep 'backend' || echo '<no backend line rendered>')"
        ok 1 "sed metacharacters in the backend port survive substitution" ;;
esac

# Re-render with the good values so later assertions read the expected conf.
prober_render_conf "$TMPL"
RENDERED="$PROBER_PREFIX/conf/nginx.conf"

# A conf asking for @PROBE@ with no consumer value must BAIL, not render an
# empty location. This is the regression that blocked all 11 scenarios: an
# empty probe location falls through to `location /`, the prober parses that
# body as the probe document and reports "malformed number" -- a failure that
# points nowhere near the missing directive. Asserted in a subshell so the
# bail's `exit 1` cannot take this script down with it.
if ( PROBER_PROBE="" prober_render_conf "$TMPL" ) >/dev/null 2>&1; then
    ok 1 "an unset PROBER_PROBE bails instead of rendering an empty probe"
else
    ok 0 "an unset PROBER_PROBE bails instead of rendering an empty probe"
fi

# The bail must also say WHY. A bare non-zero exit would satisfy the check
# above while leaving the operator with the same silent misdirection.
# Captured to a variable rather than piped into grep: this script runs under
# `set -o pipefail`, and the bail's non-zero exit on the LEFT of a pipe fails
# the whole pipeline even when grep matches -- the assertion would read as red
# no matter what the message said.
BAIL_MSG="$( ( PROBER_PROBE="" prober_render_conf "$TMPL" ) 2>&1 || true )"
case "$BAIL_MSG" in
    *"Bail out!"*"PROBER_PROBE is unset"*)
        ok 0 "the bail names PROBER_PROBE" ;;
    *)  diag "bail message was: $BAIL_MSG"
        ok 1 "the bail names PROBER_PROBE" ;;
esac

# Every scenario conf must actually declare a probe location. The scenarios ran
# for the whole life of the tree without one; a new scenario copied from an old
# template would silently reintroduce exactly that.
# Matched as a `location /__probe` block, not as a bare @PROBE@ anywhere in the
# file: the placeholder could sit in a comment or under some other location and
# still satisfy a presence check while GET /__probe goes unserved -- which is
# the original bug wearing a passing test.
missing=""
for conf in scenarios/*/nginx.conf; do
    grep -Eq '^[[:space:]]*location[[:space:]]+/__probe[[:space:]]*\{[^}]*@PROBE@' \
        "$conf" || missing="$missing $(basename "$(dirname "$conf")")"
done

if [ -n "$missing" ]; then
    diag "scenario confs with no probe location:$missing"
    ok 1 "every scenario conf declares a probe location"
else
    ok 0 "every scenario conf declares a probe location"
fi

# Every placeholder used by a checked-in scenario conf must be known to the
# renderer. A new scenario reaching for @UPSTREAM@ fails here rather than
# bailing at nginx's config test with an open() error.
unknown=""
for used in $(grep -ho '@[A-Z_]\+@' scenarios/*/nginx.conf 2>/dev/null \
              | tr -d '@' | sort -u); do
    case " $KNOWN " in
        *" $used "*) ;;
        *) unknown="$unknown $used" ;;
    esac
done

if [ -n "$unknown" ]; then
    diag "scenario confs use placeholders the renderer does not substitute:$unknown"
    ok 1 "every scenario placeholder is known to the renderer"
else
    ok 0 "every scenario placeholder is known to the renderer"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
