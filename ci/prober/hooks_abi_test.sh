#!/usr/bin/env bash
#
# TAP self-test: ngx_test_probe_hooks_t stays FROZEN.
#
# Ten consumer modules initialise that struct POSITIONALLY -- shield's
# src/ngx_shield_probe_hooks.c is `{ zone_render, fault_set }` with no member
# names. Appending a member to it is therefore not the harmless zero-init it
# looks like: -Wextra turns on -Wmissing-field-initializers, this repo's own CI
# pairs -Wextra with -Werror, and a consumer that does the same gets a BUILD
# FAILURE in its own repo, from a change made in this one. Those repos are not
# editable from here, so the breakage would land as ten red builds with no
# local test having gone red first.
#
# This reproduces that exact shape locally: a positional initializer compiled
# against the real header at the strictest warning level, with -Werror. It goes
# red in THIS repo the moment a member is appended, which is the point -- new
# hooks belong in ngx_test_probe_module_hooks_t, which has its own registrar
# and is additive by construction.
#
# Verified to actually discriminate on 2026-08-25: appending a member makes
# this file's first case fail with
#   error: missing initializer for field 'module_render' [-Werror=missing-field-initializers]
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=3
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

CC=${CC:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Shield's hook signatures and its positional initializer, transcribed from
# nginx-http-shield-module/src/ngx_shield_probe_hooks.c:59,132,160-162.
cat > "$tmp/consumer.c" <<'EOF'
#include "ngx_test_probe.h"

static u_char *
consumer_zone_render(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{ (void) last; (void) zone; return buf; }

static ngx_int_t
consumer_fault_set(ngx_shm_zone_t *zone, ngx_test_probe_fault_e fault,
    ngx_int_t nth)
{ (void) zone; (void) fault; (void) nth; return NGX_OK; }

static const ngx_test_probe_hooks_t  consumer_hooks = {
    consumer_zone_render,
    consumer_fault_set
};

void consumer_register(void);
void consumer_register(void) { ngx_test_probe_register(&consumer_hooks); }
EOF

WARN="-Wall -Wextra -Wpedantic -Wmissing-field-initializers -Werror"

# shellcheck disable=SC2086
if $CC -c -std=c99 $WARN -DNGX_TEST_HARNESS -I ../../t -I ../../src \
    -o "$tmp/consumer.o" "$tmp/consumer.c" 2>"$tmp/err"; then
    ok 0 "a positional ngx_test_probe_hooks_t initializer still builds at -Werror"
else
    ok 1 "a positional ngx_test_probe_hooks_t initializer still builds at -Werror"
    sed 's/^/# /' "$tmp/err"
fi

# The struct must also not have grown: a member added and then given a default
# elsewhere would still change sizeof and break any consumer that memcpy's or
# stores the struct by value.
cat > "$tmp/size.c" <<'EOF'
#include "ngx_test_probe.h"
/* Two function pointers, and only two. A negative array size is a compile
 * error naming this line, which is the whole diagnostic. */
typedef int hooks_t_is_exactly_two_function_pointers[
    (sizeof(ngx_test_probe_hooks_t) == 2 * sizeof(void (*)(void))) ? 1 : -1];
EOF

# shellcheck disable=SC2086
if $CC -c -std=c99 $WARN -DNGX_TEST_HARNESS -I ../../t -I ../../src \
    -o "$tmp/size.o" "$tmp/size.c" 2>"$tmp/err2"; then
    ok 0 "ngx_test_probe_hooks_t is still exactly two function pointers"
else
    ok 1 "ngx_test_probe_hooks_t is still exactly two function pointers"
    sed 's/^/# /' "$tmp/err2"
fi

# And the escape hatch exists: the zone-independent hooks have their own struct
# and registrar, so there is somewhere for a new hook to go. Without this the
# two checks above would just be a wall.
if grep -q 'ngx_test_probe_register_module' ../../src/ngx_test_probe.h \
    && grep -q 'ngx_test_probe_module_hooks_t' ../../src/ngx_test_probe.h; then
    ok 0 "ngx_test_probe_module_hooks_t exists as the place new hooks go"
else
    ok 1 "ngx_test_probe_module_hooks_t exists as the place new hooks go"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

exit $((failures > 0))
