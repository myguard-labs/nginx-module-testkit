#!/usr/bin/env bash
# shellcheck disable=SC2034
#
# The set of scenarios permitted to report SKIP, keyed by flavor:version.
#
# Sourced by test-scenarios.sh. A scenario that skips while absent from the
# allowlist fails the job. Without this, any number of skips counted `ok`, so a
# scenario that quietly stopped testing anything -- a renamed .so, a dropped
# build dependency -- stayed green forever. The allowlist turns "this skip is
# expected" into a claim someone had to write down.
#
# Two distinct reasons a scenario skips, and they age differently:
#
#   1. the module .so is not built for this flavor (every `consumer-*` plus
#      `reload-compressing`). Structural: the harness builds no consumer
#      modules, so these skip on every flavor and are expected to keep doing so.
#   2. the host cannot provide a capability (`syscall-allowlist` needs strace to
#      attach; the runner has ptrace restricted). Environmental: this one is
#      expected to START PASSING if the runner is ever granted ptrace, which is
#      why the "stopped skipping" report in test-scenarios.sh matters -- it is
#      the signal to drop the entry rather than let it mask a future regression.
#
# Adding an entry here is a coverage decision, not a formality: it says the
# scenario runs nowhere in CI. Prefer making the scenario runnable.

# Shared by every flavor -- these skip for reason (1) or (2) above regardless of
# which server is under test. Kept as one list because three identical
# per-flavor copies drift the moment one is edited and the others are not.
_PROBER_SKIPS_COMMON=(
    consumer-api-abuse
    consumer-cache-turbo
    consumer-coraza
    consumer-error-abuse
    consumer-shield
    consumer-skeleton
    consumer-strip-filter
    reload-compressing
    syscall-allowlist
)

case "${1:-}:${2:-}" in
    nginx:1.28.0 | nginx:1.29.0 | angie:1.12.0)
        # No flavor currently needs a delta. When one does, append to a copy of
        # the common list here rather than editing the common list itself.
        PROBER_EXPECTED_SKIPS=("${_PROBER_SKIPS_COMMON[@]}")
        ;;
    *)
        # Fail closed. An unrecognised flavor:version used to warn and hand back
        # an EMPTY allowlist, which reads as "nothing may skip" but in practice
        # meant the caller had a typo or the CI matrix moved -- and the gate was
        # silently disabled for exactly the run that needed it. A gate whose
        # unknown case is permissive is not a gate.
        echo "skip-allowlist: no allowlist for flavor/version '${1:-?}:${2:-?}'" >&2
        echo "skip-allowlist: add a case arm above, or fix the arguments" >&2
        exit 1
        ;;
esac
