#!/usr/bin/env bash
#
# Shared body of the scenarios/*/mutate-suite.sh scripts.
#
# Those scripts are the "suites" mutate.sh runs for the mutation rows whose
# claim lives in a scenario driver.sh rather than in a compiled test binary.
# All of them were byte-identical apart from the scenario path, which is why
# this exists: the port handling below is subtle enough that five hand-copied
# instances of it is five places to get it wrong.
#
# WHY THE PORT IS NOT SIMPLY BIND-0-AND-PRINT. Asking the kernel for an
# ephemeral port, closing the socket, and handing the number to run-scenario.sh
# leaves a window: this box runs concurrent CI, and another job can take the
# port between the close and nginx's bind. The lost race does not look like a
# race in the log -- it surfaces as `Bail out! server failed to start` with an
# `Address already in use` line, i.e. exactly like a genuinely broken scenario.
# Under mutate.sh it is worse than confusing: a suite that dies on a busy port
# exits nonzero, and every row pointed at it is then credited `caught` for a
# mutation nothing consulted. That is this repo's worst failure shape, and the
# same one MUT_KIND and baseline_ok already exist to prevent.
#
# WHY THE WINDOW IS NOT CLOSED BY HOLDING THE SOCKET. The obvious fix -- keep
# the allocating socket open until the server is up -- does not work: nginx
# then fails its OWN bind with EADDRINUSE. SO_REUSEADDR permits rebinding a
# socket in TIME_WAIT, not one that is actively bound, so any holder must
# release before nginx binds and the window reopens. Allocation cannot close
# it. So the race is made RECOVERABLE instead: lose the port, take a fresh one
# and try again, bounded.
#
# The retry is gated on the bind failure naming THIS port. A blanket
# retry-on-nonzero would convert a genuinely red suite into three runs of the
# same red suite and report the last one, which would hide real breakage --
# and hiding real breakage in a mutation harness is the one thing this
# directory may not do.
set -euo pipefail

# run_mutate_suite <scenario-dir> [flavor] [version]
#
# Runs one scenario the way a human runs it from prober/ (see each scenario's
# driver.sh header for the equivalent by-hand recipe). Output is streamed AND
# captured: a human watching a slow scenario needs the former, and the
# EADDRINUSE check needs the latter.
run_mutate_suite() {
    local scenario=$1
    local flavor=${2:-nginx}
    local version=${3:-1.29.0}

    local attempt port rc out
    out="$(mktemp)"
    # shellcheck disable=SC2064  # expand $out now: it must survive this scope.
    trap "rm -f '$out'" RETURN

    for attempt in 1 2 3; do
        port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"

        rc=0
        # `set +e` around the pipeline rather than `|| rc=$?`: under the callers'
        # `set -euo pipefail` a nonzero tee'd pipeline would abort the script
        # before the EADDRINUSE check below ever ran, which is the entire point
        # of running it.
        set +e
        PROBER_ROOT="$(pwd)/.." \
        PROBER_MODULE=ngx_http_test_ref_module.so \
        PROBER_DIRECTIVE=test_ref_probe \
        PROBER_PROBE="test_ref_probe;" \
        PROBER_PORT="$port" \
        ./run-scenario.sh "$scenario" "$flavor" "$version" 2>&1 | tee "$out"
        rc=${PIPESTATUS[0]}
        set -e

        if [ "$rc" -eq 0 ]; then
            return 0
        fi

        # Anchored on the port number: another job holding a DIFFERENT port is
        # not this run's problem, and a scenario that legitimately fails to bind
        # something of its own must not be retried into looking flaky.
        if grep -q "bind() to 127.0.0.1:$port failed (98" "$out"; then
            if [ "$attempt" -lt 3 ]; then
                echo "# mutate-suite: lost port $port to a concurrent job" \
                     "(attempt $attempt/3); retrying on a fresh port" >&2
            fi
            continue
        fi

        # A real failure. Report it on the first occurrence rather than burning
        # two more attempts to arrive at the same answer.
        return "$rc"
    done

    echo "# mutate-suite: gave up after 3 lost-port retries -- this box is" \
         "saturated, not broken" >&2
    return "$rc"
}
