#!/usr/bin/env bash
#
# Run the whole scenario suite under valgrind memcheck. The entry point a
# consumer's WEEKLY CI job calls -- see the README's "Running scenarios under
# valgrind (weekly)" section for the copy-paste job template. Consumers copy
# THAT template, not this script: this file is a fixed set of flags this repo
# has proven clean, not a tunable surface a consumer is meant to reach into.
#
#   prober/valgrind-scenarios.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what the consumer's build fetched
#
# WEEKLY, not nightly: memcheck is 20-50x slower than a native run, so the
# whole scenario tree under it is minutes, not seconds, and a shared
# self-hosted runner cannot absorb that on every push (or even every night)
# without starving the fast PR gate. A consumer's ci-deep already staggers its
# other weekly crons for the same reason -- see this repo's own analogous
# cadence discussion for SAN/fuzz jobs.
#
# WHY SCALE 40. PROBER_TIMEOUT_SCALE stretches the three timing budgets the
# engine owns (prober's own -t read timeout, the two boot readiness loops, and
# prober.c's DELTA_SETTLE retry count -- see lib.sh's prober_resolve comment).
# 40 is comfortably inside the 20-50x range memcheck instrumentation costs a
# syscall-heavy workload, chosen generously rather than tightly: a scenario
# that times out for HARNESS reasons under valgrind reads identically to one
# that timed out because the module hung, and the whole point of this leg is
# to stop conflating the two. A consumer on a fast dedicated runner may lower
# it; PROBER_TIMEOUT_SCALE stays overridable from the environment for exactly
# that case.
#
# WHY BELT (log-grep) AND SUSPENDERS (--error-exitcode). memcheck's default
# behaviour is to report everything it finds and still exit 0 -- the finding
# does not fail the PROCESS unless something says it should.
# --error-exitcode=99 is that something, but it only reaches the process
# valgrind directly launched; prober_scrape_valgrind (lib.sh) additionally
# greps every $PROBER_PREFIX/logs/valgrind.* log text regardless of what any
# exit code said, which is what makes the combination non-vacuous rather than
# an assertion that happens to agree with itself. valgrind_scrape_test.sh
# proves this pairing is load-bearing, not decorative -- it demonstrates the
# SAME planted leak passing the exit-code check with --error-exitcode and
# silently exiting 0 without it, then proves the log-grep catches the second
# case too.
#
# --gen-suppressions=all is deliberate even though nothing here parses its
# output: it makes an unsuppressed nginx-core false positive appear in the
# log as a ready-to-paste stanza (valgrind emits it inline), so extending
# valgrind.supp after a real run is a copy-paste, not a re-derivation.
#
# WHY --track-origins=yes AND --track-fds=all. The bare adapter caught only
# the "definitely lost" leak class. The two additions widen it to the two
# other finding classes a module owns cleanup for:
#   --track-origins=yes -- an uninitialised-value read (module reads a struct
#     field it forgot to zero) reports WHERE the uninitialised value came
#     from, not just that one was used. Without it the report is "Conditional
#     jump depends on uninitialised value" with no origin, which is a finding
#     you cannot action; with it the origin line names the allocation. It
#     roughly doubles memcheck's shadow-memory cost, already inside the SCALE
#     40 budget above.
#   --track-fds=all -- a leaked file descriptor (module opens a socket/temp
#     file and never closes it on the error path) is reported at exit with its
#     open() call site. A leaked FD is a real resource exhaustion under load
#     and is otherwise invisible to leak-check (the memory backing it is not
#     lost). Whether a leaked fd bumps the error count (and so trips
#     --error-exitcode=99) is version-dependent -- some fleet valgrinds report
#     it purely informationally and exit 0 -- so the portable guarantee is the
#     LOG LINE naming the fd, which is what a weekly triage reads.
#     valgrind_scrape_test.sh proves each flag load-bearing with a mutation
#     pair: the uninitialised read exits 99 AND names its origin; the leaked fd
#     is named in the log with --track-fds and absent without it.
#
# NOT --trace-children: nginx workers are fork()-without-exec, so each worker
# inherits the master's already-valgrinded image (see lib.sh prober_boot). A
# --trace-children here would only matter for an exec()'d child this harness
# never spawns; adding it costs startup with no coverage gain.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v valgrind >/dev/null 2>&1; then
    echo "1..0 # SKIP no valgrind on this box"
    exit 0
fi

# NO --log-file here: lib.sh's prober_boot appends it once $PROBER_PREFIX is
# known (only known at boot, not here), so a caller-supplied PROBER_VALGRIND
# must never include it -- see prober_boot's PROBER_VALGRIND comment.
export PROBER_VALGRIND="valgrind --error-exitcode=99 --leak-check=full \
--errors-for-leak-kinds=definite --track-origins=yes --track-fds=all \
--gen-suppressions=all --suppressions=$PWD/valgrind.supp"

export PROBER_TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-40}"

exec ./test-scenarios.sh "${1:-nginx}" "${2:-1.31.3}"
