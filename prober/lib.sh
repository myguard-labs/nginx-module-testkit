#!/usr/bin/env bash
#
# Shared engine for run.sh and run-scenario.sh: everything involved in booting
# a probe-enabled server, gating the run on things that would otherwise produce
# a green run that proves nothing, and tearing the server down again.
#
# This file is sourced, not executed. Functions communicate through the
# PROBER_* variables they set (documented per function) rather than through
# stdout, so callers can compose them without command substitution eating the
# TAP stream.
#
# Callers must run under `set -euo pipefail`; this file assumes it and does not
# re-assert it, because re-running `set -u` here would mask a caller that
# forgot it only until the first unset variable inside a function.

# prober_resolve FLAVOR VERSION
#
# Sets: PROBER_FLAVOR PROBER_VERSION PROBER_RESOLVED_ROOT PROBER_RESOLVED_BUILD
#       PROBER_SERVER_BIN PROBER_MODULE_PATH PROBER_RESOLVED_PORT
#
# Everything specific to the consuming module arrives through the environment,
# so these scripts are shared verbatim rather than forked per repo.
# prober_normalize_timeout_scale
#
# Validate PROBER_TIMEOUT_SCALE and canonicalize it to a base-10 integer in the
# 1..1000 range the C side (prober.c) also enforces. Called TWICE: once from
# prober_resolve, and again from run-scenario.sh AFTER the scenario's `env` file
# is sourced -- that file can set PROBER_TIMEOUT_SCALE to an unvalidated value
# after the first check, so the second call is what makes a scenario override
# safe rather than a way past the gate.
#
# Canonicalization is not cosmetic: every downstream use is a bash arithmetic
# expansion ($((50 * PROBER_TIMEOUT_SCALE))), which reads a leading-zero value
# as OCTAL -- "010" would silently become 8x the intended budget, and "008"
# would abort the expansion outright ("value too great for base") -- while
# prober.c's strtol(env, NULL, 10) reads the same string as base 10. Forcing
# base 10 with 10#... here makes the shell agree with the C, and clamps the
# shared 1..1000 contract in one place. A bad value bails loudly rather than
# defaulting to "no scaling", which would look identical to a healthy run right
# up until the valgrind timeout hits.
prober_normalize_timeout_scale() {
    local raw="${PROBER_TIMEOUT_SCALE:-1}"

    case "$raw" in
        ''|*[!0-9]*)
            echo "Bail out! PROBER_TIMEOUT_SCALE must be a positive integer"
            exit 1 ;;
    esac

    # 10#... forces base 10, so a leading-zero override cannot become octal and
    # "008" cannot abort the expansion; raw is already all-digits by the case above.
    raw=$((10#$raw))

    if [ "$raw" -lt 1 ] || [ "$raw" -gt 1000 ]; then
        echo "Bail out! PROBER_TIMEOUT_SCALE must be in 1..1000 (got $raw)"
        exit 1
    fi

    PROBER_TIMEOUT_SCALE="$raw"
}

prober_resolve() {
    PROBER_FLAVOR="${1:-nginx}"
    PROBER_VERSION="${2:-1.31.3}"
    PROBER_RESOLVED_PORT="${PROBER_PORT:-18099}"

    # PROBER_TIMEOUT_SCALE stretches every timing budget the engine owns: the
    # prober's own -t read timeout (run.sh/run-scenario.sh), the two boot
    # readiness loops just below, and prober.c's DELTA_SETTLE retry count.
    # Memcheck is 20-50x slower than a native run, so the weekly valgrind
    # consumer job sets this to ~40; missing ANY of those three spots means the
    # unscaled one times out under valgrind for harness reasons having nothing
    # to do with the module under test, and that leg gets disabled inside a
    # week -- which is the whole point of this knob existing at all.
    prober_normalize_timeout_scale

    PROBER_RESOLVED_ROOT="${PROBER_ROOT:-$(cd ../.. && pwd)}"
    PROBER_RESOLVED_BUILD="${PROBER_BUILD:-$PROBER_RESOLVED_ROOT/.build/${PROBER_FLAVOR}-${PROBER_VERSION}}"

    # angie names its server binary objs/angie, nginx names it objs/nginx.
    PROBER_SERVER_BIN="$PROBER_RESOLVED_BUILD/objs/nginx"
    [ "$PROBER_FLAVOR" = "angie" ] && PROBER_SERVER_BIN="$PROBER_RESOLVED_BUILD/objs/angie"

    if [ -z "${PROBER_MODULE:-}" ] || [ -z "${PROBER_DIRECTIVE:-}" ]; then
        echo "Bail out! PROBER_MODULE and PROBER_DIRECTIVE must be set --" \
             "see the header of prober/run.sh"
        exit 1
    fi

    PROBER_MODULE_PATH="$PROBER_RESOLVED_BUILD/objs/$PROBER_MODULE"

    if [ ! -x "$PROBER_SERVER_BIN" ]; then
        echo "Bail out! no server binary at $PROBER_SERVER_BIN --" \
             "build $PROBER_FLAVOR $PROBER_VERSION with the test harness enabled first"
        exit 1
    fi
}

# prober_stale_so_check
#
# Bails when $PROBER_MODULE_PATH is older than any probe source under src/.
#
# Reads: PROBER_MODULE_PATH, PROBER_RESOLVED_ROOT, PROBER_ALLOW_STALE_SO.
#
# The comparison is mtime against the NEWEST src/ngx_test_probe*.{c,h}, not
# against one named file: the two s108/s140 incidents were a field added in
# ngx_test_probe.c and a pair added across the .c and .h, so pinning a single
# filename would have caught one and missed the other.
#
# PROBER_ALLOW_STALE_SO=1 lifts exactly this bail, for the deliberate case of
# driving a known-old artifact on purpose. Scoped to the literal value 1 -- one
# named gate, never a blanket off-switch, so a stray =0 cannot disable it.
#
# UNLIKE PROBER_ALLOW_LOG and PROBER_ALLOW_MULTIWORKER, this one must come from
# the CALLER'S environment, not a scenario `env` file. Those two are read by
# prober_check_conf and prober_scrape_log, which run AFTER run-scenario.sh
# sources the scenario env; this runs from prober_detect_load, which is several
# steps BEFORE it -- the load decision has to be made before anything is
# rendered or booted. A scenario cannot opt itself in, and should not want to:
# a stale artifact is a property of the developer's build tree, not of a
# scenario's requirements.
#
# Missing src/ is NOT a bail: a CONSUMER repo vendors this harness and builds
# its own module, so there is no probe source to compare against and nothing
# stale to detect. Silence there is correct, not a hole.
prober_stale_so_check() {
    if [ "${PROBER_ALLOW_STALE_SO:-0}" = "1" ]; then
        return 0
    fi

    local src_dir stale_src
    src_dir="$PROBER_RESOLVED_ROOT/src"
    [ -d "$src_dir" ] || return 0

    # ANY probe source newer than the artifact -- this is an existence test, not
    # a max-search. `-newer` already encodes the whole question ("is the .so out
    # of date?"), so the first hit settles it and the bail is identical whichever
    # match wins the traversal. Deliberately NOT sorted by mtime: naming the
    # single newest source would cost a full traversal plus a sort to change one
    # path in a diagnostic, and the multi-write pipeline that needs is the exact
    # SIGPIPE shape the -quit note below exists to avoid. The message says "is
    # older than <this source>", which is true of whichever one is reported.
    #
    # -maxdepth 1: src/ is flat, and a consumer tree underneath it must not vote
    # on this harness's artifact.
    #
    # `-print -quit`, NOT `-print | head -1`: every caller runs `set -euo
    # pipefail`, and `head -1` closes the pipe as soon as it has its line, so a
    # find with more matches still to write dies of SIGPIPE (141). pipefail
    # propagates that and `set -e` aborts the scenario, so the bail this
    # function exists to print never appears -- a guard that kills the run
    # silently instead of naming the stale artifact. -quit makes find stop after
    # the first hit itself, so nothing is ever written into a closed pipe.
    stale_src="$(find "$src_dir" -maxdepth 1 -name 'ngx_test_probe*.[ch]' \
              -newer "$PROBER_MODULE_PATH" -print -quit 2>/dev/null)"

    if [ -n "$stale_src" ]; then
        echo "Bail out! stale module artifact --" \
             "$PROBER_MODULE_PATH is older than $stale_src;" \
             "rebuild the reference module for $PROBER_FLAVOR $PROBER_VERSION" \
             "(a stale .so reports the absent-field sentinel and fails an oracle" \
             "closed, which reads as a flavor-specific bug in your diff)." \
             "Set PROBER_ALLOW_STALE_SO=1 to drive it anyway."
        exit 1
    fi
}

# prober_detect_load
#
# Sets: PROBER_LOAD -- the load_module line for the conf template, or empty.
#
# debug/module modes build a dynamic .so and need load_module; asan and
# coverage modes use --add-module and link the module into the binary, where a
# load_module line fails with "module is already loaded".
#
# Decide by looking inside the BINARY, not by whether a .so exists: switching
# build modes leaves the previous mode's .so behind in objs/, so a file-exists
# test picks the stale artifact and emits load_module for a static build.
#
# A .so that is present and carries the directive can still be STALE -- built
# before a probe field the scenario now asserts. That failure is silent and
# expensive: the probe emits the absent-field sentinel, the oracle fails closed,
# and the red lands on whichever flavor happens to hold the older artifact, so
# it reads as a flavor-specific bug in the diff under test. It cost a full
# session twice (s108: multi-worker on a .so predating `ppid`; s140:
# deploy-canary on an angie .so predating `smaps`/`fds_by_kind`), and CI never
# reproduces it -- CI rebuilds every flavor from source on every run.
# prober_stale_so_check closes that: only the DYNAMIC path needs it, because the
# static branch above reads the freshly-linked binary and never consults objs/.
prober_detect_load() {
    if grep -qa "$PROBER_DIRECTIVE" "$PROBER_SERVER_BIN"; then
        PROBER_LOAD=""                            # statically linked (asan/coverage)
    elif [ -f "$PROBER_MODULE_PATH" ] && grep -qa "$PROBER_DIRECTIVE" "$PROBER_MODULE_PATH"; then
        prober_stale_so_check
        PROBER_LOAD="load_module $PROBER_MODULE_PATH;"   # dynamic (debug/module)
    else
        echo "Bail out! neither $PROBER_SERVER_BIN nor $PROBER_MODULE_PATH carries" \
             "$PROBER_DIRECTIVE -- rebuild with the test harness enabled"
        exit 1
    fi
}

# prober_heap_env
#
# Exports ASAN_OPTIONS always, MALLOC_PERTURB_/MALLOC_CHECK_ on unsanitized
# builds.
#
# nginx never frees its configuration pool, so LeakSanitizer reports the whole
# config parse as leaked on `nginx -t` and on every clean shutdown -- against an
# ASan build that turns the config test into a "Bail out!" before a single case
# runs. Everything else ASan catches (use-after-free, overflow) stays on.
#
# detect_odr_violation=0 is disabled for the same reason: a dynamic module and
# the nginx binary each carry their own generated *_modules.c defining the
# global `ngx_module_names`. dlopen registers both with ASan, which reports an
# ODR violation and aborts `nginx -t` before any case runs. This is inherent to
# building nginx modules dynamically under ASan, not a module defect; the two
# arrays are distinct objects and never aliased at runtime.
#
# MALLOC_PERTURB_/MALLOC_CHECK_ are glibc's own cheap heap checks, on every run
# that is NOT sanitized. They catch a class the suite otherwise cannot see:
# uninitialised reads and use-after-free get a garbage value instead of the
# zeroes a quiet heap usually hands back. Sanitizer builds are excluded rather
# than merely redundant: ASan replaces the allocator, ignores these variables,
# and MALLOC_CHECK_'s abort path can fire inside ASan's own bookkeeping.
# Decided by looking for the ASan runtime in the binary, not by the
# static/dynamic distinction -- the coverage build is also statically linked
# but is not sanitized, and would lose the check.
# Also exports PROBER_SANITIZED (1/0) so a driver can branch on it without
# repeating the detection. Scenarios need it for a different reason than the
# heap variables do: a sanitizer runtime keeps freed memory in quarantine and
# carries its own shadow bookkeeping, so any assertion about the PROCESS's
# resident size measures the sanitizer rather than the server (measured: a
# reload series that grows the master by 21 pages unsanitized grows it by 402
# under ASan). Such an assertion must be skipped there, visibly -- widening its
# band until the sanitizer fits would leave a gate that can no longer fail.
prober_heap_env() {
    export ASAN_OPTIONS="detect_leaks=0:detect_odr_violation=0:halt_on_error=1:abort_on_error=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

    if grep -qa '__asan_\|__ubsan_' "$PROBER_SERVER_BIN"; then
        export PROBER_SANITIZED=1
    else
        export PROBER_SANITIZED=0
    fi

    if [ "$PROBER_SANITIZED" -eq 0 ]; then
        # 165 is arbitrary but deliberately odd and non-zero: as a pointer it
        # is unmapped, as a length it is implausible, as a byte it is not '\0'.
        export MALLOC_PERTURB_=165
        export MALLOC_CHECK_=3
    fi
}

# prober_gates
#
# The prober and json_test binaries are gitignored build products and this
# engine does NOT build them. An edit to prober.c that was never compiled would
# otherwise be "verified" by the binary from before the edit: a green run that
# proves nothing about the change in hand. Same failure mode as a dead harness.
#
# Then check the oracle before trusting anything it says: every rule assertion
# is evaluated against the JSON reader, so if that is broken the rules can all
# pass while proving nothing. Emitted as a bail-out rather than as extra TAP
# lines, so the plan the prober prints stays the plan the run reports.
#
# Expects to be called with CWD = the prober/ directory.
prober_gates() {
    local artifact stale json_out

    # fakesrv is checked alongside the prober because a scenario's verdict
    # depends on the fake upstream behaving as its script says. A stale one
    # would be trusted forever: the faults a rebuilt script asks for would
    # silently not happen, and the scenario would pass by testing the happy
    # path under a name claiming otherwise.
    for artifact in ./prober ./json_test ./fakesrv; do
        if [ -x "$artifact" ]; then
            stale="$(find ./*.c ./*.h -newer "$artifact" 2>/dev/null || true)"

            if [ -n "$stale" ]; then
                echo "Bail out! $artifact is older than its sources --" \
                     "run prober/build.sh:"
                printf '%s\n' "$stale" | sed 's/^/# /'
                exit 1
            fi
        fi
    done

    if [ -x ./json_test ]; then
        if ! json_out="$(./json_test 2>&1)"; then
            echo "Bail out! prober JSON self-test failed:"
            printf '%s\n' "$json_out" | sed 's/^/# /'
            exit 1
        fi
    else
        echo "Bail out! no json_test binary -- run prober/build.sh first"
        exit 1
    fi
}

# prober_make_prefix
#
# Sets: PROBER_PREFIX -- fresh server prefix (mktemp), unless one already
# exists, in which case this is a no-op and the existing prefix is kept.
#
# Split out of prober_render_conf because the fake upstream needs the prefix
# BEFORE the conf is rendered: prober_backend_start writes its portfile,
# journal and errfile there, and the conf cannot be rendered until the backend
# has published the port that @BACKEND_PORT@ substitutes. Callers with no
# backend need not call this at all -- prober_render_conf still creates the
# prefix itself, so run.sh is unaffected.
#
# Reusing an existing prefix rather than replacing it is what makes the two
# call sites compose: a second call would otherwise strand the first prefix,
# leaking it past a cleanup that only knows the newer path.
prober_make_prefix() {
    [ -z "${PROBER_PREFIX:-}" ] || return 0

    PROBER_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober.XXXXXX")"
    mkdir -p "$PROBER_PREFIX/logs" "$PROBER_PREFIX/conf"

    # Ownership is recorded at creation, and ONLY here. prober_cleanup does an
    # `rm -rf` on the prefix, and the value can arrive from outside the
    # harness: run-scenario.sh exports PROBER_PREFIX to driver.sh, and a
    # scenario's `env` file is sourced into the same shell, so either can set
    # it to a directory the harness did not create and does not own. Deleting
    # that would be the harness destroying a caller's data on a normal exit.
    # A prefix we did not mktemp is used but never removed.
    PROBER_PREFIX_OWNED=1
}

# prober_render_conf TEMPLATE
#
# Sets: PROBER_PREFIX -- fresh server prefix (mktemp), conf rendered into it.
# The caller owns cleanup of $PROBER_PREFIX (run.sh and run-scenario.sh both
# install traps; a library installing its own trap would silently overwrite
# the caller's).
prober_render_conf() {
    local template="$1"

    if [ ! -f "$template" ]; then
        echo "Bail out! no conf template at $template -- a scenario needs its" \
             "own nginx.conf or a PROBER_CONF default"
        exit 1
    fi

    prober_make_prefix

    # @PREFIX@ resolves to the per-run temp prefix created just above. A
    # scenario conf needs it for pid/error_log/access_log paths: nginx resolves
    # a relative path against its compiled-in prefix, not against the rendered
    # conf, so an unsubstituted or relative path lands outside the sandbox --
    # or, as with a literal "@PREFIX@", fails open() and kills the config test.
    #
    # @PROBE@ and @PROBE_ZONE@ are the consumer's, because the probe directive
    # is module-specific: shield's is `shield_probe probezone;` and it needs a
    # `shield_ban_zone probezone:1m;` at http level to name that zone. A generic
    # scenario tree cannot hardcode either, so the consumer supplies them and
    # the scenarios only say WHERE they go. Empty is legitimate -- a module
    # whose probe needs no zone leaves PROBER_PROBE_ZONE unset.
    #
    # @BUILD_OBJS@ resolves to the build tree's objs/ dir -- the directory that
    # holds the probe .so (@LOAD@ already load_modules that one). A CONSUMER
    # scenario that must load a SECOND, module-under-test .so (e.g. an http-zstd
    # filter alongside the ref probe) references it here to write its own
    # load_module line, because the probe and the auxiliary module are built
    # into the same objs/ dir but only the probe has a dedicated macro. It is
    # empty-safe by construction: PROBER_RESOLVED_BUILD is always set by
    # prober_resolve before any conf is rendered. Scenarios that load no second
    # module simply never mention it.
    #
    # @BACKEND_PORT@ is the port a fake upstream bound, published by
    # prober_backend_start. It renders EMPTY when PROBER_BACKEND_PORT is unset,
    # and that is deliberate: a scenario with no backend is the normal case --
    # every scenario checked in today has none. Do NOT give this placeholder
    # @PROBE@'s bail-if-unset rule. @PROBE@ bails because an empty probe
    # location falls through to `location /` and the prober misreads that
    # handler's body as the probe document; an empty upstream port has no
    # equivalent silent-misdirection path, it simply fails nginx's config test
    # where the operator can read it.
    #
    # A conf that asks for @PROBE@ while the consumer supplied nothing must
    # bail, not render empty: an empty probe location falls through to
    # `location /`, the prober parses that handler's body as the probe document
    # and reports "malformed number". That misdirection is exactly the bug this
    # placeholder pair exists to end, so it fails loudly at render instead.
    if grep -q '@PROBE@' "$template" && [ -z "${PROBER_PROBE:-}" ]; then
        echo "Bail out! $template uses @PROBE@ but PROBER_PROBE is unset --" \
             "the consumer must supply its probe directive (e.g." \
             "PROBER_PROBE='shield_probe probezone;')"
        exit 1
    fi

    # Every value is escaped before it reaches sed's replacement side, where
    # `&` means "the whole matched text", `\` starts an escape and `#` closes
    # the s### expression. Unescaped, a probe directive containing `&` renders
    # the placeholder back into the output -- @PROBE@ would reach nginx as a
    # literal, which is the silent-failure mode this placeholder pair exists to
    # end. `#` is worse only in being loud. These are consumer-supplied values,
    # so the harness cannot assume they are tame.
    sed_repl() { printf '%s' "$1" | sed -e 's#[\\&/]#\\&#g' -e 's#\##\\\##g'; }

    sed -e "s#@LOAD@#$(sed_repl "$PROBER_LOAD")#" \
        -e "s#@BUILD_OBJS@#$(sed_repl "${PROBER_RESOLVED_BUILD:-}/objs")#" \
        -e "s#@PORT@#$(sed_repl "$PROBER_RESOLVED_PORT")#" \
        -e "s#@PREFIX@#$(sed_repl "$PROBER_PREFIX")#" \
        -e "s#@PROBE@#$(sed_repl "${PROBER_PROBE:-}")#" \
        -e "s#@PROBE_ZONE@#$(sed_repl "${PROBER_PROBE_ZONE:-}")#" \
        -e "s#@BACKEND_PORT@#$(sed_repl "${PROBER_BACKEND_PORT:-}")#" \
        "$template" > "$PROBER_PREFIX/conf/nginx.conf"
}

# prober_check_conf
#
# Two rendered-conf gates, each guarding an inference the engine relies on.
#
# The pid oracle compares the worker pid across each case and calls a change a
# crash. That inference only holds with ONE worker: with several, consecutive
# probe requests are answered by different live workers and every case fails on
# a server that is perfectly healthy. The conf comes from the consumer, so this
# cannot be enforced by shipping a conf -- check the rendered file instead, and
# bail rather than emit a wall of false failures. Trailing space is stripped
# separately: "worker_processes 1 ;" is valid nginx, and an untrimmed "1 "
# would not equal "1" and would bail a healthy conf.
#
# `daemon off;` is required because the engine backgrounds the binary itself
# and keeps $! as the master pid for teardown and for scenario drivers that
# send it signals. With daemon mode on, $! is a launcher that exits
# immediately: teardown kills nothing, the orphaned server keeps the port, and
# every later scenario fails on bind -- a confusing distance from the cause.
#
# PROBER_DAEMON_MODE=on inverts that one gate for the single scenario that
# CANNOT run under daemon off: a USR2 binary upgrade. nginx drops the
# NGX_CHANGEBIN signal when getppid()==ngx_parent (ngx_process.c), which always
# holds for a foreground master whose parent is prober_boot's `&` launcher, so
# the upgrade is silently ignored under daemon off. Opting in requires the
# conf to say `daemon on;` AND to write its pidfile to $PROBER_PREFIX/nginx.pid,
# because prober_boot then reads the master pid from that file instead of $!
# (the launcher exits and the master reparents away). Set it in the scenario's
# `env`, never globally: a daemonized server tracked by a stale $! is the
# orphaned-port failure this gate otherwise stops, and the scenario carries the
# pidfile-teardown contract in exchange.
prober_check_conf() {
    local workers

    workers="$(sed -n 's/^[[:space:]]*worker_processes[[:space:]]\+\([^;]*\);.*/\1/p' \
        "$PROBER_PREFIX/conf/nginx.conf" | tail -n 1 | tr -d '[:space:]')"

    # PROBER_ALLOW_MULTIWORKER lets a scenario opt into worker_processes > 1.
    # It exists for exactly one shape: a scenario whose POINT is behaviour across
    # the worker set (multi-worker), where every case carries `pid_may_change` so
    # the oracle asserts "same master" (ppid) instead of "same worker" (pid) --
    # see eval_pid_stable / assert.h. Set it in the scenario's `env` file, never
    # globally: a scenario that leaves the default strict pid oracle on ITS cases
    # and also has several workers is the wall-of-false-failures this gate exists
    # to stop, and the opt-in must be a deliberate per-scenario act, not a run
    # default. The gate cannot itself verify every case uses pid_may_change (it
    # runs before any rule is parsed), so this is a contract the scenario keeps,
    # documented at its `env`; the burst of pid-mismatch failures is the loud
    # symptom if it is broken.
    if [ -n "$workers" ] && [ "$workers" != "1" ] \
       && [ "${PROBER_ALLOW_MULTIWORKER:-0}" != "1" ]; then
        echo "Bail out! worker_processes is \"$workers\", but the pid oracle" \
             "requires exactly 1 -- with several workers a healthy server reports" \
             "a different pid per request and every case fails (set" \
             "PROBER_ALLOW_MULTIWORKER=1 in the scenario env if every case uses" \
             "pid_may_change)"
        exit 1
    fi

    if [ "${PROBER_DAEMON_MODE:-off}" = "on" ]; then
        # The USR2 opt-in: require daemon ON, and require the pidfile at the
        # path prober_boot reads. A conf that opts in but stays daemon-off would
        # still ignore the binary upgrade; one with no pidfile leaves teardown
        # with no master to kill (the launcher's $! is gone). Both are bailed
        # rather than left to surface as a hung upgrade or a leaked process.
        if ! grep -qE '^[[:space:]]*daemon[[:space:]]+on[[:space:]]*;' \
            "$PROBER_PREFIX/conf/nginx.conf"; then
            echo "Bail out! PROBER_DAEMON_MODE=on but the conf lacks" \
                 "\"daemon on;\" -- USR2 binary upgrade is ignored under daemon" \
                 "off (getppid()==ngx_parent for a foregrounded master)"
            exit 1
        fi
        if ! grep -qE "^[[:space:]]*pid[[:space:]]+$PROBER_PREFIX/nginx\.pid[[:space:]]*;" \
            "$PROBER_PREFIX/conf/nginx.conf"; then
            echo "Bail out! PROBER_DAEMON_MODE=on but the conf does not set" \
                 "\"pid $PROBER_PREFIX/nginx.pid;\" -- a daemonized master is not" \
                 "\$! and teardown reads the master pid from that file"
            exit 1
        fi
        return 0
    fi

    if ! grep -qE '^[[:space:]]*daemon[[:space:]]+off[[:space:]]*;' \
        "$PROBER_PREFIX/conf/nginx.conf"; then
        echo "Bail out! conf lacks \"daemon off;\" -- the engine tracks the" \
             "master by \$! and a daemonized server orphans itself past teardown"
        exit 1
    fi
}

# prober_wait_listen HOST PORT TIMEOUT_MS
#
# Returns 0 as soon as a TCP connect to HOST:PORT succeeds, 1 if TIMEOUT_MS
# elapses first. Prints nothing: callers are inside a TAP stream.
#
# The client is bash's /dev/tcp rather than nc, for the reason recorded in
# fakesrv_test.sh's header -- nc is not installed everywhere and the
# openbsd/traditional/ncat variants differ in ways that would make a readiness
# check succeed or fail for reasons unrelated to the listener.
#
# The wait is counted in ITERATIONS of a fixed small sleep, never as a
# difference of two wall-clock readings. A clock-budget loop runs a different
# program on a loaded runner than on an idle one: the same code performs fewer
# probes when each one is slower, so a timeout becomes a property of the host
# rather than of the listener, and the resulting flake reproduces nowhere. A
# fixed step means every host performs the same number of attempts.
prober_wait_listen() {
    local host="$1" port="$2" timeout_ms="$3"
    local step_ms=50 attempts i

    # Round up, and always attempt at least once: a timeout shorter than one
    # step would otherwise report failure without ever having tried to connect,
    # which reads as "not listening" for a port that is.
    attempts=$(( (timeout_ms + step_ms - 1) / step_ms ))
    [ "$attempts" -lt 1 ] && attempts=1

    for ((i = 0; i < attempts; i++)); do
        if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done

    return 1
}

# prober_probe_body HOST PORT
#
# Echo the raw response to a request to /__probe, or return 1 if no COMPLETE
# probe response could be read within the retry budget.
#
# The probe endpoint reports the state of the worker that served THAT request:
# its pid (the field eval_pid_stable, assert.c:543, compares across a case),
# its open descriptor count, and its cycle-pool counters. Reading them here
# rather than parsing `ps`, the pidfile, or /proc means a driver's notion of
# worker state is the assertion engine's notion: an oracle built on a different
# source could call a reload complete while the rule engine still disagrees
# about who answered.
#
# The completeness verdict is the presence of the `"pid"` field. It is the
# first field ngx_test_probe.c emits (:211) and every probe body carries it, so
# a body containing it is one whose emission began; the 124 branch below is what
# rejects a body whose emission did not FINISH. A partial read that stalled
# after `"pid"` therefore fails on the timeout, not here -- which is why the
# stalling-endpoint hazard documented in that branch is handled there and not by
# a second content check. Callers wanting a later field (fds, pool.*) must still
# treat a missing field as an error rather than as a zero.
#
# Deliberately hands back text rather than linking a JSON parser into shell: the
# probe body is emitted as flat one-level JSON, and a driver that needed real
# structure would be asking for the prober binary instead.
prober_probe_body() {
    local host="$1" port="$2" body pid read_rc attempt
    local attempts="${PROBER_PROBE_ATTEMPTS:-3}"

    # A single probe can lose a race the endpoint is not responsible for: the
    # connect succeeds but the peer RSTs before the GET is written (the write
    # takes SIGPIPE -> exit 141, empty body) or before the reply is read (empty
    # body, non-124). Against a real nginx under a reload this is a transient --
    # the worker IS answering, this one connection just lost the race -- and a
    # single empty read here would falsely certify "no new worker". Retry a
    # bounded number of times; each attempt is independently `timeout`-bounded,
    # so the AUD-09 finiteness property holds (worst case attempts * bound, and
    # the outer prober_signal_wait budget is still consulted between calls). A
    # 124 timeout is NOT retried within a call: it already consumed the full
    # per-attempt budget and retrying would multiply the wait; it returns to the
    # caller, whose counted budget advances and re-probes. Observed on the
    # qemu-s390x self-test leg, where the python3 stub's ghost/real accept
    # ordering makes the RST race fire deterministically.
    for (( attempt = 0; attempt < attempts; attempt++ )); do

    # The read's EXIT STATUS is deliberately ignored; only the bytes matter.
    # A server closing a `Connection: close` response commonly RSTs once it has
    # sent everything, and `cat` then exits non-zero having already delivered a
    # complete body. Gating on that status throws away good reads: it fails
    # here about half the time against a real nginx, and the symptom -- a wait
    # that never sees the new worker -- looks exactly like a reload that did
    # not happen.
    # AUD-09: the read is BOUNDED. A bare `cat <&3` blocks until the peer
    # closes, so a probe endpoint that trickles a byte at a time or holds the
    # connection open would hang this single call forever -- and because
    # prober_signal_wait's counted budget only advances between calls, the outer
    # timeout would never be consulted. A single failed reload would then eat the
    # whole CI job. `timeout` caps one probe; the 2 s bound is generous for a
    # healthy in-worker probe yet finite. The bound is `PROBER_PROBE_TIMEOUT`
    # (default 2), tunable ONLY to accommodate a slow host -- e.g. the
    # qemu-user s390x self-test leg, where an emulated python3 stub's
    # accept+reply cycle can exceed 2 s and starve the read into a false 124.
    # It stays finite on every path, so the AUD-09 property (bounded, the outer
    # budget is always eventually consulted) holds for any value.
    #
    # The read's EXIT STATUS is captured and a TIMED-OUT read is treated as a
    # failure even if a partial body arrived. A stalling endpoint can emit
    # `"pid":1234` and then hold the connection open; without this check the pid
    # would be extracted from that partial body and the probe would falsely
    # certify a reload landed. `timeout` exits 124 on expiry, so any non-zero
    # status here means the peer did not deliver a complete response in the
    # budget, which is "no answer" -- not a pid to trust.
        # `trap '' PIPE` is load-bearing: a probe endpoint that answers WITHOUT
        # reading the request (writes its reply and closes -- as the self-test
        # stub does, and as a real server legitimately may on a `Connection:
        # close` response) can close the socket before this `printf` finishes
        # writing the GET. The write then takes SIGPIPE and, unhandled, kills
        # this command-substitution subshell -- discarding the reply that had
        # already arrived in the socket buffer (observed as a deterministic
        # rc=141 empty body on the qemu-s390x leg). Ignoring SIGPIPE lets the
        # write fail quietly and the `cat` still drain the buffered body.
        body="$(trap '' PIPE; exec 3<>"/dev/tcp/$host/$port" 2>/dev/null && {
            printf 'GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
            timeout "${PROBER_PROBE_TIMEOUT:-2}" cat <&3
        } 2>/dev/null)"
        read_rc=$?

        # A non-zero status is only a "no answer" verdict when it is the TIMEOUT
        # (124). A clean `Connection: close` commonly RSTs after the full body
        # and cat exits non-zero HAVING delivered everything -- the case the
        # original code documents -- so that status must NOT reject a complete
        # body. On the timeout code, fail outright (see the no-retry-on-124 note
        # above); on any other non-zero, fall through and let the pid-extraction
        # be the verdict (a complete body still has its pid; a partial one does
        # not).
        if [ "$read_rc" -eq 124 ]; then
            return 1
        fi

        # `"pid": 1234` -- tolerate any spacing the emitter might use, though
        # ngx_test_probe.c:203 emits `"pid":%P` with none.
        pid="$(printf '%s' "$body" | grep -o '"pid"[[:space:]]*:[[:space:]]*[0-9]\+' \
               | grep -o '[0-9]\+$' | head -1)"

        # A pid was extracted -- that IS the success verdict, and the whole body
        # is what the caller gets (prober_probe_pid re-greps the pid from it).
        if [ -n "$pid" ]; then
            printf '%s\n' "$body"
            return 0
        fi
        # No pid this attempt: an unreachable port, a lost RST race (empty
        # body), or a complete body genuinely lacking the field. The first two
        # are transient and worth a retry; the last will fail every attempt and
        # correctly returns 1 once the retries are exhausted.
    done

    # Every attempt failed to yield a pid: no worker pid could be established.
    return 1
}

# prober_probe_pid HOST PORT
#
# Echo the worker pid that answered a request to /__probe, or return 1. Thin
# wrapper over prober_probe_body so that the retry/timeout discipline lives in
# exactly one place: a second copy of that loop is how the two halves of a
# harness drift apart.
prober_probe_pid() {
    local body
    body="$(prober_probe_body "$1" "$2")" || return 1
    prober_probe_field "$body" pid
}

# prober_probe_field BODY NAME
#
# Echo the value of the flat numeric probe field NAME, or return 1 if it is
# absent. Nested fields are addressed by their LEAF name (`cycle_used`, not
# `pool.cycle_used`): the emitted names are unique across the whole body, and a
# path-aware matcher in shell would be the JSON parser this deliberately is not.
#
# Returning 1 on absence rather than echoing an empty string is load-bearing.
# A caller doing arithmetic on a missing field would read it as 0, and a 0 is a
# perfectly plausible delta -- so a probe body that silently lost a field (an
# older module .so, a build without the counter) would certify "nothing grew"
# instead of failing. Absent must be distinguishable from zero.
prober_probe_field() {
    local body="$1" name="$2" val

    # Bounded to the field's own value: `"name" : 123`, tolerating any spacing,
    # and anchored on the quoted name so `cycle_used` cannot be matched by a
    # longer field that merely ends with it.
    val="$(printf '%s' "$body" \
           | grep -o "\"$name\"[[:space:]]*:[[:space:]]*[0-9]\+" \
           | grep -o '[0-9]\+$' | head -1)"

    [ -n "$val" ] || return 1
    printf '%s\n' "$val"
}

# prober_probe_normalize BODY
#
# Echo a normalized rendering of a probe BODY for the nginx-vs-angie flavor
# differential (scenarios/flavor-differential): every field that is legitimate
# to differ across flavor, across a flavor's own release line, or across an
# unrelated environment/run axis is replaced with a fixed placeholder token;
# every FLAVOR-INVARIANT field is passed through untouched. Two documents that
# agree on every invariant field become byte-identical after this, regardless
# of which flavor or which run produced them -- which is exactly the property
# a checked-in golden needs in order to be a real cross-flavor assertion
# rather than a coin flip on unrelated noise.
#
# MASKED (replaced with a fixed token -- legitimately differs, not a bug):
#   flavor             IS the axis under test: "nginx" vs "angie" by design.
#                       Structural presence/shape is asserted by the caller
#                       instead (a nonempty quoted string), never the literal
#                       value, or the golden could only ever match one flavor.
#   flavor_version     differs by construction between nginx 1.28.0/1.29.0 and
#                       angie 1.12.0, and again on the next release of any of
#                       them.
#   pid, ppid          OS-assigned; a different value every boot on either
#                       flavor.
#   config_generation   a process-global counter (see ngx_test_probe.h): its
#                       baseline depends on how many times THIS worker's
#                       master has loaded config before the probe fired, a
#                       run/harness artifact, not a flavor property.
#   pool.cycle_used,    MEASURED to differ (3 runs each, both stable but
#   pool.cycle_blocks,  disagreeing): nginx 1.29.0 and angie 1.12.0 allocate a
#   pool.cycle_large    different amount from the cycle pool during their own
#                       startup / module init on an otherwise-identical conf.
#                       A genuine per-flavor startup difference, not a leak.
#   fds,                ENVIRONMENT-fragile, not flavor-invariant. Locally both
#   connections.free    flavors read fds=10 / free=13, but the CI matrix legs
#                       (nginx 1.28.0/1.29.0/angie 1.12.0 + the ASan leg) all
#                       disagreed with a golden pinning those absolutes: the
#                       open-fd baseline at probe time depends on the runner's
#                       inherited fds, the build's own descriptors (ASan opens
#                       its own), and per-release listener/log fd handling --
#                       none of it a cross-flavor property. connections.free is
#                       total minus in-use, so it moves with the same fd noise.
#                       (An earlier note called both "MEASURED identical"; that
#                       was a single-host measurement mistaken for an invariant
#                       -- the CI legs are the wider sample that refuted it.)
#   fds_by_kind.*       the same fd total split by kind -- environment-fragile
#                       for the same reasons fds is, only more so: the runner's
#                       inherited descriptors, ASan's own fds, and per-release
#                       listener/log handling land in different buckets. Never a
#                       cross-flavor property.
#   smaps.pss,          RSS lineage. Depends on kernel version, page-cache
#   smaps.private_dirty  sharing, glibc arena chunking and ASLR -- an absolute
#                       differential over these is pure noise. The rss-slope
#                       scenario asserts their SLOPE (a property of the leak, not
#                       the absolute), which is the flavor-independent claim.
#   pool.cycle_cleanup   the cleanup-handler count is a per-flavor startup detail
#                       (nginx and angie register a different set of cycle-pool
#                       cleanups during module init), like cycle_used above.
#
# INVARIANT (passed through untouched -- both flavors must produce the exact
# same value on a freshly booted, request-free server, or the diff reds):
#   page_size           ngx_pagesize; same host/libc/getconf(_SC_PAGESIZE) for
#                       both binaries -- this is the "opposite" case the
#                       driver's mutation proof checks (host-dependent, not
#                       flavor-dependent; masking it would be wrong in the
#                       other direction).
#   connections.total   worker_connections from the shared conf template,
#                       echoed back structurally -- both flavors render the
#                       same template, so this must be identical or the
#                       config layer itself diverged. Unlike free/fds this is
#                       a pure config echo, not a runtime fd count.
#   zone.present        no zone is configured in this scenario's conf, so both
#                       flavors must report false.
#
# Deliberately no JSON parser: same discipline as prober_probe_field, and for
# the same reason -- the document is flat enough that a handful of sed
# substitutions is simpler and more auditable than linking a parser into
# shell.
prober_probe_normalize() {
    local body="$1"

    printf '%s' "$body" \
        | sed -E \
            -e 's/"flavor"[[:space:]]*:[[:space:]]*"[^"]*"/"flavor":"MASKED"/' \
            -e 's/"flavor_version"[[:space:]]*:[[:space:]]*"[^"]*"/"flavor_version":"MASKED"/' \
            -e 's/"pid"[[:space:]]*:[[:space:]]*[0-9]+/"pid":MASKED/' \
            -e 's/"ppid"[[:space:]]*:[[:space:]]*[0-9]+/"ppid":MASKED/' \
            -e 's/"config_generation"[[:space:]]*:[[:space:]]*[0-9]+/"config_generation":MASKED/' \
            -e 's/"cycle_used"[[:space:]]*:[[:space:]]*[0-9]+/"cycle_used":MASKED/' \
            -e 's/"cycle_blocks"[[:space:]]*:[[:space:]]*[0-9]+/"cycle_blocks":MASKED/' \
            -e 's/"cycle_large"[[:space:]]*:[[:space:]]*[0-9]+/"cycle_large":MASKED/' \
            -e 's/"cycle_cleanup"[[:space:]]*:[[:space:]]*-?[0-9]+/"cycle_cleanup":MASKED/' \
            -e 's/"free"[[:space:]]*:[[:space:]]*[0-9]+/"free":MASKED/' \
            -e 's/"fds"[[:space:]]*:[[:space:]]*-?[0-9]+/"fds":MASKED/' \
            -e 's/"socket"[[:space:]]*:[[:space:]]*-?[0-9]+/"socket":MASKED/' \
            -e 's/"file"[[:space:]]*:[[:space:]]*-?[0-9]+/"file":MASKED/' \
            -e 's/"anon"[[:space:]]*:[[:space:]]*-?[0-9]+/"anon":MASKED/' \
            -e 's/"other"[[:space:]]*:[[:space:]]*-?[0-9]+/"other":MASKED/' \
            -e 's/"pss"[[:space:]]*:[[:space:]]*-?[0-9]+/"pss":MASKED/' \
            -e 's/"private_dirty"[[:space:]]*:[[:space:]]*-?[0-9]+/"private_dirty":MASKED/'
}

# prober_stimulus_get HOST PORT PATH
#
# Issue one bounded GET to PATH and discard the body. The slope oracle's unit of
# "one operation": the thing whose repetition a resource is asserted NOT to grow
# with. Bounded by PROBER_PROBE_TIMEOUT like every other read here so a stalling
# server cannot hang the sweep, and SIGPIPE-ignored for the same reason
# prober_probe_body is (a Connection: close peer may close before the write
# finishes). The return status is ignored on purpose -- a stimulus request only
# has to REACH the worker to make it do the per-op work; whether it 200s or 404s
# is the scenario's concern, not the slope's.
prober_stimulus_get() {
    local host="$1" port="$2" path="$3"

    ( trap '' PIPE
      exec 3<>"/dev/tcp/$host/$port" 2>/dev/null && {
          printf 'GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' \
              "$path" >&3 2>/dev/null
          timeout "${PROBER_PROBE_TIMEOUT:-2}" cat <&3 >/dev/null 2>&1
      } ) 2>/dev/null
    return 0
}

# prober_slope_check HOST PORT FIELD PATH WARMUP SAMPLES MAX_PER_OP
#
# The third resource-scoreboard oracle (per plan.md P2-E, after per-operation
# delta = `delta` and suite-origin bound = `probe_baseline`): the POST-WARMUP
# SLOPE. A single request's delta can be zero by luck (an allocation freed by the
# next request, a page reclaimed) or hidden by a startup one-off; a slope over
# many operations after the server has warmed up is what a slow, steady leak
# actually looks like. This asserts that, once WARMUP operations have settled the
# server, FIELD grows by no more than MAX_PER_OP per operation across the next
# SAMPLES operations.
#
# Emits a `# `-prefixed TAP diagnostic on failure and returns 1; returns 0 on
# pass. Meant to be called from a scenario driver.sh (the slope/soak cadence is
# weekly per the plan, not the PR path), which prints the ok/not ok line itself.
#
# DESIGN NOTES, each guarding a way this oracle could measure nothing:
#
#  * FAIL CLOSED ON THE SENTINEL. FIELD is read with prober_probe_field, which
#    matches only [0-9]+ and so returns FAILURE (not -1) on the unavailable
#    sentinel the /proc fields render. A sample that cannot be read aborts the
#    sweep with a diagnostic rather than being treated as 0 -- a -1 read as 0
#    would flatten a real slope to nothing. Absent-vs-zero is the same hazard
#    prober_probe_field documents; here it is load-bearing twice over.
#
#  * WARMUP IS DISCARDED, NOT AVERAGED IN. The first allocations after boot are a
#    one-off (lazy zone init, first-request buffers); folding them into the slope
#    would show a leak on a healthy server (reload-soak's trap, in reverse). The
#    baseline is the field AFTER warmup, and the slope is measured from there.
#
#  * MEASURED PER OPERATION, NOT PER WALL-SECOND. SAMPLES is a fixed count and
#    every step is one stimulus GET, so the sweep runs the same program on a
#    loaded runner as an idle one -- the counted-iteration discipline the rest of
#    this file uses so a flake reproduces somewhere.
#
#  * SLOPE, NOT ENDPOINT DELTA. The bound is on growth per operation -- so a
#    single transient blip is amortised while a steady climb is not, which is the
#    difference between noise and a leak.
#
#  * ENFORCED AS TOTAL vs BUDGET, NOT AS A TRUNCATED AVERAGE. The check is
#    (last - baseline) <= MAX_PER_OP * SAMPLES. Dividing the growth by SAMPLES
#    first would truncate toward zero and floor any sub-SAMPLES growth to 0/op,
#    which made a "MAX_PER_OP=0, exactly flat" oracle accept up to SAMPLES-1
#    units of real growth. The per-op figure in the output is informational.
prober_slope_check() {
    local host="$1" port="$2" field="$3" path="$4"
    local warmup="$5" samples="$6" max_per_op="$7"
    local i body baseline last val slope growth budget
    local slope_q slope_r over growth_str

    if [ "$samples" -lt 1 ]; then
        echo "# slope: SAMPLES must be >= 1 (got $samples)"
        return 1
    fi

    # Warm the server: run the per-op stimulus WARMUP times and throw the
    # readings away. The baseline is taken after the last warmup op.
    for (( i = 0; i < warmup; i++ )); do
        prober_stimulus_get "$host" "$port" "$path"
    done

    body="$(prober_probe_body "$host" "$port")" || {
        echo "# slope: probe unreadable at baseline"
        return 1
    }
    baseline="$(prober_probe_field "$body" "$field")" || {
        echo "# slope: field \"$field\" unavailable at baseline" \
             "(sentinel or absent) -- cannot measure a slope over it"
        return 1
    }

    last="$baseline"

    # Post-warmup sweep: one operation, one sample, SAMPLES times.
    for (( i = 0; i < samples; i++ )); do
        prober_stimulus_get "$host" "$port" "$path"

        body="$(prober_probe_body "$host" "$port")" || {
            echo "# slope: probe unreadable at sample $((i + 1))"
            return 1
        }
        val="$(prober_probe_field "$body" "$field")" || {
            echo "# slope: field \"$field\" unavailable at sample" \
                 "$((i + 1)) (sentinel or absent)"
            return 1
        }
        last="$val"
    done

    # The assertion is on TOTAL growth against the budget the per-op bound
    # allows, NOT on a per-op average computed by integer division.
    #
    # WHY NOT (last - baseline) / samples: that division truncates toward zero,
    # so it floors any growth smaller than SAMPLES to 0/op. With the standard
    # SAMPLES=30 an oracle documented as "exactly flat" (MAX_PER_OP=0) silently
    # tolerated up to 29 bytes of total growth, and a MAX_PER_OP=4 bound
    # tolerated up to 4 + 29/30 per op -- a slow leak below one unit per op was
    # invisible to every consumer. Multiplying out instead keeps the bound
    # meaning exactly what the callers' comments claim: growth may not exceed
    # MAX_PER_OP for each of the SAMPLES operations.
    growth=$(( last - baseline ))

    # The verdict is `growth > max_per_op * samples`, but that product is NOT
    # computed: bash arithmetic wraps silently at intmax_t, and a wrapped
    # product flips the sense of the comparison. An absurd bound
    # (max_per_op=-307445734561825861, samples=30) mathematically means "must
    # shrink enormously" but multiplies out to a large POSITIVE budget, so a
    # flat field would pass a bound designed to be unsatisfiable. Nothing in
    # tree passes a value near that today -- both callers read a small integer
    # from the environment -- but a fail-open on a corrupted bound is precisely
    # the failure this helper exists to prevent, and the guard costs one
    # division.
    #
    # Compare via quotient and remainder instead, which stays in range for any
    # representable operands: with q and r from truncating division,
    # growth > max_per_op * samples  <=>  q > max_per_op, or q == max_per_op
    # with a remainder that pushes it over. r is exact and takes growth's sign
    # (bash truncates toward zero), so a positive remainder means "above q".
    slope_q=$(( growth / samples ))
    slope_r=$(( growth - slope_q * samples ))

    if [ "$slope_q" -gt "$max_per_op" ]; then
        over=1
    elif [ "$slope_q" -eq "$max_per_op" ] && [ "$slope_r" -gt 0 ]; then
        over=1
    else
        over=0
    fi

    # Reported per-op figure only. Rounded toward POSITIVE INFINITY (ceiling),
    # which is the rounding the `<=` bound implies: the printed number must
    # never read as satisfying a bound the exact average fails. Rounding away
    # from zero instead would render -5/10 as "-1/op" beside "want <= -1/op"
    # on a line that FAILED, since -0.5 does not satisfy <= -1. Ceiling gives
    # "0/op" there, which is above the bound and agrees with the verdict.
    if [ "$slope_r" -gt 0 ]; then
        slope=$(( slope_q + 1 ))
    else
        slope="$slope_q"
    fi

    # Sign is formatted rather than hardcoded: growth is negative whenever the
    # field shrank, and a literal "+" would render that as "+-5".
    if [ "$growth" -gt 0 ]; then
        growth_str="+${growth}"
    else
        growth_str="${growth}"
    fi

    # Only for the message -- the verdict above never forms this product. It
    # can still wrap on an absurd bound, so say what was asked for, not a
    # wrapped total.
    budget="${max_per_op}/op over ${samples} ops"

    if [ "$over" -eq 1 ]; then
        echo "# slope: \"$field\" $baseline -> $last over $samples ops" \
             "= ${growth_str} total (~${slope}/op)," \
             "want <= ${budget}"
        return 1
    fi

    echo "# slope: \"$field\" $baseline -> $last over $samples ops" \
         "= ${growth_str} total (~${slope}/op)," \
         "within ${budget}"
    return 0
}

# prober_signal_wait SIG PID HOST PORT TIMEOUT_MS
#
# Send SIG to the master, then wait until the reload has actually been ABSORBED
# -- a new worker is answering -- and return 0. Return 1 on timeout.
#
# Why this is not `kill -HUP $pid; sleep 1`:
#
# A signal is asynchronous. kill(1) returns as soon as the signal is queued,
# long before the master has forked a new worker, and well before the OLD
# worker has finished the requests it already had in flight. A scenario that
# asserts anything after a bare `kill` is asserting against whichever of the
# two workers happened to win a race, and it will pass on an idle box and fail
# on a loaded one -- the failure nobody can reproduce.
#
# The oracle is the probe endpoint's own pid field: before the signal we record
# which worker is serving, then poll until a DIFFERENT pid answers. That is the
# definition of "the reload landed" that agrees with the assertion engine, and
# it needs no new C and no pidfile parsing.
#
# Fixed 50 ms steps with a counted iteration budget, never a wall-clock diff.
# A clock-budget loop runs a different program on a loaded runner than on an
# idle one, so a timeout flake reproduces nowhere; prober_wait_listen above
# takes the same shape for the same reason.
#
# NOTE for scenario authors: after this returns, the worker pid HAS changed on
# purpose. The worker-survival oracle runs on every prober case and its strict
# form calls that a crash, so any case spanning this call must carry
# `pid_may_change`, which relaxes it to "still a child of the same master".
# Cases before and after the reload should NOT carry it -- the strict form is
# still the stronger assertion, and the directive is per-case so that the
# relaxation is scoped to the boundary itself.
#
# It does NOT catch a crash: a SIGKILLed worker's replacement has the same
# master as a reloaded one, so a segfault inside the spanning case reads as ok.
# If the scenario has to catch that too, assert it separately.
prober_signal_wait() {
    local sig="$1" pid="$2" host="$3" port="$4" timeout_ms="$5"
    local step_ms=50 attempts i before after

    # Record the serving worker BEFORE signalling. Failing here is fatal to the
    # wait rather than silently degrading to a sleep: without a `before` value
    # there is nothing for "a different pid answered" to be different from, and
    # returning 0 anyway would hand the caller a reload that may not have
    # happened -- the vacuous-gate shape this repo keeps re-learning.
    before="$(prober_probe_pid "$host" "$port")" || return 1

    kill -"$sig" "$pid" 2>/dev/null || return 1

    attempts=$(( (timeout_ms + step_ms - 1) / step_ms ))
    [ "$attempts" -lt 1 ] && attempts=1

    for ((i = 0; i < attempts; i++)); do
        sleep 0.05

        # A reloading master briefly has no worker able to answer; a failed
        # probe is "not yet", not a verdict. Only a SUCCESSFUL read of a
        # different pid ends the wait.
        after="$(prober_probe_pid "$host" "$port")" || continue

        if [ "$after" != "$before" ]; then
            return 0
        fi
    done

    return 1
}

# prober_drain_wait MASTER_PID WANT_WORKERS TIMEOUT_MS
#
# Wait until the master has exactly WANT_WORKERS direct children, i.e. every
# worker belonging to a previous cycle has finished shutting down. Return 0 when
# that holds, 1 on timeout, 2 when the child count cannot be observed on this
# host (no pgrep) -- which callers must surface as a VISIBLE skip rather than
# treat as drained.
#
# Why a reload is not finished when prober_signal_wait returns: that helper's
# verdict is "a NEW worker is answering", which becomes true the moment the new
# cycle's worker accepts. The OLD worker is still alive at that instant, draining
# whatever it had in flight, and while it lives the master still holds its
# channel socketpair and the new worker still holds the inherited channel fds of
# every other live worker. Any descriptor or memory measurement taken in that
# window therefore counts a transient that belongs to no cycle in particular:
# measured on this box, a post-reload worker read fds=10, 11 or 12 across
# repeated runs of the same series purely by how far the old worker had got.
# That is the classic shape of a scenario that "fails on a loaded runner only" --
# the reason this repo waits on falsifiable oracles instead of sleeping.
#
# Fixed 50 ms steps with a counted iteration budget, never a wall-clock diff --
# same discipline, and for the same reason, as prober_wait_listen and
# prober_signal_wait.
prober_drain_wait() {
    local master="$1" want="$2" timeout_ms="$3"
    local step_ms=50 attempts i n

    command -v pgrep >/dev/null 2>&1 || return 2

    attempts=$(( (timeout_ms + step_ms - 1) / step_ms ))
    [ "$attempts" -lt 1 ] && attempts=1

    for ((i = 0; i < attempts; i++)); do
        # `pgrep -P` lists direct children only, which for an nginx master is
        # exactly its worker/helper set. Counting lines rather than parsing pids
        # keeps this independent of process names, which differ between nginx
        # and angie and are localised in neither.
        n="$(pgrep -P "$master" 2>/dev/null | wc -l)"
        [ "$n" -eq "$want" ] && return 0
        sleep 0.05
    done

    return 1
}

# prober_config_wait HOST PORT WAS_GEN STREAK TIMEOUT_MS
#
# Wait until the probe reports a config_generation GREATER than WAS_GEN, and
# keeps reporting that same new value for STREAK consecutive reads. Echo the
# settled generation and return 0; return 1 on timeout, 2 when the probe body
# carries no config_generation field at all -- which callers must surface as a
# VISIBLE skip, never as agreement.
#
# WHAT THIS CATCHES THAT prober_signal_wait AND prober_drain_wait DO NOT.
# Those two answer "is a new worker answering" and "have the old cycle's
# workers gone". Neither one asks WHICH CONFIG the answering worker is running.
# A worker can satisfy both while still serving the OLD configuration: a reload
# that the master rejected (a config that fails to parse leaves the running
# cycle exactly as it was, and the old worker keeps answering), or a second
# reload arriving while the first is still being absorbed. A scenario that then
# asserts on "the new config's behaviour" is asserting against the old one, and
# it passes or fails on timing -- the race this gate exists to remove.
#
# WHY A STREAK RATHER THAN A SINGLE READ. During a reload two workers are
# briefly alive at once, from two different cycles, and the connection this
# helper opens is answered by whichever accepts first. A single read that
# happens to land on the new worker certifies the reload settled while the old
# worker is still taking traffic; the very next request can still reach the old
# config. Requiring the same new value STREAK times in a row makes that
# vanishingly unlikely without ever sleeping on a guess: each read is a fresh
# connection, so the streak samples the accept path repeatedly rather than
# re-reading one cached answer. The streak RESETS on any disagreeing read, so a
# flapping server can never accumulate one.
#
# The streak is a probabilistic argument, and deliberately paired with
# prober_drain_wait rather than offered as a replacement for it: drain is the
# deterministic half ("the old worker is gone, so no read CAN reach it"),
# generation is the half drain cannot supply ("the worker that remains is
# running the config we just loaded"). A caller wanting both properties calls
# both, which is what the reload-config-version scenario does.
#
# A counted iteration budget, never a wall-clock diff -- same discipline as
# prober_wait_listen, prober_signal_wait, prober_drain_wait. The 50 ms step is
# paid only by an iteration that did NOT advance the streak, so TIMEOUT_MS is a
# floor on the waiting time rather than an exact wall-clock bound: a run that
# spends its iterations on back-to-back streak reads takes longer than
# TIMEOUT_MS to exhaust them, each read being independently bounded by
# prober_probe_body's own timeout. Finiteness -- the property that matters and
# the one AUD-09 asks for -- holds either way, because every path through the
# loop consumes an iteration from a fixed budget.
prober_config_wait() {
    local host="$1" port="$2" was="$3" streak="$4" timeout_ms="$5"
    local step_ms=50 attempts i body gen seen=0 run=0 settled=

    attempts=$(( (timeout_ms + step_ms - 1) / step_ms ))
    [ "$attempts" -lt 1 ] && attempts=1

    for ((i = 0; i < attempts; i++)); do
        # A failed probe is NOT a disagreement: mid-reload the endpoint can
        # legitimately refuse a connection for an instant. Treat it as "no
        # sample" and retry, but do not let it extend the streak either --
        # otherwise an endpoint that answers once and then dies would settle.
        if body="$(prober_probe_body "$host" "$port" 2>/dev/null)" \
           && gen="$(prober_probe_field "$body" config_generation 2>/dev/null)"; then

            # An absent field is a different failure from a stale value, and
            # must not be retried into a timeout: the module .so predates the
            # counter, so no amount of waiting will produce one. Distinguish it
            # on the FIRST successful body read.
            seen=1

            if [ "$gen" -gt "$was" ]; then
                if [ "$run" -eq 0 ] || [ "$gen" -eq "$settled" ]; then
                    settled="$gen"
                    run=$((run + 1))
                else
                    # A different new generation than the one being counted:
                    # another reload landed mid-streak. Start counting THAT one.
                    settled="$gen"
                    run=1
                fi

                if [ "$run" -ge "$streak" ]; then
                    printf '%s\n' "$settled"
                    return 0
                fi

                # A read that ADVANCED the streak is not slept on. The streak
                # exists to sample the accept path repeatedly while both cycles
                # can still answer, and spacing those samples 50 ms apart would
                # make a STREAK of 20 cost a second of pure sleeping while
                # sampling the very window it is trying to catch less densely.
                # Back-to-back is both faster and a stronger test.
                continue
            fi

            run=0
        fi

        # Only a read that did not advance the streak waits: a stale generation
        # or an endpoint that would not answer. That is the case where there IS
        # something to wait for.
        sleep 0.05
    done

    # Distinguish "this build has no such field" (2, a visible skip) from "the
    # generation never advanced" (1, a real failure). `seen` is set only where a
    # body was read AND the field parsed out of it, so seen==0 means either the
    # endpoint never answered or it answered without the field. One final probe
    # separates those two: a body that reads but carries no config_generation is
    # the capability gap; anything else is a timeout.
    if [ "$seen" -eq 0 ] && body="$(prober_probe_body "$host" "$port" 2>/dev/null)"; then
        prober_probe_field "$body" config_generation >/dev/null 2>&1 || return 2
    fi

    return 1
}

# prober_boot
#
# Sets: PROBER_SERVER_PID. Config-tests first so a broken conf is a bail-out
# with the actual error, not a connect timeout.
prober_boot() {
    if ! "$PROBER_SERVER_BIN" -t -p "$PROBER_PREFIX" -c conf/nginx.conf \
        >"$PROBER_PREFIX/logs/conftest" 2>&1; then
        echo "Bail out! config test failed:"
        sed 's/^/# /' "$PROBER_PREFIX/logs/conftest"
        exit 1
    fi

    # Capture the launcher's stderr to a file. After config load nginx redirects
    # fd 2 onto its error_log, so a worker's sanitizer report lands in error.log
    # and prober_scrape_log catches it there. But a sanitizer abort DURING
    # startup -- before that redirect -- writes to the inherited fd 2 and would
    # otherwise vanish into the TAP stream. This file is the pre-redirect window;
    # prober_scrape_log reads it too.
    #
    # PROBER_VALGRIND, when set, is a command-prefix STRING (e.g. "valgrind
    # --error-exitcode=99 --leak-check=full ..."), never an already-quoted
    # array -- the caller cannot know $PROBER_PREFIX (only known here, at
    # boot), so lib.sh appends --log-file itself rather than requiring every
    # caller to compute the prefix twice. Built as an array (not string
    # interpolation) so the word-split prefix and the appended --log-file both
    # reach the exec as distinct argv entries; the SC2206 disable is exactly
    # that intentional word-split. Only the REAL server launch runs under it --
    # the config test above stays bare, since instrumenting `-t` is slow and
    # catches nothing the render+check_conf gates do not already catch.
    #
    # nginx workers are fork()-without-exec, so this does NOT need
    # --trace-children: each worker inherits the same valgrinded image and
    # writes its own log via the %p (pid) expansion in --log-file, same as the
    # master's.
    local _vg=()
    if [ -n "${PROBER_VALGRIND:-}" ]; then
        # shellcheck disable=SC2206
        _vg=( ${PROBER_VALGRIND} --log-file="$PROBER_PREFIX/logs/valgrind.%p" )
    fi
    "${_vg[@]}" "$PROBER_SERVER_BIN" -p "$PROBER_PREFIX" -c conf/nginx.conf \
        2>"$PROBER_PREFIX/logs/server.err" &
    PROBER_SERVER_PID=$!

    # Under the daemon-on opt-in the process just backgrounded is the LAUNCHER,
    # not the master: it double-forks the real master and exits, so $! reaps in
    # a moment and the master reparents to init. Wait the launcher out (its exit
    # is normal, status ignored), then adopt the master pid from the pidfile the
    # conf was gated to write. Everything downstream -- the readiness loop, the
    # driver's signal target, teardown -- then tracks the master by that pid.
    if [ "${PROBER_DAEMON_MODE:-off}" = "on" ]; then
        wait "$PROBER_SERVER_PID" 2>/dev/null || true
        PROBER_SERVER_PID=""

        local _p _pid
        for _p in $(seq 1 $((50 * PROBER_TIMEOUT_SCALE))); do
            if [ -s "$PROBER_PREFIX/nginx.pid" ]; then
                _pid="$(tr -d '[:space:]' < "$PROBER_PREFIX/nginx.pid")"
                if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
                    PROBER_SERVER_PID="$_pid"
                    break
                fi
            fi
            sleep 0.1
        done

        if [ -z "$PROBER_SERVER_PID" ]; then
            echo "Bail out! daemon-on master never wrote a live pid to" \
                 "$PROBER_PREFIX/nginx.pid"
            if [ -f "$PROBER_PREFIX/logs/error.log" ]; then
                sed 's/^/# /' "$PROBER_PREFIX/logs/error.log"
            fi
            # A sanitizer that aborts before the log is redirected leaves its
            # only trace in server.err; prober_scrape_log is never reached on a
            # boot failure, so emit it here or the CI trace is lost.
            if [ -f "$PROBER_PREFIX/logs/server.err" ]; then
                sed 's/^/# /' "$PROBER_PREFIX/logs/server.err"
            fi
            exit 1
        fi
    fi

    # Wait for the listener rather than sleeping a fixed interval: a fixed
    # sleep is either slow or flaky, and on a loaded CI box it is both. Verify
    # after each connect that the server is still alive: a stale listener on the
    # port can answer TCP connects while our server exited on bind() failure.
    local _i
    for _i in $(seq 1 $((50 * PROBER_TIMEOUT_SCALE))); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$PROBER_RESOLVED_PORT") 2>/dev/null; then
            if kill -0 "$PROBER_SERVER_PID" 2>/dev/null; then
                break
            fi
            # Server is dead but listener answered. Stale listener; retry.
        fi
        sleep 0.1
    done

    # Final check: server must still be alive.
    if ! kill -0 "$PROBER_SERVER_PID" 2>/dev/null; then
        echo "Bail out! server failed to start (pid $PROBER_SERVER_PID exited):"
        if [ -f "$PROBER_PREFIX/logs/error.log" ]; then
            sed 's/^/# /' "$PROBER_PREFIX/logs/error.log"
        fi
        # See the note above: server.err holds a pre-redirect sanitizer abort
        # that prober_scrape_log will never get to print on a boot failure.
        if [ -f "$PROBER_PREFIX/logs/server.err" ]; then
            sed 's/^/# /' "$PROBER_PREFIX/logs/server.err"
        fi
        exit 1
    fi
}

# prober_stop
#
# Stop the server synchronously rather than leaving it to an EXIT trap. kill(1)
# only delivers TERM; without waiting for the process to actually go, the
# script can return while workers are still writing out their .gcda files, and
# the coverage job downstream then reads a partial profile. Waiting also means
# the error-log scrape reads a file nobody is still appending to.
prober_stop() {
    # A daemon-off master is our child: kill $! and `wait` reaps it.
    if [ "${PROBER_DAEMON_MODE:-off}" != "on" ]; then
        kill "$PROBER_SERVER_PID" 2>/dev/null || true
        wait "$PROBER_SERVER_PID" 2>/dev/null || true
        return 0
    fi

    # A daemon-on master reparented to init after the launcher exited, so `wait`
    # cannot reap it -- poll until it is actually gone (prober_backend_stop's
    # shape), so the log/journal scrape that follows reads a settled process.
    #
    # Crucially, the master to kill is read from the pidfile HERE, not taken
    # from PROBER_SERVER_PID. A USR2 scenario replaces the master mid-run: the
    # new generation writes a fresh nginx.pid and the old one moves to
    # nginx.pid.oldbin. A driver runs in a subprocess, so any PROBER_SERVER_PID
    # it re-adopted does not reach this teardown in the parent -- trusting the
    # variable would kill the retired master and LEAK the live one, holding the
    # port past the run. Killing every pid named by both files, plus the
    # variable, covers all three: the current master, a not-yet-retired oldbin,
    # and the daemon-off fallback value.
    local _p _pid _targets=""
    for _p in "$PROBER_PREFIX/nginx.pid" "$PROBER_PREFIX/nginx.pid.oldbin"; do
        [ -s "$_p" ] || continue
        _pid="$(tr -d '[:space:]' < "$_p" 2>/dev/null)"
        [ -n "$_pid" ] && _targets="$_targets $_pid"
    done
    [ -n "${PROBER_SERVER_PID:-}" ] && _targets="$_targets $PROBER_SERVER_PID"

    for _pid in $_targets; do
        kill "$_pid" 2>/dev/null || true
    done
    for _p in $(seq 1 50); do
        _pid=""
        for _pid in $_targets; do
            kill -0 "$_pid" 2>/dev/null && break
            _pid=""
        done
        [ -z "$_pid" ] && break
        sleep 0.1
    done
    for _pid in $_targets; do
        kill -9 "$_pid" 2>/dev/null || true
    done
}

# prober_scrape_log
#
# Returns 1 if the error log holds an unexempted alert/crit/emerg line.
#
# Surfaces what the HTTP responses cannot show. A worker that exits on a
# signal, finalizes a request twice or reuses a busy buffer logs at [alert] or
# [crit] and then carries on serving; the next request is answered by a
# respawned worker and every assertion in the run still passes. Without this
# the suite is green and the bug ships. It is a default, not an opt-in, because
# the failure mode it catches is precisely the one nobody thinks to enable a
# check for.
#
# [crit] is in the set deliberately: nginx logs slab exhaustion at [crit],
# which is the single most common real symptom of an unchecked shm allocation.
# Rules that provoke that ON PURPOSE -- a fault injector arming an allocation
# failure -- must therefore be able to exempt the line they expect, or the gate
# would fail every suite that tests its module's out-of-memory path.
# PROBER_ALLOW_LOG is that opt-out: an extended regex, matched per line, whose
# hits are reported but not fatal. Scoped to the pattern rather than a blanket
# off switch, so exempting "no memory" still leaves a segfault in the same run
# fatal.
# A sanitizer/UBSan report is fatal and NEVER exemptable. It is not an nginx
# severity line, so the alert/crit/emerg grep below cannot see it, and
# PROBER_ALLOW_LOG must not reach it: a use-after-free or overflow is never an
# "expected fault" the way a [crit] slab exhaustion is. Matched on both the
# error_log (nginx redirects fd 2 there after config load, so a worker report
# lands in it) and the launcher's server.err (the pre-redirect startup window).
# The AddressSanitizer/LeakSanitizer banners and the libubsan "runtime error:"
# prefix cover the sanitizers the build.sh SAN=1 build turns on.
PROBER_SANITIZER_RE='(AddressSanitizer|LeakSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|SUMMARY: .*Sanitizer|runtime error:)'

prober_scrape_log() {
    local log="$PROBER_PREFIX/logs/error.log" scrape allowed san
    local serr="$PROBER_PREFIX/logs/server.err"

    san="$( { [ -f "$log" ] && grep -Ea "$PROBER_SANITIZER_RE" "$log"; \
             [ -f "$serr" ] && grep -Ea "$PROBER_SANITIZER_RE" "$serr"; } 2>/dev/null || true )"
    if [ -n "$san" ]; then
        echo "# server emitted a sanitizer report (never exemptable):"
        printf '%s\n' "$san" | sed 's/^/# /'
        return 1
    fi

    [ -f "$log" ] || return 0

    scrape="$(grep -E '\[(alert|crit|emerg)\]' "$log" || true)"

    if [ -n "${PROBER_ALLOW_LOG:-}" ] && [ -n "$scrape" ]; then
        allowed="$(printf '%s\n' "$scrape" | grep -E "$PROBER_ALLOW_LOG" || true)"
        scrape="$(printf '%s\n' "$scrape" | grep -vE "$PROBER_ALLOW_LOG" || true)"

        if [ -n "$allowed" ]; then
            echo "# error-log lines exempted by PROBER_ALLOW_LOG:"
            printf '%s\n' "$allowed" | sed 's/^/# /'
        fi
    fi

    if [ -n "$scrape" ]; then
        echo "# server logged alert/crit/emerg:"
        printf '%s\n' "$scrape" | sed 's/^/# /'
        return 1
    fi

    return 0
}

# prober_scrape_valgrind
#
# Returns 1 if any $PROBER_PREFIX/logs/valgrind.* log holds a finding.
#
# Belt-and-suspenders with PROBER_VALGRIND's own --error-exitcode: memcheck
# exits 0 by DEFAULT even when it reported errors -- --error-exitcode changes
# that, but only for the process valgrind directly launched. This scrape is
# the belt: it greps the logs regardless of what the exit code did, which is
# what makes the self-test in valgrind_scrape_test.sh able to prove the gate
# is not vacuous (a run trusting only the exit code would stay green on a
# build that forgot the flag, or on any log written by a process valgrind
# attached to without launching).
#
# A no-op, returning 0, when no valgrind log exists at all -- the normal case,
# with PROBER_VALGRIND unset. Mirrors prober_scrape_log's shape: `# `-prefixed
# TAP diagnostics, non-zero on a finding, called unconditionally by every
# caller so a scenario run under valgrind is gated the same way whether it
# went through the driver.sh path or the rules path -- the server-side logs
# are what matter regardless of which one drove the requests.
prober_scrape_valgrind() {
    local log found=""

    compgen -G "$PROBER_PREFIX/logs/valgrind.*" >/dev/null 2>&1 || return 0

    for log in "$PROBER_PREFIX"/logs/valgrind.*; do
        [ -f "$log" ] || continue

        if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' "$log" 2>/dev/null; then
            found=1
            echo "# valgrind reported errors in $(basename "$log"):"
            sed 's/^/# /' "$log"
        fi
    done

    [ -n "$found" ] && return 1
    return 0
}

# prober_backend_start SCRIPT
#
# Sets: PROBER_BACKEND_PID PROBER_BACKEND_PORT PROBER_BACKEND_JOURNAL
#
# Boots fakesrv on an ephemeral port against SCRIPT and waits for it to accept.
# The caller owns teardown via prober_backend_stop.
#
# A missing SCRIPT is fatal. This is the load-bearing line in the function: the
# alternative -- carrying on with no backend -- produces a scenario that boots,
# serves, and passes every assertion that does not happen to need the upstream,
# under a name claiming the upstream was exercised. That is the vacuous-gate
# failure mode this repo keeps re-learning, and here it would be permanent,
# because nothing downstream can distinguish "the backend said nothing" from
# "there was no backend".
prober_backend_start() {
    local script="$1" portfile port

    if [ ! -f "$script" ]; then
        echo "Bail out! no backend script at $script -- a scenario that asks" \
             "for a backend must ship one; running on without it would pass" \
             "by testing the no-upstream path under the wrong name"
        exit 1
    fi

    if [ ! -x ./fakesrv ]; then
        echo "Bail out! no fakesrv binary -- run prober/build.sh first"
        exit 1
    fi

    portfile="$PROBER_PREFIX/backend.port"
    PROBER_BACKEND_JOURNAL="$PROBER_PREFIX/backend.jsonl"

    # Port 0: the kernel picks a free one and fakesrv publishes it. Hardcoding
    # a port makes two scenarios running at once fail on bind, and the failure
    # surfaces as a connect error in whichever one lost.
    ./fakesrv -script "$script" -listen 127.0.0.1:0 \
              -portfile "$portfile" \
              -journal "$PROBER_BACKEND_JOURNAL" \
              -errfile "$PROBER_PREFIX/backend.err" &
    PROBER_BACKEND_PID=$!

    # Wait for the portfile to become NON-EMPTY, not merely to exist. fakesrv
    # writes it tmp+fsync+rename precisely so a reader never sees a partial
    # file, but a reader that accepts a zero-length one parses "" as a port and
    # then connects to port 0 -- the 1-in-20 flake fakesrv.c:37 documents.
    local _i
    for ((_i = 0; _i < 100; _i++)); do
        if [ -s "$portfile" ]; then
            break
        fi
        if ! kill -0 "$PROBER_BACKEND_PID" 2>/dev/null; then
            echo "Bail out! fakesrv exited before publishing a port:"
            [ -f "$PROBER_PREFIX/backend.err" ] &&
                sed 's/^/# /' "$PROBER_PREFIX/backend.err"
            exit 1
        fi
        sleep 0.05
    done

    port="$(cat "$portfile" 2>/dev/null || true)"

    case "$port" in
        ''|*[!0-9]*)
            echo "Bail out! fakesrv published no usable port (read \"$port\")"
            exit 1 ;;
    esac

    PROBER_BACKEND_PORT="$port"

    if ! prober_wait_listen 127.0.0.1 "$PROBER_BACKEND_PORT" 5000; then
        echo "Bail out! fakesrv published port $PROBER_BACKEND_PORT but is not" \
             "accepting connections"
        exit 1
    fi
}

# prober_backend_stop
#
# Mirrors prober_stop: TERM, then wait for the process to actually go, so the
# journal and errfile are complete before anything reads them. Tolerates an
# already-dead pid -- a scenario that kills the backend on purpose must not
# then fail in teardown.
prober_backend_stop() {
    [ -n "${PROBER_BACKEND_PID:-}" ] || return 0

    kill "$PROBER_BACKEND_PID" 2>/dev/null || true
    wait "$PROBER_BACKEND_PID" 2>/dev/null || true
}

# prober_backend_scrape
#
# Returns 1 if the backend reported an error or died during the scenario.
#
# Shaped like prober_scrape_log: `# `-prefixed TAP diagnostics, non-zero on a
# finding. It reads -errfile, which is where fakesrv's die() lands -- a script
# it could not parse, a fault action it did not recognise, a socket call that
# failed. Those are silent otherwise: the daemon is backgrounded, its stdout is
# barred by rule 1, and a scenario whose upstream died mid-run sees only
# connection errors from the module under test, which reads as a module bug.
#
# A backend that is no longer alive at scrape time is itself a finding, for the
# same reason. PROBER_BACKEND_ALLOW_EXIT is the opt-out for scenarios that
# terminate it deliberately; scoped to that one claim like PROBER_ALLOW_LOG,
# never a blanket off switch -- an exempted exit still leaves a parse error in
# the same run fatal.
prober_backend_scrape() {
    local errfile="$PROBER_PREFIX/backend.err" scrape rc=0

    if [ -n "${PROBER_BACKEND_PID:-}" ] &&
       ! kill -0 "$PROBER_BACKEND_PID" 2>/dev/null &&
       [ -z "${PROBER_BACKEND_ALLOW_EXIT:-}" ]; then
        echo "# fake upstream exited before teardown (pid $PROBER_BACKEND_PID)"
        rc=1
    fi

    if [ -f "$errfile" ]; then
        scrape="$(grep -v '^[[:space:]]*$' "$errfile" || true)"

        if [ -n "$scrape" ]; then
            echo "# fake upstream reported errors:"
            printf '%s\n' "$scrape" | sed 's/^/# /'
            rc=1
        fi
    fi

    return "$rc"
}

# prober_cleanup
#
# Idempotent teardown of everything a scenario allocated: fake upstream,
# server, prefix. Installed as ONE trap by the caller, before the first
# resource exists -- which is what closes the window a trap-per-resource
# ladder leaves open, where a failure between two installs leaks whatever the
# earlier one owned.
#
# Saves and restores $? as its very first and very last act. An EXIT trap's
# own exit status becomes the script's, so a single unguarded command in here
# -- a kill on an already-reaped pid is enough -- turns a failing scenario
# green, or a passing one red, with every assertion in the TAP stream still
# reading ok. That is not hypothetical: it is exactly what P1-B3's own gate
# hit. Hence every command below is guarded and the function ends with an
# explicit `return`, never with the status of whatever ran last.
#
# Trap install stays in the CALLER. A library that installs its own trap
# silently overwrites the caller's -- see prober_render_conf's note.
prober_cleanup() {
    local rc=$?

    prober_backend_stop || true

    if [ -n "${PROBER_SERVER_PID:-}" ]; then
        prober_stop || true
    fi

    # Only a prefix this harness created is removed. An inherited one is left
    # alone -- see prober_make_prefix for how a foreign value gets in.
    if [ -n "${PROBER_PREFIX:-}" ] && [ -n "${PROBER_PREFIX_OWNED:-}" ]; then
        rm -rf "$PROBER_PREFIX" || true
    fi

    # A second call must be a no-op rather than a second teardown: the caller
    # may run this inline at the end of a happy path AND have it fire again on
    # EXIT. Clearing the handles is what makes the guards above hold.
    PROBER_BACKEND_PID=""
    PROBER_SERVER_PID=""
    PROBER_PREFIX=""
    PROBER_PREFIX_OWNED=""

    return "$rc"
}
