#!/usr/bin/env bash
#
# TAP self-test for the fakesrv daemon.
#
# backend_test.c proves the codecs and the script parser as pure functions.
# What it structurally cannot reach is everything this file exists for: that
# the daemon binds a port and writes it where a scenario can find it, that a
# real client on a real socket gets the reply the codec built, that the faults
# actually fire on the wire, and that the journal records what happened. A fake
# upstream whose codecs are perfect and whose socket handling is broken passes
# backend_test completely.
#
# Clients here are bash's /dev/tcp rather than nc, which is not installed
# everywhere and differs across the openbsd/traditional/ncat variants in ways
# that would make this suite pass or fail for reasons unrelated to the daemon.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=35
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

WORK="$(mktemp -d)"
SRV_PID=""

cleanup() {
    if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

./build.sh >/dev/null

#
# Start fakesrv on port 0 and wait for the portfile.
#
# Polling for the file is the whole reason the daemon writes it atomically:
# a non-atomic write is visible as a zero-length file, and this loop would then
# read an empty port about one run in twenty.
#
start_srv() {
    local script="$1"
    shift

    rm -f "$WORK/port" "$WORK/journal" "$WORK/err"

    ./fakesrv -script "$script" \
              -listen 127.0.0.1:0 \
              -portfile "$WORK/port" \
              -journal "$WORK/journal" \
              -errfile "$WORK/err" \
              "$@" >/dev/null 2>&1 &

    SRV_PID=$!

    for _ in $(seq 1 100); do
        if [ -s "$WORK/port" ]; then
            PORT="$(cat "$WORK/port")"
            return 0
        fi
        sleep 0.05
    done

    return 1
}

stop_srv() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
        SRV_PID=""
    fi
}

# Send $2 to the daemon and print whatever comes back, giving up after $3
# seconds so a hung daemon fails this suite rather than the whole CI job.
talk() {
    local port="$1" payload="$2" timeout="${3:-2}"

    exec 3<>"/dev/tcp/127.0.0.1/$port" || return 1

    printf '%b' "$payload" >&3

    timeout "$timeout" cat <&3 || true

    exec 3<&- 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
}

# ---- memcached, no faults ---------------------------------------------------

cat >"$WORK/mc.backend" <<'EOF'
proto   memcached
seed    hello  world
seed    empty  ""
EOF

if start_srv "$WORK/mc.backend"; then st=0; else st=1; fi
ok "$st" "the daemon starts and writes its port"

case "$PORT" in
    ''|*[!0-9]*) ok 1 "the portfile holds a numeric port" ;;
    *)           ok 0 "the portfile holds a numeric port" ;;
esac

# Sentinel `_` on both sides, same reason as the zero-length case below: `$()`
# strips trailing newlines, so without it a reply missing its final `\n` is
# indistinguishable from a correct one.
out="$(talk "$PORT" 'get hello\r\n'; printf '_')"
if [ "$out" = "$(printf 'VALUE hello 0 5\r\nworld\r\nEND\r\n_')" ]; then st=0; else st=1; fi
ok "$st" "a get hit is served over a real socket"

out="$(talk "$PORT" 'get absent\r\n'; printf '_')"
if [ "$out" = "$(printf 'END\r\n_')" ]; then st=0; else st=1; fi
ok "$st" "a get miss is served over a real socket"

# A ZERO-LENGTH value on the wire. Legal memcached, and the framing edge case
# most likely to be got wrong: `VALUE empty 0 0\r\n\r\nEND\r\n` has an empty
# payload between two CRLFs, so a server that miscounts emits one CRLF too few
# (running the terminator into END) or one too many. Asserted as the WHOLE
# reply rather than with grep, because a grep for `VALUE empty 0 0` passes on
# every one of those malformed frames.
#
# The trailing `_` is load-bearing. `$()` strips trailing newlines from BOTH
# sides of the comparison, so without a sentinel a server that sent `END\r`
# with no final `\n` would compare EQUAL to one that framed it correctly --
# and that missing byte is precisely the off-by-one this case exists to catch.
# Appending a visible character inside each substitution preserves the newline
# before it. (CodeRabbit on PR #62; verified both directions before applying.)
out="$(talk "$PORT" 'get empty\r\n'; printf '_')"
if [ "$out" = "$(printf 'VALUE empty 0 0\r\n\r\nEND\r\n_')" ]; then st=0; else st=1; fi
ok "$st" "a zero-length value is framed correctly on the wire"

# A set followed by a get on the SAME connection: proves the store is real and
# that the daemon keeps reading after answering, which a one-shot reply loop
# would fail.
out="$(talk "$PORT" 'set k 0 0 3\r\nabc\r\nget k\r\n')"
if grep -q 'STORED' <<<"$out"; then st=0; else st=1; fi
ok "$st" "a set is acknowledged"
if grep -q 'VALUE k 0 3' <<<"$out"; then st=0; else st=1; fi
ok "$st" "a value set on one connection is readable on the same connection"

# Pipelining: two commands in one write must draw two replies.
out="$(talk "$PORT" 'get hello\r\nversion\r\n')"
if grep -q 'VALUE hello' <<<"$out"; then st=0; else st=1; fi
ok "$st" "the first of two pipelined commands is answered"
if grep -q 'VERSION' <<<"$out"; then st=0; else st=1; fi
ok "$st" "the second of two pipelined commands is answered"

# A set whose data block arrives in a SEPARATE write, and therefore in a later
# read() on the daemon side. This is the case that failed on all four CI legs
# while every local run passed: the single-write test above happens to deliver
# the command line and its payload in one read, which hides a parser that
# mutates the buffer before deciding the command is complete.
out="$(
    exec 3<>"/dev/tcp/127.0.0.1/$PORT"
    printf 'set sp 0 0 3\r\n' >&3
    sleep 0.2
    printf 'xyz\r\n' >&3
    sleep 0.2
    printf 'get sp\r\n' >&3
    timeout 2 cat <&3 || true
)"
if grep -q 'STORED' <<<"$out"; then st=0; else st=1; fi
ok "$st" "a set split across two writes is acknowledged"
if grep -q 'VALUE sp 0 3' <<<"$out"; then st=0; else st=1; fi
ok "$st" "a set split across two writes actually stores its value"

stop_srv

if grep -q '"ev":"listen"' "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "the journal records the listen event"

if grep -q '"ev":"cmd".*"cmd":"get"' "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "the journal records commands"

# AUD-10: a distinct "send" event marks when a reply's first byte hits the
# wire, strictly after the "cmd" that requested it. The reload-inflight
# scenario polls for this (not "cmd") to prove a reply is genuinely dripping
# before it signals HUP.
#
# Coupled to the command count, not a mere existence check: every command in
# this block draws exactly one reply, so one "send" must be journalled per
# "cmd". A single existence assertion would still pass if send were emitted
# once per connection (send_started never reset by out_set) -- the exact bug
# that would silently break the pipelined get+version pair, which shares one
# connection and so must produce TWO sends. Equal counts prove the per-reply
# reset works. (Ordering per record is guaranteed by fflush-per-record: a
# reply's "send" is always written after the "cmd" that armed it.)
n_cmd="$(grep -c '"ev":"cmd"' "$WORK/journal")"
n_send="$(grep -c '"ev":"send"' "$WORK/journal")"
if [ "$n_send" -gt 0 ] && [ "$n_send" = "$n_cmd" ]; then st=0; else st=1; fi
ok "$st" "one send event per command reply, reset across replies (AUD-10; cmd=$n_cmd send=$n_send)"

if grep -q '"ev":"summary"' "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "the journal ends with a summary record"

# The load-bearing claim: the summary's accept count is what makes a keepalive
# assertion falsifiable. Six connections were opened above -- this number is
# coupled to the `talk` calls in this block, so adding one anywhere above means
# bumping it here.
accepts="$(sed -n 's/.*"accepts":\([0-9]*\).*/\1/p' "$WORK/journal" | tail -1)"
if [ "$accepts" = "6" ]; then st=0; else st=1; fi
ok "$st" "the summary counts one accept per connection (got ${accepts:-none})"

if [ ! -s "$WORK/err" ]; then st=0; else st=1; fi
ok "$st" "a clean run writes nothing to the errfile"


# ---- the portfile is never observable as zero-length ------------------------
#
# The atomicity property, tested directly rather than through its symptom.
#
# The daemon writes PATH.tmp, fsyncs and renames. Written in place instead, the
# file is briefly visible with no contents, and the polling loop in start_srv --
# and in every scenario that will use this daemon -- reads an empty port. It
# reproduces roughly one run in twenty, which is exactly the frequency at which
# a CI leg gets disabled rather than fixed.
#
# Racing the window directly does NOT work as a gate, and the first draft of
# this test proved it the expensive way: a shell loop watching for an
# existing-but-empty file caught the in-place mutant on this machine and
# SURVIVED it on CI, where the daemon reaches its first write before the loop's
# first stat. A detector whose sensitivity depends on the host is not a gate.
#
# So assert the MECHANISM instead, which is timing-independent. A daemon that
# renames into place has, at the instant the final path appears, already written
# and fsynced a sibling `.tmp` -- so the final path is never observed empty, and
# the temporary never outlives the rename. Writing in place satisfies neither:
# it creates the final path itself, and creates no sibling at all.
#
# `inotifywait` would observe the window directly, but it is not installed on
# every runner and a test that silently skips is worse than one that is coarse.
portfile_ok=1
portfile_why=""

for _attempt in 1 2 3 4 5; do
    rm -f "$WORK/racecheck" "$WORK/racecheck.tmp"

    ./fakesrv -script "$WORK/mc.backend" -listen 127.0.0.1:0 \
              -portfile "$WORK/racecheck" >/dev/null 2>&1 &
    race_pid=$!

    # Wait for the daemon to publish, then judge what it left behind.
    for _ in $(seq 1 200); do
        [ -e "$WORK/racecheck" ] && break
        sleep 0.02
    done

    # 1. The published file must carry a port the moment it exists. Under an
    #    in-place write the create and the content are separate steps, so this
    #    is the state a poller can catch; under rename they are atomic.
    if [ -e "$WORK/racecheck" ] && [ ! -s "$WORK/racecheck" ]; then
        portfile_ok=0
        portfile_why="the portfile existed while still empty"
    fi

    # 2. A leftover sibling means the rename never happened.
    if [ -e "$WORK/racecheck.tmp" ]; then
        portfile_ok=0
        portfile_why="a .tmp sibling outlived the write"
    fi

    kill "$race_pid" 2>/dev/null || true
    wait "$race_pid" 2>/dev/null || true

    [ "$portfile_ok" -eq 0 ] && break
done

if [ "$portfile_ok" -eq 1 ]; then st=0; else st=1; fi
ok "$st" "the portfile is published atomically${portfile_why:+ ($portfile_why)}"

# The assertion that actually kills the in-place mutant on every host: judged on
# the SOURCE, not on a race. The daemon must name a `.tmp` path and call
# rename() on it. Timing-independent by construction, which is the whole point --
# the observable window is microseconds wide and its width depends on the host,
# so any test that has to CATCH it is a test that passes or fails on hardware.
#
# Grepping the implementation is a weaker kind of evidence than observing the
# behaviour, and it is used here deliberately rather than lazily: the behaviour
# is genuinely unobservable from a shell on a fast machine, and the alternative
# on offer was a check that reported SURVIVED on CI while reporting caught here.
if grep -q '"%s.tmp"' fakesrv.c && grep -q 'rename(tmp, path)' fakesrv.c; then
    st=0
else
    st=1
fi
ok "$st" "the daemon writes a .tmp sibling and renames it into place"

# ---- faults actually fire on the wire ---------------------------------------

cat >"$WORK/rst.backend" <<'EOF'
proto   memcached
seed    hello  world
fault   on=get:1  action=rst
EOF

start_srv "$WORK/rst.backend"

# The reset arrives as a failed read rather than as data. What must NOT happen
# is a well-formed reply: that would mean the fault was parsed and dropped.
#
# Written as an if rather than `grep -q ...; [ $? -ne 0 ]` -- that idiom reads
# the exit status of the TEST, not of the grep, so it is always true and the
# assertion passes no matter what the daemon sent.
out="$(talk "$PORT" 'get hello\r\n' 2>/dev/null || true)"
if grep -q 'VALUE' <<<"$out"; then
    ok 1 "an rst fault suppresses the reply"
else
    ok 0 "an rst fault suppresses the reply"
fi

stop_srv

# ---- truncate ---------------------------------------------------------------

cat >"$WORK/trunc.backend" <<'EOF'
proto   memcached
seed    hello  world
fault   on=get:1  action=truncate  after=8
EOF

start_srv "$WORK/trunc.backend"

out="$(talk "$PORT" 'get hello\r\n' 2>/dev/null || true)"
if [ "${#out}" -le 8 ]; then st=0; else st=1; fi
ok "$st" "a truncate fault cuts the reply short (got ${#out} bytes)"

stop_srv

# ---- redis ------------------------------------------------------------------
#
# SC2016 is disabled per-line below: the single quotes around the RESP frames
# are load-bearing. `$3` and `$5` are bulk-string length markers in the
# protocol, not shell variables -- expanding them is what must not happen.

cat >"$WORK/redis.backend" <<'EOF'
proto   redis
seed    hello  world
EOF

start_srv "$WORK/redis.backend"

# shellcheck disable=SC2016
out="$(talk "$PORT" '*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n')"
# shellcheck disable=SC2016
if [ "$out" = "$(printf '$5\r\nworld\r')" ]; then st=0; else st=1; fi
ok "$st" "a RESP get hit is served over a real socket"

# shellcheck disable=SC2016
out="$(talk "$PORT" '*2\r\n$3\r\nGET\r\n$6\r\nabsent\r\n')"
# shellcheck disable=SC2016
if [ "$out" = "$(printf '$-1\r')" ]; then st=0; else st=1; fi
ok "$st" "a RESP get miss serves the nil bulk string"

# AUD-02: an INLINE set/get over the socket. The inline parser used to store arg
# pointers into a stack buffer that died at parse return, so the daemon -- which
# reads args AFTER the parser returns to journal and reply -- served corrupted
# bytes. A set then get on one connection proves the args survived. Verbs are
# upper-case on the wire to also prove inline folding (AUD-02).
out="$(talk "$PORT" 'SET ik hello\r\nGET ik\r\n')"
# shellcheck disable=SC2016
if [ "$out" = "$(printf '+OK\r\n$5\r\nhello\r')" ]; then st=0; else st=1; fi
ok "$st" "an inline RESP set/get round-trips over a real socket (AUD-02)"

# The journal must have recorded the inline args faithfully, not freed stack.
if grep -q '"cmd":"set","args":\["ik","hello"\]' "$WORK/journal"; then
    st=0
else
    st=1
fi
ok "$st" "the journal records the inline set's args, not dead stack (AUD-02)"

# AUD-03 (binary-safe values) is proven end-to-end in backend_test.c under ASan
# rather than here: an embedded NUL cannot survive a bash "$()" capture, so a
# socket round-trip in shell would truncate the value before it ever reached the
# daemon and prove nothing. The C daemon path (parse -> store -> reply) exercises
# the same code with the NUL intact.

# AUD-04: the bulk string's trailing CRLF is mandatory. Replace it with two
# stray bytes and require the daemon to reject the frame (empty reply, since the
# connection is closed on a protocol error) rather than resynchronise and answer
# a seeded value as if the frame were legal.
# shellcheck disable=SC2016
out="$(talk "$PORT" '*2\r\n$3\r\nGET\r\n$5\r\nhelloXY')"
if [ -z "$out" ]; then st=0; else st=1; fi
ok "$st" "a RESP frame with a corrupt CRLF terminator is rejected (AUD-04)"

stop_srv

# AUD-04b: the memcached storage block's terminator must be a full CRLF. A CR
# followed by a stray byte (not LF) must be rejected, not stored-and-STORED.
start_srv "$WORK/mc.backend"
out="$(talk "$PORT" 'set bad 0 0 3\r\nabc\rX\r\n')"
if grep -q 'STORED' <<<"$out"; then st=1; else st=0; fi
ok "$st" "a memcached set with a CR+wrong-byte terminator is rejected (AUD-04)"
stop_srv

# ---- AUD-06: an unterminated RESP header is bounded, not an OOM --------------
#
# A `*` (or `$`) followed by an endless run of non-newline bytes used to be
# forever "incomplete", so the daemon doubled this connection's buffer on every
# read until malloc failed and die()d -- a fuzz input killing the shared fake.
# The parser now rejects an over-long unterminated header as a protocol error,
# so the connection is closed and, crucially, the DAEMON SURVIVES to serve the
# next client. Assert the survival: send garbage on one connection, then get a
# correct reply on a fresh one.
start_srv "$WORK/redis.backend"

# 300 bytes of `*xxxx...` with no newline: past the 64-byte header field, so the
# parser rejects it rather than asking for more.
garbage="*$(head -c 300 /dev/zero | tr '\0' 'x')"
talk "$PORT" "$garbage" >/dev/null 2>&1 || true

# The daemon must still be up: a normal get on a new connection is served.
# shellcheck disable=SC2016
out="$(talk "$PORT" '*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n' 2>/dev/null || true)"
# shellcheck disable=SC2016
if [ "$out" = "$(printf '$5\r\nworld\r')" ]; then st=0; else st=1; fi
ok "$st" "an unterminated RESP header closes the conn, not the daemon (AUD-06)"

# Process-level liveness, distinct from the functional get above: the daemon
# PROCESS must still exist (an OOM die() would have reaped it). The 256 KB
# MAX_CONN_INPUT ceiling is a deliberate backstop for a future unbounded path
# and is not separately reachable here -- the parser now rejects an over-long
# incomplete header before the buffer can approach it, which is the point.
if kill -0 "$SRV_PID" 2>/dev/null; then st=0; else st=1; fi
ok "$st" "the daemon process survives the over-long frame (AUD-06)"
stop_srv

# ---- AUD-05: fault applied is journalled; lie-with-no-length fails loud ------
#
# A happy-path fault (lie_bytes on a redis get, whose $len reply CAN carry a
# lie) must journal that it fired, so a scenario can assert the failure path it
# claims to test really ran instead of inferring it from a wire side effect.
cat >"$WORK/lie.backend" <<'EOF'
proto   redis
seed    hello  world
fault   on=get:1  action=lie_bytes  delta=2
EOF

start_srv "$WORK/lie.backend"
# shellcheck disable=SC2016
out="$(talk "$PORT" '*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n' 2>/dev/null || true)"

# The wire must carry the LIED length, not just a journal claim: a daemon that
# logged applied:true while sending the correct $5 would pass a journal-only
# assertion. delta=2 on a 5-byte value rewrites the declared length to 7.
# shellcheck disable=SC2016
if grep -q '\$7' <<<"$out"; then st=0; else st=1; fi
ok "$st" "an applied lie_bytes rewrites the declared length on the wire (AUD-05)"

if grep -q '"ev":"fault".*"action":"lie_bytes","applied":true' \
        "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "an applied lie_bytes is journalled applied:true (AUD-05)"
stop_srv

# lie_bytes on a redis SET replies +OK, which has no declared length to lie
# about. Load-time cannot know this (reply shape is proto+verb), so the script
# loads and the fault only fails at apply. Before AUD-05 the daemon sent the
# +OK UNTOUCHED -- the scenario ran the happy path under a name claiming a lie,
# a false green. Now it fails loud: the connection is reset (no +OK returns) and
# the journal records applied:false.
cat >"$WORK/lieset.backend" <<'EOF'
proto   redis
fault   on=set:1  action=lie_bytes  delta=2
EOF

start_srv "$WORK/lieset.backend"
# shellcheck disable=SC2016
out="$(talk "$PORT" '*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n' 2>/dev/null || true)"
if grep -q 'OK' <<<"$out"; then st=1; else st=0; fi
ok "$st" "lie_bytes on a length-less reply does NOT run the happy path (AUD-05)"

if grep -q '"ev":"fault".*"action":"lie_bytes","applied":false' \
        "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "an inapplicable lie_bytes is journalled applied:false (AUD-05)"
stop_srv

# AUD-05 (apply-time): truncate/drip/close_after on a reply-less command have
# nothing to perturb. memcached `quit` produces no reply, so a `truncate on=quit`
# would log applied:true and change nothing -- the same false green. It must fail
# loud instead (connection reset, journal applied:false).
cat >"$WORK/quittrunc.backend" <<'EOF'
proto   memcached
fault   on=quit:1  action=close_after  ms=50
EOF

start_srv "$WORK/quittrunc.backend"
talk "$PORT" 'quit\r\n' >/dev/null 2>&1 || true
if grep -q '"ev":"fault".*"on":"quit".*"applied":false' "$WORK/journal"; then
    st=0
else
    st=1
fi
ok "$st" "close_after on a reply-less command fails loud, not silent (AUD-05)"
stop_srv

# ---- a bad script must not boot ---------------------------------------------

cat >"$WORK/bad.backend" <<'EOF'
proto   memcached
fault   on=get:1  action=nonesuch
EOF

if ./fakesrv -script "$WORK/bad.backend" -listen 127.0.0.1:0 \
             -portfile "$WORK/badport" >/dev/null 2>&1; then
    ok 1 "a script with an unknown action refuses to boot"
else
    ok 0 "a script with an unknown action refuses to boot"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    exit 1
fi

[ "$failures" -eq 0 ]
