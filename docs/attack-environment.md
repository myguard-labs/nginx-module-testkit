# Attack surface: environmental hostility

**What it attacks:** the assumptions the code makes about the machine it runs on
rather than about the request it is handling — that the clock moves forward, that
`tolower('I')` is `'i'`, that a decimal point is a `.`, and that the worker only
makes the syscalls its author intended.

These bugs are invisible to every other surface in this repository, because
nothing about the request is wrong. The server answers 200, the deltas are zero,
and the code is still broken on a box whose locale, clock or seccomp policy
differs from the maintainer's.

## Locale hostility

The sharpest of the three, and the only one here with a proven finding behind it.

Two hostile locales are generated in CI and the prober's own self-test suite is
re-run under each:

| Locale | Hazard |
|---|---|
| `tr_TR.UTF-8` | dotless-i case folding |
| `de_DE.UTF-8` | comma decimal separator |

### The Turkish-i finding — confirmed, not theorised

glibc's `tr_TR.UTF-8` `LC_CTYPE` table makes `'I'` and `'i'` **fixed points** of
`tolower()`/`toupper()` — `tolower('I') == 'I'`, `toupper('i') == 'i'` — rather
than the C-locale mapping where they fold onto each other. glibc's
`strncasecmp()`/`strcasecmp()` consult that same table (POSIX permits
locale-aware folding here; this is *not* the ASCII-only guarantee an earlier
draft assumed — verified empirically).

The practical effect: `strncasecmp("ICE-Auth", "ice-auth", 8)` is `0` under the C
locale and non-zero under `tr_TR.UTF-8`. `http_has_header()` in `prober/http.c` is
a direct `strncasecmp()` consumer over raw response header bytes, so a header
whose name or value differs from the needle only in `I`/`i` casing silently stops
matching under this locale — every `expect header~...` assertion quietly turns
into a no-op.

`prober/http_locale_check.c` is the dedicated regression case. It is named that
way **specifically to opt out** of `test.sh`'s `*_test.c` discovery, because it
only means anything when run standalone under `LC_ALL=tr_TR.UTF-8`.

### The comma-decimal finding

`json_test` parses fractional numbers (`1.5`, `1E-007`, …). With a plain
locale-honoring `strtod()` those are rejected as `malformed number` under
`de_DE.UTF-8`, because the radix character is `,` there. `json_strtod()`'s
C-locale pin is what keeps it green — and the JSON reader is the oracle every
assertion in the whole suite runs through, so a lax reader here makes the entire
suite unable to fail.

Mutation proof, verified by hand: reverting `json_strtod()` to a plain `strtod()`
in `json.c` fails **this step** while every non-locale job stays green. That is
the signature shape of a locale bug — invisible to ordinary CI.

### A near-miss worth copying

An earlier verification pass ran `locale-gen tr_TR.UTF-8` without first
uncommenting `tr_TR.UTF-8 UTF-8` in `/etc/locale.gen`. `locale-gen` exits **0**
and regenerates whatever is already listed, so the locale was never created and
the test ran under the C locale, passing for the wrong reason. The CI job
therefore verifies `locale -a` lists both locales and fails *there*, rather than
three steps later as a confusing test failure.

## Syscall surface (`scenarios/syscall-allowlist`)

Every other scenario asserts on what the server **returns**. This one asserts on
**how it got there**: the set of syscalls the worker issues while answering a
burst of ordinary requests. A module that quietly starts calling `getrandom`,
opening a file, spawning a socket or exec-ing a helper changes that set, and a
consumer should have to acknowledge the new capability by editing
`baseline.syscalls` rather than have it slip in unremarked.

**Instrument.** `strace -f -c` *attaches* to the already-running worker via
ptrace — no rebuild, no `LD_PRELOAD` — counts syscalls across a fixed burst of
probe requests, then detaches. The union of names in the `-c` summary is the
observed set.

**The gate is one-directional.** Every observed name must appear in
`baseline.syscalls`, or the run is red. A baseline name *not* observed is fine —
it is an allowlist, not a fingerprint — so it does not flake on a kernel that
satisfies an epoll from cache or coalesces a write.

**Why attach rather than wrap the boot.** Wrapping the boot in strace folds
nginx's startup syscalls (open the conf, the logs, the shared libraries, map
them) into the set: a large, version-variable surface with nothing to do with the
request path under test. Attaching after boot isolates exactly the per-request
surface, which is both the stable thing to baseline and the thing a module
actually influences.

**Why a driver rather than a `.rule`.** The prober speaks HTTP; it has no notion
of attaching a tracer to the server it is probing or diffing a syscall set. This
is server-side introspection the rule DSL cannot express.

**Cross-version stability.** The observed set on a bare request path is small and
stable across nginx mainline, stable, and angie: `accept4`/`close` for the
connection, `epoll_ctl`/`epoll_wait` for readiness, `recvfrom` for the request,
`write`/`writev` for the response, `setsockopt` for per-connection options. The
near neighbours a different kernel or libc can substitute (`accept`,
`epoll_pwait`, `recv`, `read`, `send`/`sendto`) are pre-listed in
`baseline.syscalls`, so a benign substitution is not mistaken for a new
capability.

**The budget (assertion 3).** The set gate above is one-directional and cannot
see a module that opens one file of its OWN per request: `openat` is necessarily
allowlisted, because the reference probe walks `/proc/self/fd` on every request.
Only a COUNT ceiling closes that, so assertion 3 budgets `openat+open <= 3` and
`accept4+accept <= 1` per SERVED response.

Three properties of that gate are load-bearing, each closing a way it could have
reported green on the behaviour it exists to catch:

- **Families, not names.** `open` and `accept` are separately allowlisted libc
  near-neighbours, so a module reaching the kernel through `syscall(SYS_open,
  ...)` leaves `openat` at its baseline and a name-wise ceiling never moves.
- **The denominator is responses served BY THE TRACED WORKER.** `strace` attaches
  to one pid, and `-f` does not follow a replacement worker (the master forks it,
  not the tracee). Counting any status line credits responses whose syscalls were
  never traced, inflating the denominator while the numerator holds only the
  tracee's calls.
- **An absent family is RED, never zero.** If no member of a budgeted family
  appears at all, the capture is not what the code thinks it is, and answering 0
  gives the most comfortable possible answer to a question that could not be
  evaluated.

`readlink` and `getdents64` are deliberately NOT budgeted: both scale with the
worker's FD population rather than the request count, so a ceiling over either is
a flake generator.

## Clock hostility (`scenarios/clock-jump`)

**The attack:** step the **wall clock** backwards by an hour under a running
worker and require that nothing measuring elapsed time notices. This is the
NTP-correction shape — a machine that boots with a wrong clock and syncs, a leap
second, a VM resumed from a snapshot. A module computing an interval from
`CLOCK_REALTIME` (a ban that expires, a rate-limit window, a cache TTL) has that
interval silently extended by the size of the step: nothing logs, nothing errors,
and a one-second timer sits an hour in the future.

### What it was until 2026-07-29, and why it is recorded

The scenario shipped an `nginx.conf` and a four-case `clock-jump.rule` and
nothing else — no `env`, no `LD_PRELOAD`, no driver. libfaketime appeared nowhere
in the tree. The four cases sent byte-identical requests asserting `status=200`
and `delta fds == 0`, under names ("request after clock jump", "request after
negative clock jump") describing an event that never occurred. It passed reliably
for having tested nothing — the same defect that got `zone-exhaustion` deleted the
day before. It was rebuilt rather than deleted because the attack it *named* is
real.

### The instrument, and the trap inside it

libfaketime is `LD_PRELOAD`ed with a **timestamp file** (`env`), so the driver
steps the clock by writing a file rather than by booting the server in the past.

Two things make it work, and each was a dead end first:

**1. nginx rebuilds its workers' environment.** `ngx_set_environment()` constructs
a fresh environ from the `env` directives alone, so a worker inherits only what
the config names. The library stays *mapped* in the forked worker — measured, 7
`libfaketime` entries in `/proc/<worker>/maps` — but with `FAKETIME_TIMESTAMP_FILE`
stripped it has nothing to read and reports the real clock. The symptom is a
server that boots cleanly, serves everything, and ignores every step: a −1h step
moved the worker's `Date` header *forward* by one second. The fix is four `env`
directives in `nginx.conf`. **This is why the original stub could never have
worked even with a driver bolted on.**

**2. libfaketime fakes `CLOCK_MONOTONIC` by default.** Measured both ways:

| Setting | `CLOCK_MONOTONIC` under a −3600 step | Parked keepalive connection |
|---|---|---|
| default | stepped too (unpreloaded ~90183 vs faked ~1785276494) | **never closes** (>12 s) |
| `FAKETIME_DONT_FAKE_MONOTONIC=1` | untouched (~90191) | closes in **1.70 s** |

A backward-stepping *monotonic* clock is not something nginx is required to
survive — the kernel guarantees it cannot happen — so asserting against one
measures libfaketime rather than the server. The scenario therefore sets
`FAKETIME_DONT_FAKE_MONOTONIC=1` and asserts the second row. The first row then
becomes the scenario's own negative control.

### The oracles

| | Assertion |
|---|---|
| **O1** | The step actually landed, read from the server's own `Date` header rather than assumed from having written the file. Asserted **first**, because a step that never reached the worker leaves every other oracle passing against an unstepped clock — the exact vacuous shape this is a rebuild of |
| **O2** | A keepalive connection parked *before* the step still closes on its ~2 s timeout *after* it. Holds iff the expiry is computed from a monotonic source |
| **O3** | The worker keeps its pid — no crash and respawn |
| **O4** | `cycle_used` is unchanged across the stepped clock — the harness's standard resource oracle |

### Non-vacuity, as run

Both controls were executed, and each reds **exactly one** oracle:

- **Delete `FAKETIME_DONT_FAKE_MONOTONIC` from `env`** → `not ok 2` only ("the
  parked connection did not close within 8s of a -3600s step"), exit 1, with O1,
  O3 and O4 green. Proves O2 reads the *timer* and not merely the clock.
- **Delete `env FAKETIME_TIMESTAMP_FILE;` from `nginx.conf`** (the historical
  bug) → `not ok 1` only ("expected the server's clock to move back ~3600s, saw
  0s"), exit 1, with O2, O3, O4 green.

That second result is also the argument for O1's existence: under it O2 still
passes, so without O1 an unstepped clock would take the whole scenario green.

One hazard found while building it and worth copying: the timestamp file must be
written **atomically** (temp + `rename`). `FAKETIME_NO_CACHE=1` makes the library
re-read it on every clock call, so a plain truncate-and-write lets a reader catch
it half-written — `libfaketime: In parse_ft_string(), failed to parse FAKETIME
timestamp` on stderr, and a silent fallback to the real clock.

### What it does not claim

The probe document exposes no time field, so this cannot see a *module's* internal
timer directly; it asserts on nginx's own keepalive expiry as the observable
proxy. A module keeping its own `CLOCK_REALTIME` deadline is caught only if the
consumer exposes it via `zone_render` and adds a case. That is the honest limit of
a generic clock oracle.

`prober/http.c` and `prober/fakesrv.c` both time their deadlines with
`prober_monotonic_ms()` (`prober/util.c`) for the same reason: `CLOCK_MONOTONIC`,
and a 64-bit millisecond count so a host up 24.9 days does not wrap a deadline
negative under `-m32`. One implementation rather than two, because the two
hand-written copies it replaced had already drifted -- only one carried the
width fix.

## How this class produces a green run that proves nothing

- **A locale that was never generated.** `locale-gen` exits 0 regardless. Assert
  `locale -a` before trusting the run.
- **A locale test folded into the ordinary suite.** It would run under the C
  locale on every other job and prove nothing there; `http_locale_check.c` opts
  out of discovery by name for exactly that reason.
- **A syscall gate that is a fingerprint rather than an allowlist.** Requiring the
  observed set to *equal* the baseline flakes on benign kernel substitutions, gets
  widened, and stops failing.
- **A syscall trace that includes boot.** The startup surface swamps the
  per-request one and drifts with every nginx version.
- **A scenario named for an attack it does not perform.** `clock-jump`, above.

## See also

- [attack-leak-pressure.md](attack-leak-pressure.md) — the `delta` oracles these scenarios also carry
- [COVERAGE.md](COVERAGE.md) — the control-mutation rule that `clock-jump` currently fails
- [../README.md](../README.md#the-test-that-decides-it-for-scenarios) — the in-scope test for a scenario
