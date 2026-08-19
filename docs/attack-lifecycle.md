# Attack surface: lifecycle events

**What it attacks:** reload, binary upgrade, worker death, and signal storms
landing mid-transfer.

**Why this is where the bugs are.** A reload tears down a cycle and builds a new
one, and every unbalanced allocation becomes visible at exactly that moment. A
module that acquires something per cycle and never releases it fails *silently*:
nothing errors, nothing logs, and the server grows one cycle's worth on every
`SIGHUP` for as long as it runs. Under load the same event exercises paths an
idle reload never touches — request cleanup on the retiring worker, and the
listen-socket handover while it is being `accept()`ed on.

Almost nobody tests this, because from outside a reload looks like a reload.

## The primitives a driver gets

Lifecycle work happens in a scenario `driver.sh`, which runs with the server
already booted and holds the master pid, so it can interleave prober runs with
signals. `ci/prober/lib.sh` gives it:

| Helper | What it settles |
|---|---|
| `prober_probe_body` | one `/__probe` read, with the retry and timeout discipline in one place |
| `prober_probe_pid` | that body's worker pid |
| `prober_probe_field BODY NAME` | any flat or nested-leaf numeric field — **returns nonzero for an absent field rather than an empty string**, so a lost counter cannot be read as a zero delta |
| `prober_signal_wait` | the signal was absorbed: a new worker answers |
| `prober_drain_wait` | the previous cycle is *gone*: the master is back to its configured worker count |
| `prober_config_wait` | a given `config_generation` reads `STREAK` times consecutively, each on a fresh connection |

**`prober_signal_wait` and `prober_drain_wait` are not interchangeable, and
measuring between them is what makes a reload scenario flaky.** When
`signal_wait` returns, the old worker is still alive and both it and the master
hold handover channel descriptors that belong to no cycle. The same healthy
series measured 10, 11 and 12 fds on the same box in that window — the exact
shape of a scenario that only fails on a loaded runner. Take every snapshot after
`drain_wait`.

## Reload

### `reload-cycle` — the accounting

Reloads eight times and asserts that reload *K* costs exactly what reload 1 did.

- **The comparison is exact, not banded.** Every cycle is built by parsing the
  same config with the same binary, so `cycle_used` / `cycle_blocks` /
  `cycle_large` and the worker's `fds` are identical across a healthy series
  (measured on nginx 1.29.0, nginx 1.31.3 and angie 1.12.0). A band would be the
  weaker claim for no gain.
- **The master is asserted separately**, because worker-side counters can only
  ever see the cycle the worker was forked into. `/proc/<master>/fd` is the sharp
  oracle — a leaked listening socket or old-cycle descriptor is countable and
  deterministic. `/proc/<master>/statm` is a deliberately coarse backstop, since
  an allocator that does not return pages to the OS hides a small leak from RSS
  entirely. Both skip **visibly** where `/proc` is unreadable, and the RSS one
  skips on sanitized builds.
- **A worker that never exits is itself the leak**, so the drain is asserted as a
  result and not merely used as a precondition.

Controls, both run: a sub-pagesize allocation from the cycle pool that grows with
the cycle count reds only the `cycle_used` comparison — a page-sized one lands on
the large list instead, which is why the scenario asserts all three pool counters.
A descriptor opened per config load reds the worker `fds` comparison and the
master descriptor count together.

### `reload-config-version` — is it running the config you just loaded?

`reload-cycle` answers "did a new cycle appear, and did the old one go away".
Neither of its oracles can say *which configuration* the answering worker runs,
and both hold perfectly while the server still serves the old one:

- **A reload nginx rejected.** A config that fails to parse or bind leaves the
  running cycle exactly as it was: `[emerg]` in the log, nothing exits non-zero,
  the old worker keeps answering. This is negative control A in the driver, and
  with it planted every other oracle in the scenario stays **green** while all
  five reloads are silently rejected.
- **Overlapping reloads.** A second `SIGHUP` arriving while the first is still
  being absorbed leaves more than one new cycle in flight.

The oracle is `config_generation`, a counter the master bumps once per config
**load** and every worker of that cycle inherits through `fork()`.
`prober_config_wait` requires the new value `STREAK` times consecutively, each on
a fresh connection, so a single read that landed on the new worker while the old
one is still accepting cannot settle it. The streak is the probabilistic half;
`drain_wait` alongside it is the deterministic half. Neither replaces the other.

It is deliberately **not** angie's `cycle->generation`: stock nginx has no such
field, so a gate built on it would be silently absent on every nginx leg. The
harness keeps its own counter — a plain process global, safe because the only
writer is the master, during config load, strictly before it forks the workers
that read it. It does not survive a binary upgrade (`execve` resets the image),
which is correct for a `SIGHUP` gate.

A counter that only asserts about itself would be the classic vacuous gate, so
each reload **rewrites the rendered conf** (a `marker=<n>` in the `/` body) and
the driver requires the served body to carry the new marker before accepting the
generation as meaningful. Negative control B neutralises the rewrite: the
generation still advances — reloading an identical config is still a config load —
so the generation oracle stays green while the marker oracle reds, proving the two
are not restating each other.

### `reload-soak` — 100 reloads under concurrent traffic

The higher count turns a per-cycle leak from a handful of ambiguous steps into an
unmistakable climb, and background traffic keeps requests in flight across every
signal.

The pool oracles are `reload-cycle`'s, exact-equal across the whole series. The
one deliberate difference: the worker **fd count is not** in the exact-equal set
here, because under load a background connection can be mid-flight on the freshly
drained worker at snapshot time (10 vs 11 fds on a few of the 100 reloads), so an
exact assertion would flake on one in-flight request rather than a leak. A leaked
descriptor still climbs the *master* fd count, which is the oracle that catches
it.

The scenario adds one oracle of its own, and it is what gives "under load" its
teeth: the background stream must record **no failed request**, and be non-empty.
A reload that dropped a connection or refused `accept()` during the handover
shows up there and nowhere else.

### `reload-mid-fault` — a reload landing on an already-failing request

Every reload scenario above proves a reload absorbs *clean* work in flight;
`fault-matrix` proves the upstream error branches clean up correctly, but only at
an idle moment. The combination is where an unbalanced allocation or a leaked
upstream descriptor becomes visible: `ngx_http_upstream_finalize_request`'s
error-cleanup path and the reload's own worker-drain teardown running concurrently
on the same worker, instead of at two separate idle moments.

The fault is a `drip` paced slower than a pinned `memcached_read_timeout` (400 ms
between 4-byte chunks against a 150 ms budget), so nginx's own upstream read
genuinely times out mid-transfer — a real failure, not a slow-but-clean transfer.
`rst`/`truncate`/`lie_bytes` were considered and rejected: each sends its reply in
one shot, so none can hold a connection open long enough to straddle a `SIGHUP`.

A single fixed get ordinal (`on=get:2`, after one clean warmup get settles the
worker) arms it, so which fault fires never depends on timing; only the
read-timeout's real-time race is time-based, sized with a 2.7× margin.

Oracles: the held request must NOT complete as a clean 200 (the anti-vacuity check
for this scenario's own failure mode); the reload must be absorbed while it is in
flight; the new worker's counters must be allocation-neutral across an extra clean
request taken after *both* the fault's cleanup and the reload's drain complete;
no worker died by signal; the upstream saw the held get exactly once (finalized,
not retried).

Note the technique in that third oracle — **two quiescent post-drain snapshots**,
not a pre-fault-vs-post-reload compare. The direct comparison reads a reproducible
~3.5 kB `cycle_used` gap that is the "first post-reload fork carries a one-off"
artifact `hup-storm-mid-transfer` documents, not a leak.

Why the probe and not a `.t` file: a worker that leaks the upstream fd or a
cycle-pool block *specifically* on this branch still returns a plausible 502/504
and a plausible "worker process ... exiting" log line. Nothing in a `.t` file's
assertion surface tells that apart from correct cleanup.

### Others in this family

`hup-storm-mid-transfer` (signals arriving during a transfer),
`reload-compressing`, `reload-idle-keepalive`, `reload-mid-upload`,
`reload-worker-shutdown-timeout`, `backend-reload-inflight`.

## Worker death

`worker-death` is the mirror image of the reload scenarios: it `SIGKILL`s the
single worker while it is serving the probe, lets the master respawn it, and
asserts the death was **contained**.

The load-bearing oracle is the non-vacuity control. A crash-respawned worker
keeps its master's pid — *measured*, not assumed — so "a different pid answers"
and "still a child of the same master" are both satisfied by a respawn and cannot
tell a crash from a reload. **Without a positive assertion that a worker exited
on signal 9, every other oracle passes on a server that was never killed at all.**
That assertion reads the `exited on signal 9` line out of the error log, separately
from any pid oracle, because the process-identity oracles are blind to it. A
companion oracle then requires **no other** signal death — no `SIGSEGV`/`SIGABRT`/
`SIGBUS`, no second signal-9 — because a contained kill leaves exactly the one
line we caused.

The rest proves the master rode it out: the replacement's pool counters must
**equal** the killed worker's (a fresh fork of the same master parsing an
already-loaded config — no reparse, so identical), the master's descriptor count
must be flat (it must close the dead worker's channel fd), the replacement's
`ppid` must still be the original master, and a strict prober case proves the
replacement serves a clean 200.

The kill's `[alert]` line is exempted via the scenario's `env`
(`PROBER_ALLOW_LOG`), pinned to `signal 9` only, so a fault signal still reds the
log scrape as a backstop.

## Binary upgrade (`SIGUSR2`)

`usr2-state-machine` observes the master-generation state machine directly. A
`SIGUSR2` execs a **new master** from the old master's inherited fd table, so two
generations coexist for a window: the old master renames its pidfile to
`nginx.pid.oldbin`, the new master writes a fresh `nginx.pid`, both naming a
distinct live process.

The headline oracle is the listen socket. Because the new master execs from the
inherited fd table, its listening socket is the *same kernel socket object*, not a
fresh `bind()`. The driver reads the inode behind the master's listening fd from
`/proc/<master>/fd` (cross-checked against a `LISTEN` state in `/proc/net/tcp`)
and asserts it is **identical** on the old master, the new master, and the new
master after the old one is QUIT. A re-bind would change the inode and would race
a `bind()` against the still-held socket. The port must also keep answering across
every transition — a surviving socket is meaningless with a refused window.
Linux-only; skipped visibly where `/proc` fd links are unreadable.

The `.oldbin` teardown oracle then retires the old master (`WINCH` to drain,
`QUIT` to stop, targeting the pid from `nginx.pid.oldbin`) and requires
`nginx.pid.oldbin` to **disappear** while `nginx.pid` still holds the new master.
A lingering `.oldbin` is a stuck upgrade.

It runs under `PROBER_DAEMON_MODE=on`, because USR2 is silently dropped under
`daemon off` — the boot contract demands a daemonized master tracked by its
pidfile. That incompatibility is also why USR2 is deliberately out of
`stateful-property-fuzz`'s step alphabet; the USR2 lifecycle is owned by
`usr2-state-machine`, `usr2-mid-transfer` and `backend-usr2-keepalive`
(the orthogonal half: a new-exec worker reconnecting an upstream keepalive pool it
did not inherit).

## Lifecycle events inside a generated sequence

`stateful-property-fuzz` interleaves `SIGHUP` and `SIGKILL` steps with request
steps, and after every lifecycle event runs five checkpoint oracles:

- **C1 lineage** — the answering worker is still a child of the *original* master.
- **C2 no forbidden death** — no `SIGSEGV`/`SIGABRT`/`SIGBUS` exit, and the
  `signal 9` count equals exactly the number of kills this run sent. An unsent
  kill or a cascade reds. This is `worker-death`'s control, folded into every kill
  step.
- **C3 cycle-pool settlement — generation-scoped.** A kill re-forks the same cycle
  so the footprint must match exactly; a reload builds a new cycle so it
  re-baselines, but must not climb past a running high-water mark. A per-reload
  leak grows monotonically and breaches it.
- **C4 generation coherence** — after a reload `config_generation` must strictly
  advance and settle (the reload was *absorbed*, not rejected-with-old-cycle-kept);
  after a kill it must hold, since a bump would mean a spurious reload.
- **C5 zone/probe coherence** — the probe still parses and reports the expected
  `zone.present` after the event.

Each has a documented driver mutation as its control.

## How this class produces a green run that proves nothing

- **A rejected reload read as an absorbed one.** Negative control A above: every
  process-shaped oracle stays green while the old config keeps serving. Assert
  `config_generation` *and* an observable that depends on the new config.
- **A respawn indistinguishable from a reload.** Without the positive signal-9
  assertion, `worker-death` passes on a server that was never killed.
- **A snapshot taken between `signal_wait` and `drain_wait`.** Handover
  descriptors belong to no cycle; the reading is unstable and the scenario becomes
  a loaded-runner flake.
- **A pre-vs-post compare across a reload.** The first post-reload fork carries a
  reproducible one-off (~3.5 kB `cycle_used`). Compare two quiescent post-drain
  snapshots instead.
- **An exact fd assertion under load.** One in-flight request reds it. Move the
  claim to the master fd count.
- **A generation counter asserting only about itself.** Negative control B: pair
  it with a served marker.

## See also

- [attack-leak-pressure.md](attack-leak-pressure.md) — the counters every oracle here reads
- [attack-fault-injection.md](attack-fault-injection.md) — the fault half of `reload-mid-fault`
- [attack-hostile-input.md](attack-hostile-input.md) — the generator `stateful-property-fuzz` reuses for its request steps
