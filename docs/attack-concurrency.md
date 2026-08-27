# Attack surface: concurrency

**What it attacks:** state that is correct when one request owns the worker and
wrong when several do — a module allocating per accepted connection but freeing
per retired *request*, a shared-memory structure keyed on the assumption that the
current connection is the only live one, a per-worker cache that two workers
disagree about.

**Why the sequential suite cannot reach it.** A sequential prober retires each
request before starting the next, so a race needing two requests inside the same
worker at the same instant is simply unreachable. Every scenario in this
repository was sequential until the `concurrent` directive landed.

## `concurrent N` — N requests in flight

```text
name        twenty overlapping requests leave the worker exactly as one does
send        GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
concurrent  20
delta       fds == 0
```

Every connection is opened and every request written before *any* response is
read. The before/after snapshots bracket the entire fan, so the case's existing
`delta` oracles assert that N overlapping requests leave the worker in the state N
sequential ones would: no extra descriptor, no pool growth, no slab page. Every
leg is also checked against the case's own `expect` assertions, so a leg answered
differently from the others is a finding even when the aggregate delta is clean; a
failure names the leg (`concurrent leg 3/20: ...`).

The count must be `2..64`. **The floor is 2, not 1** — `concurrent 1` is the
ordinary path in costume, and accepting it would let a rule file claim a
concurrency test that asserts nothing about overlap.

### What the directive guarantees, precisely

All N requests are written before any response is *consumed*. That is a
**client-side ordering property**, and it is what the self-tests prove.

It is **not** the same as "N request lifetimes overlap inside the worker."
Against a fast handler with a small response, nginx may process, answer and
finalize leg 0 while the prober is still writing leg 1, and leaving that response
unread in the kernel buffer does not hold the worker's request open. The overlap
is *made likely*, not enforced.

A case that needs a proven simultaneous peak has to observe it from inside the
module — an active-request counter in the probe document, asserted to reach N —
not infer it from this directive. That is a module-side capability. **Do not add
an oracle that assumes a guaranteed peak:** it would pass for the wrong reason on
a fast handler and red spuriously on a slow one.

### Why a fan is worth running given that limit

Even without a guaranteed peak, the fan drives the accept path with a burst
instead of a trickle, and every leg's response is left unread in the kernel
buffer while the remaining legs are written. Both are shapes the sequential suite
never produces. A module that allocates per accepted connection and frees per
retired request, or that keys state on a connection it assumes is the only live
one, drifts here and nowhere else.

### Combinations rejected at load time

Four, each rejected rather than silently resolved:

- **No `delta` or `probe`** — the snapshots are the only thing that observes the
  overlap, so a fan without one pays for N connections and asserts exactly what a
  single request already asserted.
- **`block`** — a pipeline is an *ordered* sequence on *one* connection. "N
  pipelines at once" is coherent but much larger, so the pair is refused rather
  than resolved toward either reading.
- **`abort`, `hold`, `expect_idle`** — each ends its connection without ever
  reading a response, so a fan carrying one would collect nothing to assert
  against.
- **`expect_close_within`, `recv_slow`** — the fan drains its legs in order and
  blocking, so an earlier leg's read time is charged to every later leg's clock. A
  prompt final leg would be reported as a timeout purely as an artifact.

## `open_conns N` — the opposite half

`open_conns` parks N **bare** connections that never send anything, accepted by
the worker but carrying no request, held open across this case's probe read:

```text
name        a hundred idle connections show up in the worker's connection count
send        GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
open_conns  100
probe       connections.free <= 28
```

Do not confuse the two: `open_conns` parks, `concurrent` sends and collects.

The connections open **after** the case's own exchange, are held only for the
instant the snapshot is taken, and close before the `pid_may_change` and `delta`
reads that follow — so those still see a clean count, and a case may pair
`open_conns` with a delta on some other field without the parked sockets skewing
it. It is case-level, not per-block: on a pipeline case it lands on the case,
since the connection count is a property of the worker rather than of one
exchange. Count `1..512`. A case setting it but carrying no `probe` assertion is
rejected at load time, because idle connections nothing reads are a test that
asserts nothing.

**Set `multi_accept on` in the scenario conf.** Whether all N connections are
counted by probe time depends on how fast the worker drains its accept queue; with
one connection accepted per event the count lags the sockets this process has
opened, and the assertion becomes timing-dependent.

## `scenarios/concurrent-fan` — the directive against a real worker

`concurrent N` is proven at the unit level against `spawn_barrier` in
`ci/prober/http_test.c`, a fixture that withholds every reply until all N requests
have arrived and so pins the client-side write ordering exactly. What no
self-test does is run the directive against a **real** worker: the fixture
exercises none of nginx's accept path, connection slots, cycle pool or descriptor
accounting. This scenario is the directive's only live-worker coverage.

It asserts resource neutrality under a fan, which is an honest reading of what the
before/after snapshots bracket. It deliberately asserts nothing about a
simultaneous peak, for the reason above.

## `scenarios/backpressure` — a reader that will not drain

The write-side counterpart: a response too large to leave in one write must still
be delivered whole, and the connections it parked must come back.

`rules/stock/slow-reader.rule` already pairs `so_rcvbuf` with `recv_slow` and
asserts `delta fds == 0` per case, so a connection leaked by one slow reader is
caught. Two things it cannot do, both environmental rather than client behaviour:

1. **The stock rule probes whatever the consumer's `/__probe` returns** — a
   snapshot document, small enough that the kernel usually absorbs it whole
   however tight the client's window is. When that happens the server never
   blocks, the case still returns 200, and the rule passes having exercised
   nothing. This scenario supplies its own ~1.7 kB `/bulk` location and turns off
   the coalescing that would let even that leave in one `writev` —
   `postpone_output 0`, small `output_buffers`, `sendfile off`, `gzip off`.
2. **Per-case `delta` is case-local.** A connection parked on a blocked write and
   never reclaimed — one per stalled response — satisfies every `delta fds == 0`
   while the worker bleeds an fd per request. Same limitation `conn-delta`
   documents, same answer: run the shapes back to back, then close on an absolute
   floor.

## `scenarios/multi-worker`

`worker_processes 4`, against the harness's own same-master pid oracle. It was
unrunnable from the day it was written until `PROBER_ALLOW_MULTIWORKER` was added
as an explicit opt-in — the oracle assumes a single worker answers, and every
other scenario keeps `worker_processes 1` for exactly that reason.

## `fanout N [min_workers]`, `quiesce`, `zone_invariant` — cross-process shm coherence

**What this class attacks.** Every oracle above lives inside one worker's
address space: `concurrent` overlaps requests on the worker that accepts them,
`open_conns` counts one worker's descriptor table. Neither can see a shared
memory zone read from *two different worker processes*, which is exactly the
state a module keeps when it declares an shm zone — the same bytes, `mmap`ed
before `fork()`, guarded by `ngx_shmtx` rather than a `pthread_mutex`. A counter
that one worker leaks, a view that has diverged between two workers, an
`ngx_uint_t` decremented past zero into a huge value — none of these are
reachable by sending traffic to a single worker and reading its own answer
back, however many requests that worker sees.

**Why the sequential/single-worker suite structurally cannot reach it.** Every
scenario above this section keeps `worker_processes 1` on purpose — the
same-worker pid oracle every other case relies on assumes it. A single worker
has no second view to diverge from; a zone read twice from the same process is
trivially coherent with itself no matter what the module does. Reaching this
class requires *both* several live workers *and* a client with no way to choose
which one answers a given connection, which is why the directives below exist
as their own layer rather than as options on `concurrent`.

### `fanout N [min_workers]`

Sends `N` requests as `N` separate fresh connections and collects the
answering pid of each, exactly like `concurrent` collects timing but for
identity instead. `N` is `2..64`, same floor and the same reasoning as
`concurrent`: `fanout 1` is the ordinary path in costume, and permitting it
would let a rule file claim a cross-worker test while only ever reaching one
worker.

`min_workers` defaults to 2 rather than 1. Worker sampling is probabilistic —
nothing lets a client pick which worker accepts a connection — so a run *can*
legitimately land every leg on one worker. A default of 1 would let the entire
lens pass having sampled a single worker `N` times, a coverage claim it never
earned; requiring 2 is what turns incomplete coverage into a failure instead of
a quiet pass. `min_workers` must be `2..N`.

**Rejected at load time:**

- **`fanout` outside `2..64`.** Same vacuous-gate reasoning as `concurrent`'s
  floor.
- **`fanout` combined with `block`.** A pipeline is an ordered sequence on
  *one* connection, so it reaches exactly one worker; a fanout over it would
  assert cross-worker agreement having sampled a single worker.
- **`fanout` combined with `concurrent`.** Both drive the request count for the
  case; the pair is refused rather than resolved toward either reading.
- **`fanout` with no `probe`/`delta`/`zone_invariant`.** Nothing would read the
  per-leg identities the fan exists to collect.

### `quiesce <path> [timeout_ms]`

Polls the named probe field until two consecutive reads agree, or
`timeout_ms` elapses. **Expiry FAILS, never degrades to a skip or a pass** —
the directive's entire value is that a wait is *stated and verified*, not
guessed, and an oracle that quietly moves on after a timeout would put the
exact unstated-timing trap this file warns about (an oracle assuming a
guaranteed peak) back into the harness through a different door. `timeout_ms`
defaults to `QUIESCE_DEFAULT_MS` (2000) and is bounded `1..QUIESCE_MAX_MS`
(30000); the floor is 1, not 0, because `quiesce <path> 0` would expire before
the first pair of readings could even be compared, failing every case that
carries it for a reason unrelated to the code under test.

**Rejected at load time:**

- **A case carrying `quiesce` but no `probe`/`delta`/`probe_baseline`/
  `zone_invariant`.** A quiesce nothing observes is a sleep, not an oracle.
- **`timeout_ms` outside `1..QUIESCE_MAX_MS`**, or a value that fails to parse
  as a whole argument (a silently-truncated numeric prefix would wait a
  different time than the file states).
- **`quiesce` set twice on one case.**

### `zone_invariant <coherent|at_rest|monotonic> <field> [<op> <value>]`

Judges the shm zone as read from every worker a `fanout` reached, against one
of three forms:

- **`coherent <field>`** — identical across every answering pid, at rest.
  COR-class divergence: two workers holding different views of what should be
  the same bytes.
- **`at_rest <field> == N`** (any of `== != < <= > >=`) — a shared counter must
  land on a stated value once traffic has quiesced. This is the direct oracle
  for a counter that a module increments and decrements across requests and
  which must return to a baseline (an inflight counter back to 0).
- **`monotonic <field>`** — never decreases across the fanout's readings
  (e.g. `slab_reqs`, a cumulative allocation count).

Every form is judged on readings taken by a **separate sweep after `quiesce`
completes**, never on the coverage sweep's own interleaved snapshots — the
coverage sweep's readings are mid-flight by construction, and judging an
at-rest invariant against one of them would ask whether a counter had settled
while the case was still driving it.

`at_rest`'s comparison bounds itself against `QUIESCE_SANE_MAX`
(2^31 - 2) on the counter side: an `ngx_uint_t` decremented past zero wraps to
a huge value, and an unbounded compare would let that wrapped value satisfy a
loose enough ceiling. `at_rest` is the form that catches the underflow class
directly, by refusing to treat the wrapped reading as a legitimate large
number.

**Rejected at load time:**

- **A case carrying `zone_invariant` with no `fanout`.** A single snapshot is
  trivially coherent with itself, and a monotonic or at-rest read of one
  sample proves nothing about a shared counter.
- **`coherent`/`monotonic` carrying a trailing `<op> <value>`.** Refused
  rather than silently ignored — dropping it would leave a rule file believing
  a bound is enforced that the harness never applies.
- **An unrecognised form**, or `at_rest` missing its `<op> <value>` pair.
- **`at_rest` using `~`** (a substring test) — the field is a counter, not
  text; a substring comparison against a number is a rule-file mistake caught
  at the line that wrote it rather than a comparison that happens to pass.

### What this combination guarantees, precisely

**IS**: a detector of race *consequences* — a leaked counter, a diverged view
between two workers, an underflow that wrapped. A green `zone_invariant` means
none of those consequences showed up in the readings this run actually took.

**IS NOT**: a race detector. It never observes an interleaving, only a broken
invariant afterwards, and it is not a substitute for one. Helgrind and TSan
model pthread races inside *one* address space; nginx workers are `fork()`ed
processes sharing an `mmap` under `ngx_shmtx`, an atomic-CAS spinlock rather
than a `pthread_mutex` — neither tool can see this race class, and this lens
does not see theirs. Claiming this proves the code race-free, rather than
"no observed consequence in the sample taken," recreates the exact
vacuous-green problem the lens exists to replace.

**Known limit**: worker sampling is probabilistic. A `fanout` cannot force a
particular worker to answer, which is why its coverage oracle fails loudly on
incomplete spread rather than accepting whichever pids happened to show up.

## `scenarios/shm-coherence` — the directive set against real workers

`worker_processes 4` plus `PROBER_ALLOW_MULTIWORKER=1` in `./env` — the two
must stay together, same requirement `scenarios/multi-worker` states. Every
other test of `fanout`, `quiesce` and `zone_invariant` is a unit test over
synthetic readings: pure functions, no master, no fork, no accept path, no
mapped zone. This scenario is where those directives meet four real workers —
that a `fanout` leg really is answered by a worker whose pid the probe can
read, that consecutive fresh connections really do land on different workers,
and that the coverage oracle really does count them.

It deliberately carries no `zone_invariant` line, in any of the three forms.
The reference module never allocates from the shm slab on a request path
(measured live, nginx 1.31.4, four workers: `zone.slab_reqs` stays 0 across a
full sweep), so against a zone nothing mutates, every reading is the same
number and all three forms would be satisfied by a constant sequence no defect
could falsify — green for a reason unrelated to whether the comparisons are
correct. This holds equally for all three forms; none of `coherent`, `at_rest`
or `monotonic` gets closer to a live negative control than the others against
this module, and no field on `zone.*` gives one a way around it —
`connections.free` resets to baseline between fanout legs rather than
accumulating a fall, and `open_conns`'s held connections do not exist yet when
`zone_invariant` takes its readings (see `collect_zone_readings` in
`ci/prober/prober.c` and the header of `shm-coherence.rule` for both routes
and why each is closed). The forms are implemented, load-checked, and
unit-tested against synthetic readings including their reds; their live
coverage against a mutating zone arrives with a consumer that has one.

## How this class produces a green run that proves nothing

- **An oracle that assumes a guaranteed peak.** The single largest trap here.
  Passes on a fast handler for the wrong reason, reds spuriously on a slow one,
  and is unfixable without a module-side counter.
- **`concurrent 1`.** Rejected at load time; it is the sequential path claiming to
  be a concurrency test.
- **A fan with no snapshot.** Rejected for the same reason: it costs N connections
  and asserts what one request already did.
- **`open_conns` without `multi_accept on`.** The count lags, the assertion gets
  loosened to fit, and it stops failing.
- **A backpressure test against a response the kernel absorbs whole.** The server
  never blocks; the case is green and exercised nothing. Supply a body big enough
  and disable output coalescing.
- **Case-local `delta` against a per-request connection leak.** Cancels. Close on
  an absolute floor.
- **Sampled one worker N times.** A `fanout` whose coverage oracle was skipped,
  loosened or defaulted to `min_workers 1` passes having reached a single
  worker repeatedly. The whole point of the coverage oracle is that this fails
  loudly instead.
- **A `zone_invariant` asserted without `quiesce`.** Judging `at_rest` or
  `monotonic` against a mid-flight reading — one taken while the case's own
  traffic is still in the air — asks whether a counter had settled at a moment
  nobody arranged for it to be. It reddens or greens on timing, not on the
  invariant.
- **A coverage assertion loosened to fit an observed run.** Lowering
  `min_workers` to whatever a flaky box happened to reach, rather than widening
  `fanout` or investigating the accept path, disarms the one assertion this
  layer exists for: every fanout ever written would then pass having sampled
  however few workers a bad run touched.
- **An oracle nobody has seen fail.** A `zone_invariant` that has never been
  driven red by a broken fixture is unverified by the standard the rest of this
  repository holds every oracle to — it might be vacuously true against the
  reference module's non-mutating zone rather than actually checking anything.

## Not yet reachable

A scenario cannot overlap two *different* requests, only N copies of one, so a
race that needs request A and request B to interleave remains out of reach.
Tracked in
[Ideas and opportunities](../README.md#ideas-and-opportunities--ways-to-break-a-module-we-do-not-yet-try).

## See also

- [attack-leak-pressure.md](attack-leak-pressure.md) — the oracles a fan is judged by, and the case-local `delta` blind spot
- [attack-hostile-input.md](attack-hostile-input.md) — `block`, the ordered-pipeline counterpart `concurrent` refuses to combine with
- [attack-lifecycle.md](attack-lifecycle.md) — `reload-soak`, concurrency against a reloading server
- [attack-memory-corruption.md](attack-memory-corruption.md) — the canary lens this section's cross-process shm oracles complement: that one attributes a corruption to the worker that *looked*, this one detects the leaked/diverged *consequence* of a race neither it nor a thread-race detector can see
- [COVERAGE.md](COVERAGE.md) — the control-mutation rule every `zone_invariant` form had to pass before it shipped
