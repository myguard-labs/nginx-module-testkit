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

## Not yet reachable

A scenario cannot overlap two *different* requests, only N copies of one, so a
race that needs request A and request B to interleave remains out of reach.
Tracked in
[Ideas and opportunities](../README.md#ideas-and-opportunities--ways-to-break-a-module-we-do-not-yet-try).

## See also

- [attack-leak-pressure.md](attack-leak-pressure.md) — the oracles a fan is judged by, and the case-local `delta` blind spot
- [attack-hostile-input.md](attack-hostile-input.md) — `block`, the ordered-pipeline counterpart `concurrent` refuses to combine with
- [attack-lifecycle.md](attack-lifecycle.md) — `reload-soak`, concurrency against a reloading server
