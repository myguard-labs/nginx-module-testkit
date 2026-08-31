# Attack surface: hostile and malformed input

**What it attacks:** the request shapes the module's author did not think of —
odd header casing, an oversize value, a missing `Host`, a chunked body, an
unusual method, embedded control bytes, a request split across the wire at an
inconvenient byte, and several requests sharing one connection.

**Why the Perl suite does not cover it:** `Test::Nginx::Socket` will happily send
any of these, and for status-code and body assertions it is the right tool. What
it cannot do is state the assertion that matters here — that the *worker* is
unchanged afterwards. A malformed request that is correctly rejected with a 400
and leaks one descriptor while doing so passes every `.t` file ever written.
Every generator below is therefore held to the resource oracles in
[attack-leak-pressure.md](attack-leak-pressure.md), not to a status code.

## Machinery

### Shaping one request on the wire

The rule DSL splits a single request across the wire rather than handing it over
in one write. `send` lines concatenate into one buffer and reach the socket in a
single write, so splitting a request across several `send` lines does **not**
split it on the wire — these directives are the ones that do:

| Directive | Shape |
|---|---|
| `pause <ms>` | Stall at the byte offset where it appears. Before the first `send`, it attacks the pre-request idle timeout; after the last, it holds a complete request open. 1–10000 ms, and a case's pauses may not sum past 10000 ms |
| `send_slow <chunk> <ms>` | Dribble a span in fixed-size pieces — the slowloris shape, where the read path is entered once per chunk. Chunks 1–4096 bytes, costed per chunk against the same ceiling |
| `shutdown 0\|1\|2` | `shutdown(2)` once the request is on the wire. `1` (SHUT_WR) is the useful one: it tells a server reading to EOF that the body is complete *without* tearing the connection down |
| `abort` / `hold` / `expect_idle` | End the connection without a clean exchange — reset, park, or assert nothing comes back |

The 10000 ms ceiling is enforced at load time, not at run time, because a stall
longer than the prober's own read timeout would report a harness timeout instead
of whatever the server did. `send_slow`'s cost depends on bytes added *after* the
directive, so the check runs once more when the stanza closes — a case that
looked cheap on its `send_slow` line can still be rejected after a later `send`
makes it expensive.

`send_slow` asserts a slow request is served *correctly*. It does not assert that
one is eventually cut off: timeout policy is the consumer's, not the harness's.

### Several requests on one connection (`block`)

`block <name>` turns a case into a pipeline — two or more exchanges on a single
keepalive connection, each judged against its own response. It is the only way to
reach a bug that lives *across* requests on a reused connection: module context
bleeding from one request into the next, a keepalive pool serving a stale
response, a second request corrupted by what the first left in flight.

```text
name    a reused connection does not bleed the first response into the second
from    127.0.0.1
block   establish
send    GET / HTTP/1.1\r\nHost: prober\r\n\r\n
expect  status=200
block   reuse
send    GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect  status=200
expect_not  body~establish
delta   fds == 0
```

Four properties carry the weight, each guarding an inference:

- **Each block's `expect`s judge that block's own response.** The reader stops at
  the framed end of each response, so a server that folded two responses together
  is caught rather than absorbed by reading to EOF.
- **Case-level assertions bracket the whole pipeline.** `probe`, `delta`,
  `probe_baseline`, `from`, `fault` and the log assertions are written outside any
  block and take one before-snapshot and one after — they measure the
  connection's total effect, not one exchange's.
- **A block that ends the connection must be last.** `abort`, `hold` and
  `expect_idle` hand the socket back closed, so a block after one could never
  run; rejected at load time.
- **A stranded block fails, it is not skipped.** If the connection ends early,
  every remaining block reports `not reached, connection ended by block "<name>"`
  and **fails**. A silently-skipped assertion reading as a pass is the exact
  failure this harness exists to rule out.

Up to 16 blocks per case. `scenarios/keepalive-bleed` is the reference — and the
negative control for the framing-aware reader itself: `ci/prober/http.c` points at
it for the conn-reuse split.

### Generated shapes (`scenarios/property-fuzz`)

Every other scenario asserts a hand-written list of adversarial shapes.
`property-fuzz` **generates** a fixed-count batch from a checked-in corpus,
through a deterministic PRNG, and holds every one to the same oracle
`conn-delta` and `soak-delta` use: `delta fds == 0`, `delta pool.cycle_used == 0`,
and the worker keeps its pid. No new C — a `driver.sh` writes a `.rule` file and
hands it to the stock prober.

- **Fixed iteration count (40), never a wall-clock budget**, so the fast leg and
  a sanitizer leg run the identical generated program and a failure reproduces
  across both.
- **xorshift64 in `gawk`**, seeded from a checked-in `seed` file — not `$RANDOM`,
  which is implementation-defined per bash build. Same seed reproduces the same
  rule byte for byte; `seed + 1` must differ, and both are asserted as real TAP
  tests inside the driver rather than claimed in a comment.
- **`corpus/*.frag`** — one already-escaped request per file. A new regression is
  pinned by adding one file: a one-file reviewable PR.
- **A `backend` fault script** routed to by roughly a quarter of the generated
  cases, so the upstream-failure teardown path is exercised every run and not
  only the request-shape path (see [attack-fault-injection.md](attack-fault-injection.md)).
- **The saved rule is the reproduction recipe.** Every generated file is written
  to `$PROBER_PREFIX/property-fuzz.generated.rule`, named in the TAP diagnostic
  on failure, and the driver re-runs that exact saved file a second time to prove
  replaying it reproduces the same verdict.

### Generated *sequences* (`scenarios/stateful-property-fuzz`)

Where `property-fuzz` throws independent request shapes at a fresh connection
each, this draws a fixed-count **sequence of stateful steps** from the same style
of deterministic PRNG and walks it in order: connection reuse, client
`abort`/half-close, upstream faults, and server-lifecycle events (`SIGHUP`,
`SIGKILL` of the serving worker) interleaved. Request steps run as stock `.rule`
batches — the whole `property-fuzz` generator, reused.

After every lifecycle event, five checkpoint oracles run (C1 lineage, C2 no
forbidden death, C3 cycle-pool settlement, C4 generation coherence, C5
zone/probe coherence). They are documented in
[attack-lifecycle.md](attack-lifecycle.md), which is the surface they belong to.

Replay differs from `property-fuzz` in one honest way: a kill's respawn pid and
the shared fakesrv counter make byte-identical prober-TAP replay impossible, so
the guarantee here is **plan-level** — the same seed regenerates the
byte-identical step plan (`$PROBER_PREFIX/stateful-property-fuzz.plan`, named in
every failure diagnostic), and each request batch is separately saved as
`batch-N.rule` for `./prober` reproduction.

## How this class produces a green run that proves nothing

- **A generator with no resource oracle.** A fuzz batch that only asserts "the
  server did not crash" passes against a module leaking a descriptor per
  malformed request. Every generated case carries the `delta` oracles for that
  reason.
- **A pipeline judged as one response.** A reader that drains to EOF and matches
  against the concatenation cannot tell a correctly-framed pair from a server
  that merged them. This is why `keepalive-bleed` was unrunnable for as long as
  it was, and why it is now the framing reader's negative control rather than a
  nice-to-have.
- **A stranded assertion reported as a skip.** See the block rule above.
- **A PRNG that is not reproducible.** `$RANDOM` differs per bash build, so a
  failing seed does not reproduce on the maintainer's box and the finding is
  lost. Both fuzz scenarios assert their own determinism as TAP tests.
- **An `abort` case carrying `expect_not`.** A reset connection has no response,
  so the assertion passes against an empty buffer whatever the server did. The
  loader rejects the combination — run `ci/prober/prober --check rules/*.rule`
  before a run, which costs nothing and catches it without a server boot.

## Not yet reachable

HTTP/3 is still not reachable from this harness: there is no QUIC/HTTP/3
transport leg or scenario. Some hostile request-body rows that used to live in
this section have graduated: `short-body.rule`, `huge-content-length.rule` and
`chunked-trickle.rule` now cover the module request path, while
`backend-lying-length` remains the upstream counterpart. TLS and HTTP/2 are no
longer untouched protocol surfaces; their scenario-backed status is tracked in
[Ideas and opportunities](../README.md#ideas-and-opportunities--ways-to-break-a-module-we-do-not-yet-try).

## See also

- [attack-leak-pressure.md](attack-leak-pressure.md) — the oracles every case above is held to
- [attack-fault-injection.md](attack-fault-injection.md) — the upstream faults the fuzz corpus routes into
- [attack-concurrency.md](attack-concurrency.md) — the same shapes, N in flight at once
- [COVERAGE.md](COVERAGE.md) — the control-mutation rule these generators are held to
