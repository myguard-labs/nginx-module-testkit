# Attack surface: fault injection

**What it attacks:** the branches that only execute when something fails —
a full slab, a failed `ngx_palloc`, a temp file that cannot be created, an
`accept()` that returns an error, an upstream that resets mid-reply or declares a
length it then contradicts.

**Why nothing else reaches them:** `malloc` does not fail in CI. The error path a
module writes for "out of memory" is, on most projects, the code with the highest
ratio of lines to executions — written once, reviewed once, and never run again
until a box under real pressure runs it in production. The same is true of every
upstream failure branch: a real redis or memcached daemon cannot be made to
truncate a reply mid-`VALUE`, to reset after eight bytes, or to close a parked
keepalive connection at the instant of a reload.

Two independent injectors cover the two halves.

## Half one: allocation faults inside the worker

`src/ngx_test_probe_arm.c` implements the arming side. Four named knobs make the
allocator fail on demand, on the Nth call:

| Knob | Fails |
|---|---|
| `fault_slab=<n>` | the nth shared-memory slab allocation |
| `fault_palloc=<n>` | the nth pool allocation |
| `fault_tempfile=<n>` | the nth temp-file creation |
| `fault_accept=<n>` | the nth `accept()` |

They are armed over HTTP, by the rule directive `fault <query>`:

```text
name    a slab allocation failure is handled, not fatal
fault   fault_slab=1
send    GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
delta   fds == 0
```

The prober issues its own `GET /__probe?<query>` first, requires a 200, and only
then takes the before-snapshot and sends the case's request — so a counter the
arming request itself moved is not billed to the case. The reply to the arming
request is discarded: what it did is judged by the case's own `probe` and `delta`
assertions. The whole arming request must fit in 512 bytes; a longer query is a
rule-file mistake and is reported as one.

**The query string is the module's own vocabulary, not the harness's.** The
harness delivers it; the module decides what a fault name means. That is the
consequence of the design boundary below.

### The hook boundary, stated plainly

`ngx_test_probe_arm()` returns `NGX_DECLINED` unless the module under test
registers a `fault_set` hook. Zero-hook consumers therefore get the whole generic
document and every leak oracle, but **not** allocation faults — there is no
generic place for the harness to make someone else's allocator fail.

Call it anyway, from the HTTP handler, before rendering the snapshot:

```c
(void) ngx_test_probe_arm(mlcf->probe_zone, &r->args);
```

With no hook registered it is a no-op returning `NGX_DECLINED`; if a hook is
added later it takes effect immediately, with no change to the tests already
written. Both return values are success. The timing is load-bearing — arm before
rendering, so the response reflects the armed state.

This boundary is why `t/module`, the reference module, cannot exercise this half:
it deliberately registers no hooks, so the allocation-fault knobs have nothing to
call. Reaching that half in this repository's own CI needs a real module fault
site plus a consumer `.so`, and it is recorded as open work in
[Ideas and opportunities](../README.md#ideas-and-opportunities--ways-to-break-a-module-we-do-not-yet-try).

## Half two: a hostile upstream (`prober/fakesrv`)

A scriptable fake redis/memcached backend. A scenario gets one by shipping a
`backend` file; it is started before the conf is rendered, binds an ephemeral
port, and `@BACKEND_PORT@` substitutes what it bound — the value does not exist
any earlier.

```sh
prober/fakesrv -script mc.backend -listen 127.0.0.1:0 \
               -portfile "$PROBER_PREFIX/backend.port" \
               -journal  "$PROBER_PREFIX/backend.jsonl"
```

The port is written to `-portfile` atomically, before the first `accept()`, so a
polling shell can never read it half-written.

### The fault vocabulary

Faults are **overlays on correct behaviour**, keyed `(command-glob : occurrence)`.
The default with no faults is a correct server backed by a real in-memory store.

```
proto   memcached
seed    hello  world
fault   on=get:3     action=truncate    after=8
fault   on=get:*     action=lie_bytes   delta=+5
fault   on=set:1     action=rst
fault   on=connect:2 action=accept_close
fault   on=get:2     action=drip        bytes=1 ms=5
fault   on=idle      action=close_after ms=100
```

| action | parameters | what it does |
|---|---|---|
| `truncate` | `after=<bytes>` | correct reply, cut after N bytes, then RST |
| `lie_bytes` | `delta=<signed>` | declared length disagrees with the payload |
| `rst` | — | TCP reset instead of a reply |
| `accept_close` | — | accept, then close without reading |
| `drip` | `bytes=<n> ms=<n>` | correct reply, N bytes at a time |
| `close_after` | `ms=<n>` | close this long after the connection goes idle |
| `raw` | `data=<bytes>` | send these exact bytes instead |
| `cursor_never_zero` | — | RESP `SCAN` that never terminates |

`<nth>` is a 1-based occurrence counter (per command, per run) or `*` for every
occurrence; an exact match beats a `*` match, so a script can state a general
rule and except one occurrence from it. `connect:<nth>` fires as the nth
connection is accepted; `idle` fires on a connection gone quiet.

**Why keyed occurrences and not a list of canned replies.** The obvious
alternative was rejected because a positional reply list cannot express a
keepalive test: the number of `get`s nginx will issue is precisely what such a
test is trying to discover, so a reply list encodes the answer into the question.

`raw` carries most of the adversarial surface — embedded NULs, oversize declared
lengths, a reply when none was due, `$-1` nil against a malformed near-miss. It
uses the same `\r \n \t \\ \" \0 \xNN` escapes as a rule file's `send`, through
the same lexer, so the two formats cannot drift on what a byte means.

**An unknown `action=` is fatal, never skipped.** A dropped fault leaves a
scenario exercising the happy path while its name and its TAP output both claim
otherwise.

It is deliberately not a real cache: the moment a scenario needs eviction or
expiry it should point at a real daemon, because a fake growing toward a real
redis is a second implementation to keep correct, and its bugs become
indistinguishable from the module's.

### The journal is what makes a fault falsifiable

```
{"ev":"listen","port":41897}
{"ev":"accept","conn":1,"t_ms":12}
{"ev":"cmd","conn":1,"n":7,"cmd":"get","args":["hello"]}
{"ev":"fault","nth":3,"action":"truncate","applied":true}
{"ev":"close","conn":1,"by":"peer","cmds":5}
{"ev":"summary","accepts":1,"conns_max":1,"cmds":5}
```

Two records do real work. The `summary` settles connection reuse —
`accepts==1 && cmds==5` proves the connection was reused, `accepts==5` proves it
was not — which no amount of reading the module's own logs settles as directly.
The `fault` record settles whether the fault *fired*, and that is the check the
next section is built on.

## The sweep: `scenarios/fault-matrix`

Every named upstream fault reaches a *different* nginx upstream error branch, and
after that branch has run the request pool and the upstream connection must be
back to exactly what a clean request would leave. `fault-matrix` sweeps them: one
fakesrv script arms all six, each pinned to a distinct 1-based get ordinal
(`on=get:<nth>`), and the driver issues the gets in order so get *N* triggers
exactly matrix row *N* — a stable, byte-reproducible injection with no timer and
no race.

`matrix.tsv` beside the driver is the plan's required record, `branch → fault →
fast target → resource oracle → mutation`. The table, the backend script and the
driver are three views of one list: the driver's plan count is `2 × row count + 1`,
so a drift between the three reds the scenario.

`memcached_read_timeout` is pinned to `200ms` (not a round `1s`) because nginx
applies it *between* successive reads, not to the whole response — it has to sit
strictly between the `drip` row's 50 ms inter-chunk gap and its ~800 ms total
transfer time. A timeout at or above 800 ms lets `drip` complete as an ordinary
slow-but-clean transfer and never reach the read-timeout branch its own row
claims.

Each row asserts two things, in order:

1. **Fault fired — read from the journal, not inferred.** The driver polls for
   this row's own `nth`+`action` pair before trusting anything else. A backend
   that silently drops or misnumbers a fault serves an ordinary correct reply —
   the get-ordinal guard still matches and the resource oracle still reads clean
   baseline — so without this check every row would print `ok` for having tested
   nothing. The same poll synchronizes the `close_after` row, whose socket close
   is asynchronous on fakesrv's own event loop.
2. **Harness-owned resource neutrality**, read from the probe rather than from
   the faulted reply's status or body (that is `backend-lying-length`'s and
   `backend-rst-midreply`'s job):
   - **`cycle_used` — EXACT.** The long-lived cycle pool is deterministic
     (measured identical to the byte across 20 faulted gets). This is the primary
     oracle.
   - **`fds` — CEILING, not equality.** The keepalive upstream pool parks a
     connection between requests, so the fd count legitimately oscillates by one.
     The oracle is a monotonic-growth backstop: a row fails only if it *exceeds*
     the max settled count. A leaked descriptor climbs to `baseline + N`; a
     parked keepalive fd never does.
   - Worker liveness (per-row pid, plus an error-log signal-death backstop).

## How this class produces a green run that proves nothing

- **A fault that never fired.** The single largest risk here, and the reason the
  journal poll exists. A misnumbered ordinal, a stale `matrix.tsv` row or a
  deleted `fault` line all yield a correct reply that satisfies every downstream
  assertion.
- **An unknown action silently skipped.** Fatal by design, for the same reason.
- **An allocation fault armed against a module with no `fault_set` hook.**
  `NGX_DECLINED`, no fault, a clean request, a green case. The arming request's
  own reply is discarded, so nothing downstream notices — this is a real trap for
  a consumer who copies a `fault` rule from a hooked module.
- **An fd equality assertion where a keepalive pool parks a connection.** It
  flakes, gets widened, and ends up unable to fail. Hence the ceiling.
- **A timeout tuned to the wrong side of the fault.** The `drip` row is the
  worked example: a round `1s` would have made it a slow-but-clean transfer that
  passes for the wrong reason.

## Non-vacuity, as run

The fault-fired oracle's own control is deleting a backend `fault` line — proven
by hand: removing `drip`'s line reds its row's fault-fired assertion and raises
the scenario's exit status; restored, re-verified clean. The resource-neutrality
oracle is proven by baseline corruption — corrupting `BASE_USED` reds every row,
proving the exact `cycle_used` oracle fires. The fds-ceiling control is
documented-only, because `fds` oscillates.

`fault-matrix` runs on the weekly lane (`impact.map` `SLOW`); a PR runs only the
sites mapped from its diff.

## See also

- [attack-leak-pressure.md](attack-leak-pressure.md) — the `delta` and baseline oracles every row is judged by
- [attack-lifecycle.md](attack-lifecycle.md) — `reload-mid-fault`, a reload landing on an already-failing request
- [attack-hostile-input.md](attack-hostile-input.md) — the fuzz corpus that routes a quarter of its cases through fakesrv
