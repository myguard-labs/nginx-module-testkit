# nginx-module-testkit

Functional + leak testing for nginx and Angie modules, in C, with no Perl and
no version banner sniffing.

You compile a small **probe** into your module's test build. It answers one
special HTTP request with a JSON snapshot of the worker's internals: pid, open
file descriptors, memory-pool usage, shared-memory slab accounting. A
standalone **prober** binary sends your test requests, takes a snapshot before
and after each one, and asserts that the difference is exactly zero. If your
module leaks an fd or a byte of long-lived memory per request, the delta is
nonzero and the test goes red — in CI, not in production three weeks later.

## What this tool is for

**This is an adversarial tool. Its purpose is to break the module under test,
by any means available.**

A consumer points it at their nginx/Angie module and the harness goes looking
for the failure they have not found yet. Not "does the happy path return 200" —
that is `nginx.pm`'s job. This tool exists to find the leak, the corruption, the
descriptor that never closes, the allocation that is never checked, the state
that survives a reload it should not have survived.

The attack surface it works, and the machinery already here for each. Each
bullet has a document of its own under [docs/](docs/README.md#attack-surfaces),
naming the oracle that decides a verdict and the ways that class can produce a
green run proving nothing:

- **[Hostile and malformed input](docs/attack-hostile-input.md)** — `property-fuzz` and `stateful-property-fuzz`
  generate request shapes the module's author did not think of, including
  pipelined and split-framing cases (`keepalive-bleed` is the negative control
  for the reader that makes those honest).
- **[Allocation-failure injection](docs/attack-fault-injection.md)** — `fault_slab=`, `fault_palloc=`,
  `fault_tempfile=`, `fault_accept=`, `fault_codec=`, `fault_codec_end=`
  (`src/ngx_test_probe_arm.c`) make the
  allocator fail on demand, on the Nth call. Most module bugs live on the error
  path that nobody exercises, because in a healthy test the allocator never
  fails. `fault-matrix` drives these. Arming is over HTTP (`fault <query>` in a
  rule file), and the prober takes its before-snapshot *after* the arming
  request, so a counter that request moved is never billed to the case. A module
  opts in by registering a `fault_set` hook and returns `NGX_DECLINED` for the
  sites it has no fault point for; without the hook `ngx_test_probe_arm()`
  declines, which is the boundary `fault-matrix` documents. The second injector
  half is `fakesrv` — upstream faults (mid-reply reset, contradicted length,
  keepalive close at reload) a real daemon cannot be made to produce.
- **[Resource exhaustion and leak pressure](docs/attack-leak-pressure.md)** — repeated-operation deltas on
  cycle-pool bytes, file descriptors and slab accounting. A leak of one
  descriptor per request is invisible in a functional test and fatal in
  production; `rss-slope` and the `delta` oracles pin total growth, not a
  per-operation average that truncates to zero. **Shared-memory slabs need no
  module C**: every nginx shm zone begins with an `ngx_slab_pool_t`, so
  `zone->shm.addr` *is* the slab pool and the generic probe renders the zone's
  name, size and page accounting for any module. The optional `zone_render`
  hook is for what is private to the module on top of that.
- **Algorithmic and allocation cost** — the module that is correct but gets
  quadratic as its zone fills, or that churns a hundred slab allocations to
  serve one request. Neither is a leak, so no `delta` oracle above sees it, and
  neither shows up in review. `ci/prober/perf/cachegrind-scale.sh` is the
  shipped instance of the technique on the prober's own JSON parser: it asserts
  a **shape, not a speed** — parsing an 8x document must cost about 8x the
  instructions, never ~64x. Cachegrind counts instructions exactly and
  reproducibly, so the ratio is a host-independent proxy for asymptotic
  complexity, which is why a wall-clock `expect time<ms` directive was
  considered and **rejected** (load- and host-dependent, flaky by construction).
  Generalizing that ratio to a consumer's module, and counting per-request slab
  allocations rather than only net occupancy, are both open — see "Ideas and
  opportunities".
- **[Memory corruption ASan cannot see](docs/attack-memory-corruption.md)** —
  `ngx_palloc_small()` is a bump allocator, so a pool holding two hundred small
  objects is ONE live allocation to AddressSanitizer and to valgrind. Their
  redzones are at the two ends of that block; between the objects there is
  nothing to poison, and an overflow from one object into its neighbour is
  invisible to both. Demonstrated rather than asserted: the vacuity proof in
  `t/probe_redzone_test.c` runs that exact overflow under ASan and it exits 0
  with no diagnostic. `ngx_test_probe_palloc()` brackets an allocation with
  guard bytes and reports corruption as `redzone.violations`; `redzone.checked`
  is what stops "no violations" from meaning "nothing was ever guarded". The
  shm half is `ngx_test_probe_slab_alloc()`: a zone is one mmap shared across
  PROCESSES, which no single-address-space tool models at all, and slab's
  power-of-two rounding means a 20-byte request lands in a 32-byte chunk whose
  slack an overflow hides in — so the guard goes at the caller's size, not the
  chunk's. Freeing poisons the span, which makes use-after-free on shared
  memory obvious (a pool has no per-object free, so that half is slab-only).
  Not an ASan replacement — it catches one class, at detection time rather than
  at the faulting instruction. Run both.
- **[Lifecycle attacks](docs/attack-lifecycle.md)** — reload, binary upgrade,
  worker death, signal storms mid-transfer (`reload-*`, `usr2-*`,
  `hup-storm-mid-transfer`, `worker-death`). Reloads are where module leaks
  surface, because that is when a cycle is torn down and every unbalanced
  allocation becomes visible.
- **[Concurrency](docs/attack-concurrency.md)** — `concurrent N` holds N requests
  in flight at once (`concurrent-fan`), `open_conns` parks bare connections,
  `backpressure` attacks the write path with a reader that will not drain.
- **[Environmental hostility](docs/attack-environment.md)** — the
  `locale-hostility` CI job re-runs the self-tests under `tr_TR.UTF-8` and
  `de_DE.UTF-8` (both have caught a real bug), and `syscall-allowlist` traces
  what the worker actually does rather than what it claims. `clock-jump`
  LD_PRELOADs libfaketime to step the worker's wall clock backwards mid-run and
  requires its timers to be unmoved by it.

If you can think of another way to break a module, it belongs here. New attack
ideas are welcome as scenarios; see "Ideas and opportunities" below for the
current list of ones worth building.

### Coverage

**The goal is 100% coverage of the code under test.** We will very likely never
get there, and that is fine — the number is a direction of travel, not a
promise. What matters is that every uncovered line is *known* and either gets a
real adversarial test or an honest note saying why it is unreachable.

`ci/prober/coverage-director.sh` generates the per-test reachability map (opt-in;
it feeds the impact selector). Use it to find what is **not** reached — that is
its value here, as a generator of work.

There is deliberately **no coverage-percent merge gate**, and adding one would
be a mistake: the fastest way to move a coverage number is a test that executes
lines without asserting anything, which is precisely the vacuous gate this repo
has already shipped by accident several times and now hunts on purpose. A
mutation-proven test that covers one line beats a suite that touches every line
and cannot fail. Chase the coverage, never the percentage.

The policy in full — the four reachability classes, the control-mutation rule
every new test has to pass, how to annotate a line that really is unreachable,
and the constraints that keep the resulting tests contributable to the module's
own repository — is [docs/COVERAGE.md](docs/COVERAGE.md).
[docs/COVERAGE-HOWTO.md](docs/COVERAGE-HOWTO.md) is the procedure with commands:
find the drivable core, baseline it, classify the uncovered lines, write the
case, break the code to prove the case, ship it. Worked end to end on
[nginx-strip-filter-module](https://github.com/myguard-labs/nginx-strip-filter-module),
which went 77.21% → 99.79% that way, with two tests caught being vacuous by
their own controls.

## What this repo's own CI is for — and what it is not

The section above is what the tool does to a *consumer's* module. This one is a
narrower question: what does **this repo's own CI** spend its budget proving?

**This is a probe tool for nginx. It is not an nginx module, and it is not a
test suite for nginx itself.**

That distinction decides what belongs in CI here. The thing under test is *our
own code* — the `prober` binary, its rule parser, the probe's JSON emitter, the
shell plumbing that boots a server and diffs snapshots. nginx is the fixture we
run our tool against, not the subject. When a scenario boots nginx, it is there
to give the prober something real to talk to.

Concretely:

- **We test our test tool.** Does the parser accept the rules it should and
  reject the ones it should not? Does a snapshot diff report the delta that is
  actually there? Does a gate fail when its own control is broken? That is the
  whole job.
- **We do not test nginx's memory safety.** nginx upstream has its own
  sanitizer and fuzzing coverage, and it is far better resourced than ours.
  Instrumenting nginx core here spends our CI budget re-testing someone else's
  code, and every finding it could produce is a finding for upstream, not for
  this repo.
- **ASan/UBSan coverage:** No sanitizer instrumentation on nginx itself (the
  `selftest`, `scenario`, and mutation gates do not compile nginx under ASan/UBSan).
  The parser fuzz targets run deterministic replay under gcc + ASan/UBSan on every
  PR (`fuzz-replay` job) to catch memory safety issues in the rule parser; this is
  a Decided policy, not a gap. The sanitizer legs for the main prober binary and
  the full test suite were removed 2026-07-30 — they cost multi-minute wall-clock
  on the shared builder and were a steady source of flakes. The selftest suites,
  the mutation gates, and the scenario oracles are what actually prove the tool
  works; parser memory safety is proven separately by fuzz-replay.

The known cost of that last rule, recorded so nobody has to rediscover it:
`ci/prober/rules.c` and `ci/prober/json.c` are parsers, and dropping the sanitizer
selftest legs removes the only automated check for an out-of-bounds read or a
use-after-free inside them. If a parser bug is ever suspected, the move is a
one-off local sanitizer build (`SAN=1 ci/prober/test.sh` still works and is not
going away), not a new permanent CI leg.

**Also not in scope:** valgrind on nginx, whole-server fuzzing, and performance
benchmarking of nginx itself. Fuzzing our *own* parser is in scope and stays.

**Do not add a test here that the Perl suite can already do.** A consuming
module has `Test::Nginx::Socket` and its own `.t` files, and that is the right
home for ordinary request/response behaviour: status codes, headers, body
content, rewrites, `error_page`, config permutations. This harness exists for
the assertions the Perl suite structurally *cannot* make — what the worker looks
like from the inside, before and after: cycle-pool bytes, descriptor counts,
slab pages, allocation neutrality across a request or a reload. If a proposed
scenario could be written as a `.t` file with no probe snapshot, write it as a
`.t` file. The overlap is not free: a second suite asserting the same thing is
another place to update when behaviour changes, and it dilutes the signal this
one exists to give.

### The test that decides it, for scenarios

Booting or reloading nginx does **not** make a scenario out of scope. The
question is what the *oracle asserts*:

- If it asserts that **our measurement stays correct** — cycle-pool counters
  equal across a reload, fd accounting flat under pressure, the prober's reader
  framing a pipelined response correctly — it is in scope. Reloads and signals
  are precisely where module leaks surface, so most of the `reload-*` and
  `usr2-*` scenarios are core tool coverage despite looking nginx-shaped.
- If it asserts that **nginx does its own job** — resolves a location, serves an
  `error_page`, runs a subrequest without corrupting the parent — that is
  upstream's to prove. Removed 2026-07-28: `config-matrix`, `event-methods`,
  `internal-redirect`, `subrequest`.

Two that read as nginx-behaviour from their names are deliberately kept, because
our own C names them as the thing that proves it. `keepalive-bleed` is the
negative control for the prober's framing-aware reader — `ci/prober/http.c` points
at it for the conn-reuse split, and it is the shape `stateful-property-fuzz`
builds its pipeline kind on. `clock-jump` LD_PRELOADs libfaketime on purpose, to
prove a timer parked before a backward wall-clock step still fires on schedule
after it — i.e. that elapsed time is measured on `CLOCK_MONOTONIC` and cannot be
walked backwards by a stepping wall clock. It runs with
`FAKETIME_DONT_FAKE_MONOTONIC=1`, because faking the monotonic clock too would
measure libfaketime rather than the server; see
[docs/attack-environment.md](docs/attack-environment.md).

`zone-exhaustion` went on the same date for a worse reason. Its name promised
zone exhaustion; its `nginx.conf` set `worker_connections 10`; its rule sent two
sequential `Connection: close` requests and asserted `status=200`. Nothing ever
approached the limit, and no `limit_conn` or `limit_req` existed anywhere in the
tree. It would have passed with the mechanism it named entirely broken — and a
gate that cannot fail is the precise defect the rest of this suite exists to
catch, so it does not get to live in it.

## The problem, in plain terms

Three gaps this closes, in the order they hurt:

**Leaks that sanitizers cannot see.** ASan and valgrind watch *memory*. A
leaked file descriptor is not a memory error, so they say nothing while your
worker crawls toward `worker_rlimit_nofile`. Same for a slab page lost in a
shared-memory zone. And nginx's own pool design hides a third kind: every
request gets its own memory pool that is freed wholesale when the request
ends, so a per-request leak inside it looks like a flat line from outside.
That is why the probe measures the **cycle pool** — the one that lives as
long as the worker and where normal request handling should never allocate.
Any nonzero cycle-pool delta across a request is unbounded growth, full stop.

**Angie has no functional coverage.** Stock `Test::Nginx::Socket` probes `-V`
and requires `nginx version: ...`; Angie answers `Angie version: Angie/1.12.0`
and the suite bails before the first test. The prober reads no banner, so the
same rule files run against both servers unchanged.

**Allocation-failure paths are untested.** `malloc` does not fail in CI, so
the branches that handle a full slab or a failed `ngx_palloc` only ever
execute on a box under real pressure. The probe can arm a fault injector at
those sites and make "out of memory" just another test case.

## How it fits together

```
prober (standalone binary)          nginx/Angie worker (test build only)
┌──────────────────────┐            ┌────────────────────────────────┐
│ rule files           │  HTTP/1.1  │ your module (.so)              │
│ raw sockets          │ ─────────► │  + ngx_test_probe.c            │
│ strict JSON reader   │ ◄───────── │    renders pid/fds/pools/slab  │
│ delta oracle · TAP   │   JSON     │    as JSON on a test directive │
└──────────────────────┘            └────────────────────────────────┘
```

- **`src/ngx_test_probe.{c,h}`** — the in-worker probe, compiled into the
  module under test. Renders worker and shm-zone state as JSON so a test can
  assert on things the HTTP response never reveals.
- **`ci/prober/`** — the standalone C prober. Rule files, raw sockets, an
  RFC 8259-strict JSON reader (24 self-tests), TAP output. Knows nothing
  about any particular module.
- **`ci/prober/fakesrv`** — a scriptable fake redis/memcached upstream, for
  modules that talk to a cache. Serves correct replies by default and takes
  adversarial fault overlays (truncation, lying lengths, resets, idle closes)
  that a real daemon cannot be made to produce, plus a JSONL journal that makes
  connection reuse falsifiable. See [Fake upstream](#fake-upstream-proberfakesrv).

## Start here: you probably do not need to write any C

There are two ways in, and the cheap one is not obvious from the howto below.

**Zero-hook (no module C at all).** Build your module as a dynamic module
alongside this repo's reference probe (`t/module`), and point a scenario at
both. The probe is a *separate* `.so`; your module does not have to host it, and
you do not write a directive, a handler, or a hook. You still get worker pid,
connection counts, `fds` and `fds_by_kind`, `smaps`, and the full cycle-pool
accounting — which is enough to assert that a request produces no measurable
growth in descriptor count or in cycle-pool and resident memory. Note what that
does and does not say: these are counters and totals, so the oracle catches
growth, not every conceivable leak. An allocation freed by something else in the
same window, or a leak offset by a legitimate release, nets to zero and passes.
It is still the assertion most consumers actually want, and it is the one the
Perl suite cannot make at all.

Ten of our own modules were wired this way in one pass, and eight of them
produced a working allocation-neutrality scenario with zero lines of
module-specific C. The worked reference is
[`ci/prober/scenarios/consumer-cache-turbo/`](ci/prober/scenarios/consumer-cache-turbo/);
the others in `ci/prober/scenarios/consumer-*/` are generated from a table by
[`tools/gen-consumer-scenarios.sh`](tools/gen-consumer-scenarios.sh).

**Hooked (the Mini howto below).** You need this only when the generic document
cannot answer your question — custom introspection (`zone_render` /
`module_render`) or on-demand fault injection (`fault_set` /
`fault_set_global`). All four hooks are optional and independent. Reach for
this when zero-hook has shown you nothing, not before.

The pairs differ only in where your state lives. `zone_render`/`fault_set` are
handed the shm zone the probe was pointed at and are skipped entirely when
there is no zone. `module_render`/`fault_set_global` take no zone at all, and
are the path for a module that has none — a body filter such as a compression
module keeps every byte of its state in the request pool and per-worker
globals. **Register the pair that matches your module**: a zoneless module that
registers only the zone-addressed pair compiles, links and is never called
once, which looks instrumented while asserting nothing.

The rule of thumb: **start zero-hook, promote to a hook when an oracle you want
is unexpressible.** Everything in the howto below still applies once you get
there.

### What zero-hook actually costs, measured

Timed on the maintainer's box (2026-07-28), against an already-unpacked nginx
source tree:

| step | command | wall |
|---|---|---|
| build your module + the reference probe into one tree | `tools/build-consumers.sh --only <mod>` | **8 s** |
| generate the scenario from the table | `tools/gen-consumer-scenarios.sh` | 0.05 s |
| run it | `ci/prober/run-scenario.sh scenarios/consumer-<mod> nginx <ver>` | **0.4 s** |

The first run in a fresh checkout also downloads and unpacks the nginx tarball,
which dominates everything above and depends on your link. Budget minutes for
that once, then seconds forever after.

Two configure flags are needed by particular modules, not by all of them, and
neither module declares its own — so the failure arrives at build time with no
hint of which module asked for it. `--with-http_ssl_module` is
nginx-autocert-module's (its sources use `ngx_ssl_t`; without the flag the build
dies with `field 'ssl' has incomplete type`, which reads like a module bug and
is not one). `--with-stream` is nginx-label-autoconf-module's, for its stream
half; without it that half silently does not build at all.
`tools/build-consumers.sh` passes both unconditionally so a mixed build works,
which costs nothing for the modules that need neither.

## Mini howto: from zero to a passing leak test

This is the HOOKED path — read the section above first, because most modules do
not need it. Five steps. Step 2 is the only C you write, and most of it is
copy-paste.

**1. Add the harness to your module repo as a submodule:**

```sh
git submodule add https://github.com/myguard-labs/nginx-module-testkit t/harness
```

**2. Give the probe an HTTP surface.** An nginx module cannot inherit another
module's command table, so you add one directive and a tiny content handler
that calls `ngx_test_probe_json()`. Roughly 120 lines of boilerplate, all behind
`#ifdef NGX_TEST_HARNESS`. Copy from:

- **Template (recommended):** Start with [`PROBE_HTTP_TEMPLATE.c`](PROBE_HTTP_TEMPLATE.c)
  in this repo. It is fully documented and ready to fill in — just rename it,
  swap module names, and update three struct pointers.
- **Worked example (if you need asymmetric hooks):** See
  [`src/ngx_shield_probe_hooks.c`](https://github.com/myguard-labs/nginx-http-shield-module/blob/main/src/ngx_shield_probe_hooks.c)
  in the shield module for a production consumer. Use the template first; copy
  from shield only if your module needs custom zone introspection or
  fault injection that differs from the generic model.

Optionally register hooks for what the probe cannot know generically:

```c
static u_char *
my_zone_render(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    /* appends to the "zone" object -- leading comma, no closing brace */
    return ngx_slprintf(buf, last, ",\"nodes\":%ui", my_count(zone));
}

/* The zoneless counterpart, for a module with no shm zone. Renders into a
 * top-level "module" object whose braces the probe writes -- so unlike
 * zone_render there is NO leading comma and no closing brace. */
static u_char *
my_module_render(u_char *buf, u_char *last)
{
    return ngx_slprintf(buf, last, "\"frames\":%ui", my_frame_count);
}

/* Zone-addressed hooks. Skip this struct entirely if you have no shm zone. */
static const ngx_test_probe_hooks_t  my_hooks = {
    .zone_render = my_zone_render,   /* extra fields inside "zone" */
    .fault_set   = my_fault_set,     /* arm faults, zone-addressed */
};

/* Zone-independent hooks, in their own struct with its own registrar. */
static const ngx_test_probe_module_hooks_t  my_module_hooks = {
    .module_render    = my_module_render,     /* fields inside "module" */
    .fault_set_global = my_fault_set_global,  /* arm faults, no zone    */
};

ngx_test_probe_register(&my_hooks);              /* if you have a zone */
ngx_test_probe_register_module(&my_module_hooks);
```

**Two structs, not one, and that is deliberate.** `ngx_test_probe_hooks_t` is
frozen: existing consumers initialise it positionally, and `-Wextra` turns on
`-Wmissing-field-initializers`, so appending a member there is a *build
failure* in every one of those repos rather than a silent zero-init. New hooks
therefore arrive in `ngx_test_probe_module_hooks_t` with its own registrar. A
module that never calls `ngx_test_probe_register_module()` is unaffected. The
two registries are independent in both directions — registering one never
disturbs the other.

All four hooks are **optional**. Registering nothing still gets you the whole
generic document — flavor, pid, connections, `fds` (total and split by kind in
`fds_by_kind`: socket / file / anon / other), resident-set lineage in `smaps`
(`pss` and `private_dirty`, in kB, from `/proc/self/smaps_rollup`), cycle-pool
stats (`cycle_used` / `cycle_blocks` / `cycle_large` / `cycle_cleanup`), and the
zone's name, size and slab page accounting. That is already enough for fd and
memory leak assertions without a line of module-specific C. Slab occupancy
works for any zone because every nginx shm zone begins with an
`ngx_slab_pool_t`.

The `/proc`-derived fields (`fds`, every `fds_by_kind` bucket, both `smaps`
figures) and `timers` (uninitialised timer tree) render **-1** where the
underlying reading cannot be taken — a fail-loud sentinel, not a fabricated
zero. The `delta` / `probe_baseline` / slope oracles reject it rather than
subtracting `-1 − -1 = 0` into a passing result.

**Buffer sizing in the HTTP handler.** When you allocate a buffer for the
response, size it as:

```c
size_t size = NGX_TEST_PROBE_JSON_MAX + zone->shm.name.len + N;
```

where `N` accounts for your `zone_render` hook's output (if any). The generic
document is bounded by `NGX_TEST_PROBE_JSON_MAX`; a zero-hook consumer adds only
the zone name length. If your hook appends fixed-width data (e.g.,
"`,"nodes":123456789`"), add ~128 bytes for safety. Undersizing truncates the
JSON in the harness (ngx_slprintf stops at `last`), which surfaces as a parse
error on every case — not wrong assertions on one. The template provides this
formula with detailed comments.

**3. Build the test flavor of your module.** Compile
`t/harness/src/ngx_test_probe.c` and `t/harness/src/ngx_test_probe_arm.c`
alongside your sources with `-DNGX_TEST_HARNESS`. Without the define,
everything — probe, hooks, directive — compiles out to nothing (see
[Never ship it](#never-ship-it)).

**4. Write a rule file**, e.g. `t/prober/rules/00-smoke.rule`:

```
name    a plain request leaks no fd and no cycle-pool memory
from    127.0.0.20
send    GET / HTTP/1.1\r\n
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=200
delta   fds == 0
delta   pool.cycle_used == 0
```

`probe` lines assert on a single snapshot, `delta` lines on the change across
the case. A numeric literal must be a JSON number — the same grammar the probe
document is held to, enforced by the same code. `nan`, `inf`, `0x7`, `+1`, `.5`
and `1e999` are rejected at load time rather than compared: `probe fds != nan`
is true for every finite value, and a line that cannot fail is worse than no
line. `~` is a substring test and its pattern may not be empty, quoted (`""`)
or otherwise, for the same reason. `probe_baseline` lines subtract like `delta`, but from a snapshot
taken once before the first case of the run — see
[Catching a slow leak](#catching-a-slow-leak). `from` binds the source
address — load-bearing for anything keyed on the peer: without varying it, a per-IP fault never fires and the case
passes for the wrong reason. Your test nginx.conf **must** set
`worker_processes 1;` and `daemon off;` (the runner checks and bails
otherwise — see [Consumer contract](#consumer-contract)).

### Catching a slow leak

`delta` has one blind spot, and it is the shape most real leaks take. It reads
its before-snapshot **per case**, so a resource that grows by one unit on every
case is already present in both of that case's reads. The subtraction cancels,
every `delta fds == 0` in the file passes, and the count climbs from 0 to 200
across a 200-case run without a single red line.

`probe_baseline <path> <op> <value>` subtracts from a fixed origin instead: one
snapshot taken before the first case runs, held for the whole run. The same leak
that is invisible per case fails on whichever case crosses the bound.

```text
name            a request leaks no descriptor of its own
send            GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect          status=200
delta           fds == 0

name            ... and neither did any request before it
send            GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect          status=200
delta           fds == 0
probe_baseline  fds <= 2
```

Every case carries the `delta`; only the last carries the `probe_baseline`.
With two cases the difference is small — the point is what happens when the
file has two hundred of them, where a one-descriptor-per-case drip leaves every
`delta` at zero and lands the baseline at 200.

The two are complements, not alternatives. `delta` localises a jump to the case
that caused it; `probe_baseline` bounds the total. Writing both, as above, tells
you *which* case leaked and *that* the run stayed inside its budget.

Two things to get right:

**Usually a bound, not `== 0`.** A scenario that legitimately warms a cache,
opens a keepalive connection or faults in a slab page has an honest non-zero
floor by the second case. `probe_baseline fds == 0` fails there against
perfectly correct behaviour. Measure what a healthy run actually reaches and
bound slightly above it — the same discipline the absolute floors in
`scenarios/conn-delta` needed.

**Usually on the last case.** The bound is only interesting once the run has had
enough cases to accumulate something. Putting it on every case is not wrong, but
it makes the earliest case the one that reports the failure, which is rarely the
one that caused it.

The origin is read before any case, so it precedes every `fault` the file arms —
unlike `delta`'s before-snapshot, which is deliberately taken *after* arming so a
counter reset does not read as a leak. A fault counter is therefore visible to a
`probe_baseline` and not to a `delta`. If the origin snapshot cannot be read the
run aborts rather than starting: a `probe_baseline` with nothing to subtract from
would silently assert nothing.

### Catching a slow leak, third form: the post-warmup slope

`delta` and `probe_baseline` are two of the three resource oracles; the third is
a **slope over many operations, after warmup**. A single `delta` can read zero by
luck — an allocation the next request frees, a page the kernel reclaims — and a
`probe_baseline` bound has to be set generously enough to clear the boot one-off.
A slope divides the *total* growth over N identical operations by N, so a per-op
leak of even a few bytes is a nonzero slope while a healthy server sits flat, and
the warmup prefix (discarded, not averaged in) absorbs the startup allocations
that would otherwise read as a leak.

The slope is driven from a scenario `driver.sh` via `prober_slope_check` (it
needs a sequence of snapshots around repeated operations, which no single rule
case straddles), not a rule directive:

```sh
# field  stimulus  warmup  ops  max-growth-per-op
prober_slope_check "$HOST" "$PORT" cycle_used     / 10 60 0   # flat: 0/op
prober_slope_check "$HOST" "$PORT" private_dirty  / 10 60 4   # bounded: <= 4 kB/op
```

`cycle_used` is asserted **flat** (`0`/op — nothing may allocate on the cycle
pool per request), and `private_dirty` (RSS) is **bounded** rather than zero
because the kernel and glibc settle a healthy worker by a page here and there.
`scenarios/rss-slope` is the reference scenario. Like the other soaks its cadence
is weekly, not the PR path.

`send` lines concatenate into one buffer and reach the socket in a single
write, so splitting a request across several `send` lines does **not** split it
on the wire. To actually stall mid-request, use `pause <ms>`:

```
name    headers arriving late do not leak a connection
send    GET / HTTP/1.1\r\n
pause   200
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=200
delta   fds == 0
```

`pause` stalls at the byte offset where it appears: the request line goes out,
the connection sits idle for 200 ms, then the headers follow. That split is
what makes request-header timeouts, partial-header handling and smuggling
windows reachable at all. A `pause` before the first `send` stalls before any
byte is written (the server's pre-request idle timeout); one after the last
holds the connection open with a complete request already sent. Each pause is
1–10000 ms and a case's pauses may not sum past 10000 ms — a stall longer than
the prober's own read timeout would report a harness timeout rather than
whatever the server did, so the rule file is rejected at load time instead.

Where `pause` puts one gap on the wire, `send_slow <chunk> <ms>` dribbles a span
of the request in fixed-size pieces — the slowloris shape, where the server's
read path is entered once per chunk instead of a handful of times:

```text
name       a dribbled header block still completes
send       GET / HTTP/1.1\r\n
send_slow  4 20
send       Host: prober\r\nConnection: close\r\n\r\n
expect     status=200
delta      fds == 0
```

`send_slow` paces from where it appears up to the next `pause`/`send_slow` (or
the end of the request), writing `chunk` bytes at a time with `ms` between —
plus one leading stall, so it reads like `pause` at the point it appears. A
chunk at or above the remaining length degrades to a single write after that
stall. Chunks are 1–4096 bytes.

The pacing is costed **per chunk** against the same 10000 ms ceiling, so a
dribble long enough to outlast the read timeout is rejected at load time. That
cost depends on bytes added *after* the directive, so the check runs once more
when the stanza closes — a case that looked cheap on its `send_slow` line can
still be rejected after a later `send` makes it expensive.

This asserts that a slow request is served *correctly*; it does not assert that
one is eventually cut off. Timeout policy is the consumer's, not the harness's.
See `rules/stock/slowloris.rule`.

`send_slow_chunks <ms>` paces the same span at **chunked-framing granularity**:
one complete `<hex>[;ext]\r\n<data>\r\n` unit per write, `ms` between units. A
byte count cannot express this — `send_slow` cuts at fixed offsets irrespective
of framing, so a split lands mid size-line as often as on a boundary, and the
peer sees a partial chunk header rather than a complete-but-tiny chunk:

```text
name              a byte-at-a-time chunked body still completes
send              POST /echo HTTP/1.1\r\n
send              Host: prober\r\nTransfer-Encoding: chunked\r\n
send              Connection: close\r\n\r\n
send_slow_chunks  20
send              1\r\nA\r\n1\r\nB\r\n1\r\nC\r\n0\r\n\r\n
expect            status=200
delta             fds == 0
```

Offset, span and leading stall work exactly as in `send_slow`, and the two are
mutually exclusive on one directive line. The terminating `0`-chunk is a unit
like any other. Durations are 1–10000 ms.

Framing the parser rejects — a bare-LF size line, a length longer than the
bytes actually present, a truncated tail — is still **written in full, byte for
byte**. Pacing simply stops at the first unparseable byte and the remainder goes
out in one write. That is deliberate: putting malformed framing on the wire is
what this harness is for, and the alternative (guessing where the next unit
begins) is the mid-header slicing the directive exists to avoid.

Cost against the 10000 ms ceiling is charged as if every unit were the smallest
the wire allows — a zero-sized chunk, `0\r\n\r\n`, 5 bytes — because the real
unit count is not knowable at load time: a later `send` may still append framing,
and a size line may carry an extension of any length. Nothing stops a body from
being made entirely of zero-sized chunks, so 5 is a real floor rather than a
theoretical one. Costing at the floor overestimates the unit count for any larger
unit, which is the safe direction: being strict rejects a case that would have
fit, being lenient ships one that reports a harness timeout as a server verdict.

`shutdown 0|1|2` calls `shutdown(2)` once the request is on the wire — `0` =
SHUT_RD, `1` = SHUT_WR, `2` = SHUT_RDWR. One per case:

```text
name      a half-closed request is still answered
send      POST /upload HTTP/1.1\r\nHost: prober\r\n\r\nbody
shutdown  1
expect    status=200
delta     fds == 0
```

`shutdown 1` is the useful one: it half-closes the sending side, which is what
tells a server reading to EOF that the body is complete *without* tearing the
connection down — the response still arrives. `0` and `2` are accepted for
completeness, but a case using them is asserting on what the server logged and
on `delta` counters, not on a response it will not see.

`abort <offset>` writes the first `<offset>` request bytes and then destroys the
connection with a TCP reset (`SO_LINGER{1,0}`), so the server sees `ECONNRESET`
rather than a clean close:

```text
name          a reset mid-header-block is cleaned up
send          GET /__probe HTTP/1.1\r\nHost: prober\r\n
abort         24
delta         fds == 0
no_error_log  (assertion|panic|segfault)
```

This is the client-vanishes primitive: it tests that a server releases a
request's resources when the peer disappears, instead of holding them until a
timeout expires. A graceful EOF arrives where the event loop expects one; a
reset can land anywhere, including mid-parse. Offset `0` resets before the first
byte, an offset past the request end sends all of it and then resets, and pauses
inside the written prefix still apply — so `send_slow` followed by `abort` is a
slowloris that gives up.

An aborted case has **no response**, so it may not carry `expect`, `expect_not`
or `error_code_like`; the parser rejects that at load time. An `expect_not` in
particular would otherwise pass unconditionally against an empty buffer,
reporting green for an assertion that tested nothing. Judge an aborted case with
`delta` / `probe_baseline` / `probe` / `no_error_log` / `grep_error_log` —
evidence the server itself produced. For the same reason `abort` and `shutdown` are mutually
exclusive: a half-close asks to be answered, a reset says the client is gone.
See `rules/stock/abort.rule`.

`hold <ms>` writes the whole request, then waits that long without reading a
single byte before closing normally:

```text
name          a completed request whose client stops listening
send          GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
hold          200
delta         fds == 0
no_error_log  (assertion|panic|segfault)
```

This is the third way a client can walk away, and deliberately the polite one.
`abort` resets, so no response can be written at all. `shutdown` half-closes,
and the response still arrives. `hold` does neither: the connection stays fully
open and idle while the server writes a response nobody will ever read, and only
then ends with an ordinary FIN.

What that catches is a server holding a completed request's resources because it
keys cleanup off an error or an EOF — and here it sees neither, just a peer that
asked a question and left without waiting for the answer. Nothing is wrong at
the TCP level for the event loop to react to, which is exactly what makes it a
different path from the two directives above.

Like `abort`, a held case is **never read**, so it may not carry `expect`,
`expect_not` or `error_code_like` — same vacuous-assertion trap, reached a
different way, and rejected at load time for the same reason. The difference is
worth keeping straight: with `abort` the response does not exist, with `hold` it
exists and was simply never collected. Either way it is not there to assert on.

`hold` is mutually exclusive with `abort` (a reset destroys the connection
`hold` means to keep open) and with `recv_slow` (which paces a read loop `hold`
skips entirely). The wait counts against the same total-stall ceiling as
`send_slow`, so it cannot be spent on top of the budget. See
`rules/stock/abandoned-response.rule`.

A **send-then-drop client** — one that writes a complete request and closes
without reading a byte, distinct from `abort`'s reset — is `hold` with the
shortest wait the case needs, not a separate directive: the FIN is ordinary and
the response is left uncollected exactly as above. The wait is there only to give
the server time to finish writing before the close; a case that wants the drop as
immediate as the harness can make it uses `hold 1`.

`recv_slow <chunk> <ms>` paces the READ side — take `chunk` bytes, hold off
`ms`, repeat — and `so_rcvbuf <bytes>` shrinks the client's receive window:

```text
name       a slow reader still gets its whole response
send       GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
so_rcvbuf  512
recv_slow  256 40
expect     status=200
delta      fds == 0
```

This is the mirror of `send_slow`, and it tests the other half of the server. A
client that stops draining its socket applies **backpressure**: the server's send
buffer fills, its write blocks or returns `EAGAIN`, and the response sits
half-delivered while the event loop must keep the connection alive without
spinning on it. A module can handle every malformed request correctly and still
burn a worker on a slow reader.

The two directives only work as a pair. With the default receive buffer the
kernel absorbs a modest response whole, so `recv_slow` alone delays when the
*prober* sees the bytes while the server never blocks — nothing is under test.
`so_rcvbuf` is what makes the stall reach the far end.

**Constraints:**
- `so_rcvbuf` range: 128..1,048,576 bytes. The kernel enforces a minimum, so
  values below 128 are rejected at rule load time (not silently absorbed).
  `so_rcvbuf` may appear only once per case and only in the first block of a
  pipelined case — it is a connection property set when the connection opens,
  so a later block's value would never take effect.
- `recv_slow` chunk range: 1..4,096 bytes per read. This paces the read loop
  on the client side.
- `recv_slow` delay range: 1..10,000 ms between chunks.

Note the kernel doubles the requested `so_rcvbuf` size and enforces its own
floor, so the effective window is not the number given; assert on behaviour,
never on the size.

`recv_slow` is mutually exclusive with `abort` and `hold` — neither reads the
connection at all, so pacing their reads would pace nothing.

See `rules/stock/slow-reader.rule` for a working example.

`pid_may_change` relaxes the worker-survival oracle for one case, from "the same
worker answered both probe reads" to "the worker answering now is still a child
of the same master":

```text
name        the reload does not drop the connection
send        GET /slow HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
pid_may_change
expect      status=200
```

Every case is checked for worker survival, whether or not it asks: a worker that
segfaults mid-request is respawned by the master, and the retry the client never
sees can still produce the status and body the rule asked for, so the case would
report `ok` on a module that crashed. A changed pid is that crash.

A **reload changes the worker pid on purpose**, so a case spanning a `SIGHUP`, a
binary upgrade, or a conf with several workers fails the strict form while doing
exactly what the scenario asked. `pid_may_change` is for those cases and no
others. It takes no arguments, is off by default, and is **per case** — put it on
the stanza that crosses the signal, not on the ones before and after, which
should keep the stronger assertion.

It relaxes the oracle rather than removing it: the after-worker must still be a
child of the same master, so the probe port being answered by an unrelated
server is caught, and a probe document missing `ppid` fails the case instead of
passing quietly. What it **does not** catch is a crash — a worker killed and
respawned by the same master keeps that master's pid, so a segfault inside a
case carrying this directive reads as `ok`. A scenario that has to catch a crash
across the reload asserts it another way (a `no_error_log` on the worker-exit
message, or a delta a respawned worker could not satisfy). Note the directive
raises the floor on the probe contract — `ppid` is rendered by the generic half
of the probe, so a consumer gets it by rebuilding against the harness, with no
change to its own template.

`open_conns <N>` parks `N` bare idle connections — accepted by the worker but
carrying no request — open across this case's probe read, so a `probe
connections...` assertion can watch a worker approach its `worker_connections`
or upstream `max_conns` limit:

```text
name        a hundred idle connections show up in the worker's connection count
send        GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
open_conns  100
probe       connections.free <= 28
```

The connections are opened **after** the case's own exchange, held only for the
instant the probe snapshot is taken, and closed before the `pid_may_change` and
`delta` reads that follow — so those still see a clean count, and a case may pair
`open_conns` with a delta on some *other* field without the parked sockets
skewing it. It is **case-level**, not per-block: on a pipeline case it lands on
the case, since the connection count it observes is a property of the worker, not
of one exchange. A count must be `1..512`; a case that sets it but carries no
`probe` assertion is rejected at load time, because idle connections nothing
reads are a test that asserts nothing.

Whether all `N` connections are counted by probe time depends on how fast the
worker drains its accept queue: set **`multi_accept on`** in the scenario conf so
one listen-socket wakeup accepts the whole backlog at once, rather than one
connection per event. Without it the count can lag the sockets this process has
opened.

`concurrent <N>` issues `N` copies of this case's request and holds them **all in
flight at once**: every connection is opened and every request written before
*any* response is read. That overlap is the whole directive — a sequential prober
retires each request before starting the next, so a race that needs two requests
inside the same worker at the same instant is simply unreachable without it:

```text
name        twenty overlapping requests leave the worker exactly as one does
send        GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
concurrent  20
delta       fds == 0
```

The before/after probe snapshots bracket the entire fan, so the case's existing
`delta` oracles then assert that `N` overlapping requests leave the worker in the
state `N` sequential ones would: no extra descriptor, no pool growth, no slab
page. A leak or a double-free that only manifests under overlap shows up as a
non-zero delta here and nowhere else in the suite.

**What the directive guarantees, precisely:** all `N` requests are written before
any response is *consumed*. That is a client-side ordering property, and it is
what the self-tests prove. It is not the same as "`N` request lifetimes overlap
inside the worker" — against a fast handler with a small response, nginx may
process, answer and finalize leg 0 while the prober is still writing leg 1, and
leaving that response unread in the kernel buffer does not hold the worker's
request open. The overlap is *made likely*, not enforced. A case that needs a
proven simultaneous peak has to observe it from inside the module (an
active-request counter in the probe document), not infer it from this directive. Every leg is also checked
against the case's own `expect` assertions, so a leg answered differently from
the others is a finding even when the aggregate delta is clean; a failure names
the leg (`concurrent leg 3/20: ...`).

Do not confuse it with `open_conns`, which is its opposite half: `open_conns`
parks **bare** connections that never send anything, while `concurrent` sends the
request on all of them and collects every response. A count must be `2..64`. The
floor is **2, not 1** — `concurrent 1` is the ordinary path in costume, and
accepting it would let a rule file claim a concurrency test that asserts nothing
about overlap.

Three combinations are rejected at load time rather than silently resolved:

- **no `delta` or `probe`** — the snapshots are the only thing that observes the
  overlap, so a fan without one pays for `N` connections and asserts exactly what
  a single request already asserted.
- **`block`** — a pipeline is an *ordered* sequence on *one* connection. "`N`
  pipelines at once" is a coherent feature but a much larger one, so the pair is
  refused rather than resolved toward either reading.
- **`abort`, `hold`, `expect_idle`** — each ends its connection *without ever
  reading a response*, so a fan carrying one would collect nothing to assert
  against.

`fanout <N> [min_workers]` is the cross-**worker** relative of `concurrent`, and
the two answer different questions. `concurrent` asks *what happens when N
requests overlap*, and holds them all in flight to create that overlap.
`fanout` asks *do the workers agree about shared state*, and only needs to
REACH several workers — whether the requests overlapped is irrelevant to it:

```text
name    every worker sees the same zone
send    GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
fanout  8 3
probe   zone.digest >= 0
```

It rests on a property that `multi-worker.rule` documents as a *limitation*: the
probe reports state for whichever worker answered. That makes `fds` and
`pool.cycle_used` meaningless under `worker_processes > 1`, because those are
**per-worker**. The shm zone is the opposite — it is the same bytes in every
worker, so any worker's answer is a view of shared truth and a **disagreement
between two workers is itself a finding**. `zone.digest` exists to make that
comparison one field wide.

**What the directive guarantees, precisely:** that `N` requests were sent and
that at least `min_workers` *distinct* worker pids answered them. It does not
and cannot choose which worker serves a connection — nothing in the client can.
So the coverage is **asserted, never assumed**: `min_workers` defaults to `2`
and the case FAILS when the fan reaches fewer. That failure direction is the
whole point. A lens that passed after sampling one worker `N` times would be
claiming cross-worker agreement it never observed, which is precisely the
vacuous-gate shape this harness exists to catch.

A count must be `2..64` and `min_workers` must be `2..count`. Both floors are
`2` for the same reason `concurrent`'s is: one request reaches one worker, and
one worker cannot disagree with itself. A `min_workers` above the count is
refused as well — a bound nothing can satisfy makes every case fail for a
reason unrelated to the code under test.

`fanout` is mutually exclusive with both `block` (a pipeline is ordered on ONE
connection, so it reaches one worker) and `concurrent` (both drive the request
count). Both pairs are rejected at load time in **either order**, so the
diagnostic does not depend on which directive a file happens to name first.

`expect_close_within` and `recv_slow` **used to be a fourth rejection and are now
allowed individually.** The fan drained its legs in index order with a blocking
read each, so an earlier leg's read time was charged to every later leg's clock
and a prompt final leg could be reported as a timeout purely because an earlier
leg was slow. The drain is now a single `poll()` loop over per-leg state: legs
advance independently, each leg's timing is measured against its own clock, and
pacing is a per-leg gate that excludes that leg from the poll set rather than a
sleep that would withhold every other leg.

- **`concurrent` + `recv_slow` + `expect_close_within` (all three)** remains
  rejected, and the poll drain does not fix it. `close_ms` is measured from the
  moment the request finished going out to the moment the client observes the
  connection end, and `recv_slow` makes the client withhold reads on purpose —
  so a server that closed promptly is not *seen* to have closed until the
  client's own pacing gates have elapsed. A prompt response spanning four 50 ms
  gates fails `expect_close_within 100` as a 200+ ms close, blaming the server
  by name for the client's delay. Each *pair* is fine: `recv_slow` alone asserts
  nothing about close timing, and `expect_close_within` alone withholds no
  reads. Subtracting the pacing would only produce a plausible number that is
  still not the remote FIN's timestamp, so the case is refused rather than
  answered with a quantity known to be wrong.

`shutdown` is deliberately **not** in that list and combines freely: a half-close
is a modifier on the request, not a substitute for the response. After `SHUT_WR`
the peer still answers, and collecting that answer is the entire point.

Pacing (`pause`, `send_slow`) applies to the **first leg only**, which bounds the
damage rather than exploiting it: the write loop is sequential, so leg 0's pauses
all elapse before leg 1 is written either way. Pacing every leg would multiply
that delay by `N` and push the fan further from overlap, so only the first leg
carries it. If you want a slow request genuinely in flight while others pile in
behind it, this directive does not currently give you that — it would need the
paced leg's write to be interleaved with the other legs' rather than completed
first. A leg that fails to connect fails the whole case, because `N-1` overlapping
requests are not the test the file asked for.

`dechunk` decodes a `Transfer-Encoding: chunked` response body before the body
assertions run, so `body~`, `expect_not body~` and `body_sha256=` see the
payload rather than the chunk size lines:

```text
name        a chunked response decodes to the expected payload
send        GET /chunked HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
dechunk
expect      status=200
expect      body_sha256=2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

It takes no arguments and is off by default, so no rule written before it existed
changes meaning. The raw wire bytes stay reachable — decoding writes to a
separate buffer rather than over the response — because a harness built to
provoke invalid framing has to be able to assert on what actually arrived.

A framing error fails the case on its own, before the body assertions are
judged, and names which rule the server broke: a malformed or overflowing size
line, chunk data not followed by CRLF, a chunk shorter than its declared size,
or no terminating 0-chunk. That last one is the interesting failure — every
chunk parsed cleanly and only the terminator is missing, which is precisely how
a truncated response looks to anything that validates just the chunks it did
receive. A `dechunk` on a response that is *not* chunked also fails, rather than
passing quietly: a decode oracle that skips itself is not an oracle.

`gunzip` inflates a `Content-Encoding: gzip` or `Content-Encoding: deflate`
response body before the body assertions run, so `body~`, `expect_not body~` and
`body_sha256=` see the decompressed payload rather than the compressed stream:

```text
name        a gzip response inflates to the expected payload
send        GET /compressed HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
gunzip
expect      status=200
expect      body~hello
```

It takes no arguments and is off by default, so no rule written before it existed
changes meaning. It **chains after `dechunk`**: a `Transfer-Encoding: chunked`
response that is also `Content-Encoding: gzip` needs its framing removed before
the compressed stream is coherent, so write `dechunk` then `gunzip` and the body
oracles read the inflated bytes. Both `gzip` and `deflate` (zlib-wrapped and raw
headerless) are handled. The compressed wire bytes stay reachable, exactly as
with `dechunk` — inflation writes to a separate buffer.

A decode error fails the case on its own, before the body assertions are judged,
and names the failure: not a valid gzip/deflate stream, or a stream that ended
before its terminator. That truncated case is the sharp one — the stream inflates
cleanly up to where it was cut, which is exactly how a response dropped
mid-transfer looks to anything that trusts the bytes it did receive. A `gunzip`
on a response that carries no compression header fails rather than passing
quietly, for the same reason `dechunk` does.

`json_sort` canonicalizes a JSON response body before the body assertions run —
object keys are byte-sorted (recursively), whitespace is stripped, and the result
is what `body~`, `expect_not body~` and especially `body_sha256=` then see. Its
purpose is a **key-order-independent** hash: a server free to emit an object's
members in any order still produces one canonical form, so a `body_sha256=`
assertion matches regardless of that order:

```text
name        the JSON body matches whatever key order the server chose
send        GET /status.json HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
json_sort
expect      status=200
expect      body_sha256=<hash of the CANONICAL form, keys sorted>
```

It takes no arguments and is off by default, so no rule written before it existed
changes meaning. It **chains after `dechunk`/`gunzip`**: it canonicalizes the
most-decoded body those tiers leave, so `dechunk gunzip json_sort` sorts the keys
of the inflated payload. Only object key order is normalized — array order is
preserved (order is semantic in arrays), and values are untouched. Numbers are
emitted from their source lexeme verbatim, not round-tripped through a float:
integers beyond 2⁵³ stay exact and distinct (`9007199254740992` ≠ `…993`), the
decimal point is always `.` regardless of the process locale, and only the
exponent spelling is normalized (`1E+05` → `1e5`). The flip side is that `1` and
`1.0` are distinct lexemes and canonicalize to distinct bytes — exactness is
preferred over numeric equivalence for a key-order oracle. The raw wire bytes
stay reachable, exactly as with `dechunk`/`gunzip` — canonicalization writes to a
separate buffer.

A body that does not parse as JSON fails the case on its own, before the body
assertions are judged, rather than falling back to the raw bytes — unlike a plain
`dechunk` on an unchunked response, a `json_sort` on non-JSON is always a failure,
because the case asked to compare a canonical form and there is none. Trailing
garbage after a valid document is rejected too.

`expect_close_within <ms>` asserts the **server** ended the connection within
that long of the request going on the wire:

```text
name                 a completed request has its connection closed promptly
send                 GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect               status=200
expect_close_within  2000
delta                fds == 0
```

Every rule here already asks for `Connection: close`; this is what checks the
server did it, and by when. The response bytes are identical whether the
connection was released promptly, released far too late, or is still held open —
so a module that keeps a reference after the response is written (an uncancelled
timer, a cleanup handler that never runs) passes every other assertion. Even the
fd delta can be back to baseline by the time the probe runs, having been leaked
for seconds.

It judges *how* the connection ended, not what came back, and reports the three
outcomes distinctly: a close inside the deadline passes; a close after it fails
**with the measured time**; and a connection still open at the deadline fails as
that. A reset counts as closed — the connection is gone — but a late one is
named as a reset, since a server that resets is not merely slow.

That last outcome is why the directive changes a read timeout from a transport
error into a result. Without it the read gives up, the case aborts with "request
failed", and the assertion that asked the question never runs — a real server
defect reported as a harness fault. The opt-in is per case: every rule without
the directive reads a non-closing server exactly as before.

The deadline is measured from the **last request byte**, so a case that
deliberately dribbles with `pause` or `send_slow` is not billed for its own
pacing. Bounded two ways, both because a deadline that cannot be missed is an
assertion that cannot go red: the directive caps at 10000 ms at parse time, and
the run **bails** if any case's deadline is at or past the read timeout (`-t`,
default 5000 ms) — the read would give up first and report a timeout whatever
the server did. That second check needs both numbers, so it happens after the
rule files load rather than in the parser; `prober --check -t <ms>` validates
the combination without booting a server.

Mutually exclusive with `abort` and `hold` — neither ever reads the socket, so
the server's close is unobservable and the deadline would judge nothing. `hold`
looks like the natural pairing and the *idea* is right, but observing an
idle-but-open connection needs a read-side wait rather than hold's blind sleep;
that is `expect_idle`, below. The pairing that works today is `shutdown 1` — half-close, keep reading, and assert the server closes its half on time. See
`rules/stock/close-deadline.rule`.

`expect_idle <ms>` is the opposite oracle on the same connection state: it
asserts the server left the connection **open and silent** for that long,
rather than acting on it.

```text
name             an unterminated request is neither answered nor hung up on
send             GET /__probe HTTP/1.1\r\nHost: prober\r\n
expect_idle      300
delta            fds == 0
```

A module that mis-drives the event loop fails in one of two directions, and
only one was testable before. An over-eager cleanup — a timer armed on the
wrong branch, a handler reading "no data yet" as "peer is gone" — closes a
connection that should have stayed open. An over-eager response path answers a
request whose headers were never terminated. Both look like a perfectly valid
exchange from the client's side; what marks a correct server here is that it
does *nothing*, which no other directive could observe.

The wait **polls without reading**. Draining would defeat it twice over: the
response bytes would be collected, so the case could no longer assert the
server stayed silent, and the read would consume the very readiness being
asserted about. The connection is left exactly as an idle client leaves it.

Three outcomes, again distinct because they are three different bugs: nothing
arrived and the connection stayed open passes; data arriving fails **naming
that the server answered**; a close arriving fails with the measured time and
the manner (FIN or reset). Data or a close ends the wait immediately rather
than at the deadline.

Like the close deadline it is measured from the last request byte and capped at
10000 ms, and the run bails if a case's wait is at or past `-t`. That bound is
weaker here and for a different reason: `poll()` answers to its own deadline, so
a long wait is *not* truncated and the assertion stays falsifiable — but a case
quietly parking longer than the per-request budget stalls the run somewhere
nobody thinks to look.

Mutually exclusive with `abort`, `hold`, `recv_slow`, `expect_close_within`, and
response expectations. The first three never observe the socket; the fourth
asserts the opposite outcome, so whichever assertion ran first would decide the
verdict; response expectations would assert against a buffer that is empty by
construction — and `expect_not` would report green having looked at nothing. It
*does* combine with `shutdown 1`, though note a half-close on an *incomplete*
request is a truncated request, which a healthy server answers with 400 rather
than ignoring. See `rules/stock/idle-connection.rule`.

Beyond `expect status=` / `body~` / `header~`, a case can also carry:

```
expect          raw_response_headers_like~^Content-Type:.*text
expect_not      body~stack smashing
expect_not      header~X-Debug
error_code_like ^(403|429)$
no_error_log    \[emerg\]
grep_error_log  banned by rule
xfail           issue #12: trailer parsing not implemented yet
```

- **`expect raw_response_headers_like~`** — POSIX extended regex against the
  raw HTTP header block (CRLF-delimited lines, no status line, no body). Useful
  for asserting header order, duplicates, or byte-level framing that a substring
  match cannot express. The header block is NUL-terminated but may contain
  embedded NULs in header values; the regex matches the full block as-is.
- **`expect_not`** — the negative form of `expect` (`body~`, `header~` only):
  the case fails if the pattern IS found. Status has no negative form here on
  purpose; a negated status is a set, and sets are spelled with
  `error_code_like`.
- **`error_code_like`** — POSIX extended regex against the status code as
  decimal text, for rules that accept a class (`^2[0-9]{2}$`) rather than one
  value. An unparseable status line is matchable as the literal `-1`. Invalid
  regexes are rejected at load time, before the first request goes out.
- **`no_error_log` / `grep_error_log`** — per-case error-log assertions: no
  line / at least one line written **during this case** may/must match the
  regex. The prober records the log file offset before the case's request and
  greps only that slice, so an earlier case's lines can neither satisfy nor
  trip these. Needs the log path (`prober -e`, or `PROBER_ERROR_LOG`, which
  `run.sh` exports automatically); a case carrying either directive fails
  loudly when the path is missing. They complement — not replace — the
  whole-run alert/crit/emerg gate below.
- **`xfail [reason]`** — known-broken case: it still runs, but a failure is
  reported as `not ok N # TODO reason` and does not fail the suite. If it
  unexpectedly passes, the line reads `ok N # TODO reason`, which TAP
  consumers surface as "unexpectedly succeeded" — the signal to remove the
  annotation.

Two more directives shape the request itself rather than the assertions on it:

- **`repeat <count> <text>`** — append `text` to the request `count` times,
  with the same `\r`/`\n`/`\t`/`\\`/`\"`/`\0`/`\xNN` escapes `send` accepts.
  This is how a case reaches a limit without a thousand-line rule file: a
  header block that overruns `large_client_header_buffers`, a body longer than
  `client_max_body_size`, a pathological repetition that makes a parser go
  quadratic. `count` is 1–100000, and the whole token must be the number —
  `10junk` is rejected at load time rather than quietly parsed as `10`, since
  a size-driven case that silently changes size is exactly how a limit test
  stops reaching its limit.

  ```text
  name    an over-long header block is rejected, not crashed
  send    GET / HTTP/1.1\r\nHost: prober\r\n
  repeat  2000 X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n
  send    \r\n
  expect  status=400
  delta   fds == 0
  ```

- **`fault <query>`** — arm the module's fault injector before the case runs.
  The prober issues its own `GET /__probe?<query>` first, requires a 200, and
  only then takes the before-snapshot and sends the case's request — so a
  counter the arming request itself moved is not billed to the case. The reply
  to the arming request is discarded: what it did is judged by the case's own
  `probe` and `delta` assertions.

  ```text
  name    a slab allocation failure is handled, not fatal
  fault   fault_slab=1
  send    GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
  delta   fds == 0
  ```

  The query string is the module's own vocabulary, not the harness's — the
  harness only delivers it. Allocation-failure branches are the least-tested
  code in any module, and this is what makes them reachable without a
  debugger. The whole arming request must fit in 512 bytes; a longer query is
  a rule-file mistake and is reported as one.

### Pipelining several requests on one connection (`block`)

Everything above drives **one** request/response exchange per case. A `block
<name>` directive turns a case into a **pipeline**: two or more exchanges on a
single keepalive connection, each judged against its own response. This is the
only way to test a bug that shows up *across* requests on a reused connection —
module context that bleeds from one request into the next, a keepalive pool that
serves a stale response, a second request corrupted by whatever the first left
in flight.

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

The rules:

- **Everything per-exchange moves inside a block.** Once a case uses `block`,
  every `send`/`pause`/`expect`/`shutdown`/`abort`/`hold`/`recv_slow`/`dechunk`/
  `gunzip`/`json_sort`/… attaches to the **open** block, not the case. A
  per-exchange directive *before* the first `block` is a load-time error — a
  case cannot drive part of itself flat and part in blocks.
- **Case-level assertions stay at the case level.** `probe`, `delta`,
  `probe_baseline`, `no_error_log`/`grep_error_log`, `pid_may_change`, `fault`
  and `from` are written once, outside any block, and judge server-wide state
  **once around the whole pipeline** — one before-snapshot, one after. They
  measure the connection's total effect, not one exchange's.
- **Each block's `expect`s judge that block's own response.** Block 2's
  `expect status=200` checks the *second* response on the wire, never a merged
  view; the reader stops at the framed end of each response (E1's framing-aware
  reader) so a server that folded two responses together is caught, not
  silently absorbed by reading to EOF.
- **A block that ends the connection must be last.** `abort`, `hold` and
  `expect_idle` stop reading and hand the socket back closed, so any block after
  one of them could never run — rejected at load time. Only the **last** block
  may carry `Connection: close` (or drain to EOF).
- **A stranded block fails, it is not skipped.** If a connection ends early — a
  peer FIN/RESET, a read error — before the last block, every remaining block is
  reported `not reached, connection ended by block "<name>"` and **fails**. A
  silently-skipped assertion reading as a pass is the exact failure this harness
  exists to rule out.
- Up to `MAX_BLOCKS` (16) blocks per case; the block's name is diagnostic only,
  the way a case `name` is. See `ci/prober/scenarios/keepalive-bleed/`.

**5. Check the rules parse, without a server:**

```sh
ci/prober/prober --check ci/prober/rules/stock/*.rule
# 12 cases parsed from 3 rule files
```

`--check` runs the rule files through the same loader a real run uses, then
exits without opening a connection. Nonzero status means a file is malformed.
Worth doing before a run because the loader enforces more than syntax: it also
rejects combinations that would produce a case which cannot fail, such as an
`abort` case carrying `expect_not` — a reset connection has no response, so the
assertion would pass against an empty buffer whatever the server did.

Catching that here costs nothing; catching it after a server boot costs a cycle,
and *not* catching it means a green test that asserts nothing.

**6. Build the prober and run:**

```sh
( cd t/harness/prober && ./build.sh )     # builds prober + json_test
PROBER_PROBE='mymod_probe probezone;' \
PROBER_PROBE_ZONE='mymod_ban_zone probezone:1m;' \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
t/harness/prober/run.sh nginx 1.31.3
```

`PROBER_PROBE` is what fills the `/__probe` location in the conf template;
see [Consumer contract](#consumer-contract) for when it is required.

Output is TAP: one `ok`/`not ok` per rule, `prove`-consumable. Most consumers
wrap this in a ~15-line `t/prober/run.sh` that exports the `PROBER_*`
variables and execs the harness runner.

`run.sh` refuses to start when any of three preflight gates fail, because
each failure mode once produced a green run that proved nothing:

1. the prober binary is not older than its sources (it does not build them);
2. the JSON reader passes its own self-tests — it is the **oracle** every
   assertion runs through, so a lax reader makes the whole suite unable to fail;
3. the module binary actually carries the probe directive, decided by
   inspecting the binary rather than by whether a `.so` happens to exist.

### Proving the tests assert

`ci/prober/test.sh` proves the self-tests **run**. `ci/prober/mutate.sh` proves they
**assert**: it breaks the code on purpose, once per known behaviour, and requires
the named suite to go red each time.

```sh
ci/prober/mutate.sh              # every mutation
ci/prober/mutate.sh SO_LINGER    # only those matching a substring
MUT_KIND=c ci/prober/mutate.sh   # only rows whose suite is a compiled test binary
```

`MUT_KIND` is `all` (default), `c`, or `scenario`. The split is by the KIND of
suite a row needs, because the two need different environments: a `scenario`
suite boots a real server and needs `.build/<flavor>-<version>/objs` staged,
which a bare checkout does not have. CI runs `MUT_KIND=c` in the `mutation` job
and `MUT_KIND=scenario` in the `scenarios` job, where that tree exists. A run
that skips rows says so, with the mode that produced it.

A `SURVIVED` line means the suite passed with the code deliberately broken —
that behaviour is untested, whatever the coverage number says. It has found a
real gap on every pass so far, including a directive whose entire effect was
untested behind assertions that read as thorough.

Doing this by hand is where the danger is, and the script exists mostly to
remove four failure modes that each *look* like a caught mutation:

- **the mutation did not compile** — the build fails, the stale binary re-runs,
  the suite goes red anyway. The `-Werror` wall makes this common: zeroing a
  parameter's only use trips `-Werror=unused-parameter`, so `x * 0` is the safe
  mutation, not `0`.
- **the edit did not apply** — a pattern matching nothing leaves the code
  pristine, the suite passes, and that reads as `SURVIVED`. Anchors are literal
  strings and must match exactly once.
- **the wrong suite was run** — a transport mutation checked against the parser
  tests survives trivially.
- **the suite was already red before the mutation** — every verdict is read off
  the mutant run's exit status, so a suite that cannot RUN (a `Bail out!` on a
  stale or absent build tree, a missing fixture, a busy port) exits nonzero for
  its own reasons and credits every row pointed at it. Each suite is therefore
  run once, unmutated, before any row using it is scored.

Any of those is reported as `BROKEN`, never as a result, and fails the run.

The test for whether a mutation harness has this property at all is a **no-op
mutation**: a row whose replacement changes nothing observable must report
`SURVIVED`. If it reports `caught`, the verdict does not depend on the mutation
and no other row's result means anything either.

## Stock rules

`rules/stock/` holds rule families that hold for **any** module, so a
consumer gets them without writing them. `PROBER_RULES` is word-split by
`run.sh`, so several space-separated globs compose:

```sh
PROBER_RULES="t/harness/rules/stock/*.rule t/prober/rules/*.rule" \
PROBER_PROBE='mymod_probe probezone;' \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
t/harness/prober/run.sh nginx 1.31.3
```

They target `/__probe` — the one location every consumer already has — so
they need no extra `location` block, no upstream, and no per-consumer status
knob.

| File | Family |
|---|---|
| `malformed-http.rule` | Hostile request-line and header framing: NUL bytes, bare LF, oversized headers, smuggling header pairs |
| `malformed-body.rule` | Malformed chunked framing: non-hex, negative and oversized chunk sizes |
| `head-no-body.rule` | HEAD reports a GET's headers and emits no body |
| `huge-content-length.rule` | `Content-Length` of 2^31−1, 2^32+1, 2^63−1, past 2^64 and negative, with no body sent |
| `slow-headers.rule` | A request line, a stall, then the headers — partial-header handling and header timeouts |
| `slowloris.rule` | The request dribbled out in small paced chunks |
| `abort.rule` | The client resets mid-request (RST); resources released when the peer vanishes |
| `half-close.rule` | The client half-closes (`SHUT_WR`) and is still answered |
| `abandoned-response.rule` | The client completes its request, then stops listening without erroring |
| `slow-reader.rule` | The client drains its socket slowly through a shrunken window (backpressure) |
| `close-deadline.rule` | The server closes the connection it promised to close, on time |

### What may live there

Only assertions that are module-independent, which in practice means
**nginx's own parser rejected the request before any module ran**. A 400
from a NUL byte in the URI is core behaviour and is identical for every
consumer.

What may not live there is any **handler-level verdict** — the status a
module chooses for a request nginx accepted. Shield answers 403 to an
absolute-form request target; another module answers 200, 404 or 502 to the
same bytes. Two of shield's ten malformed cases were dropped on exactly that
ground rather than hoisted.

That line is not where intuition puts it, and it was drawn by measurement.
Three results are worth knowing before writing a stock case, because each
one would have produced a rule that passes for the wrong reason:

- **Bare LF line endings are accepted**, not rejected — nginx takes a bare
  LF as a line terminator, so the request reaches the handler.
- **`%00` is rejected in the URI path but accepted in the query string**,
  since only the path is percent-decoded during normalization.
- **A bad chunk size is only rejected if a handler actually reads the
  body.** The same request answers 400 at a `proxy_pass` location, 405 at a
  GET-only one and 404 where nothing matches. That is why the chunked cases
  assert survival and deltas rather than a status, and why they are a
  separate file.

Cases that cannot assert a status assert worker survival and clean deltas
instead, which holds whether the consumer's location proxies, returns or
serves a file.

## Scenarios

`run.sh` is the single-scenario form: one conf, one rule glob, one boot. When
what varies is the *environment* — a tiny shm zone, an `LD_PRELOAD`, an
rlimit, a signal choreography — a flat rule list cannot express it, and
Perl-style one-boot-per-test-file wastes a server boot on every case that
didn't need one. Scenarios split the difference: one boot per **environment**,
many cases inside it.

A scenario is a directory; every file is optional except that a scenario must
end up with something to assert (rules or a driver):

```
scenarios/conn-delta/
    nginx.conf    conf template, placeholders below  (default: $PROBER_CONF)
    *.rule        cases run by the prober            (default: $PROBER_RULES)
    env           sourced before boot: LD_PRELOAD, ulimit, PROBER_ALLOW_LOG
    driver.sh     replaces the prober call: signal choreography (see below)
    requires      gate; nonzero exit = scenario SKIPPED, not failed
    backend       fakesrv script; its presence starts a fake upstream
```

Every conf template — a scenario's `nginx.conf` or the single-run
`$PROBER_CONF` — is rendered through the same substitution pass before the
server sees it. Seven placeholders are recognized, and nothing else is: a
template containing an unknown `@NAME@` reaches nginx with the literal text
intact, which `render_conf_test.sh` fails on rather than leaving to be
discovered as a parse error.

| Placeholder | Supplied by | Expands to |
|---|---|---|
| `@LOAD@` | harness | The `load_module` line for a dynamic build; empty when the module is linked statically (asan/coverage builds) |
| `@BUILD_OBJS@` | harness | Path to the build tree's `objs/` directory — used in consumer confs to reference pre-built objects |
| `@PORT@` | harness | `$PROBER_PORT` (default `18099`) |
| `@PREFIX@` | harness | The per-run `mktemp -d` prefix — `pid` and `error_log` must be written under it |
| `@PROBE@` | **consumer** (`PROBER_PROBE`) | The body of the `/__probe` location: the module's probe directive |
| `@PROBE_ZONE@` | **consumer** (`PROBER_PROBE_ZONE`) | An http-level declaration the probe directive needs, if any |
| `@BACKEND_PORT@` | harness (`PROBER_BACKEND_PORT`) | The ephemeral port the fake upstream bound; empty when the scenario ships no `backend` file, which is the normal case |

`@PROBE@` and `@PROBE_ZONE@` are the consumer's because the probe directive is
module-specific — the generic tree cannot name `shield_probe` any more than it
can name yours. A template that uses `@PROBE@` while `PROBER_PROBE` is unset
**bails at render** rather than substituting empty, because an empty probe
location falls through to `location /`, the prober parses the wrong body and
reports `malformed number` — a failure that points nowhere near its cause.
`PROBER_PROBE_ZONE` is genuinely optional: a probe directive needing no zone
leaves it unset and `@PROBE_ZONE@` renders empty.

```sh
PROBER_PROBE='mymod_probe probezone;' \
PROBER_PROBE_ZONE='mymod_ban_zone probezone:1m;' \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
ci/prober/run-scenario.sh ./scenarios/conn-delta nginx 1.31.3
```

- `ci/prober/run-scenario.sh <dir> [flavor] [version]` runs one scenario.
- `ci/prober/test-scenarios.sh [flavor] [version]` runs every directory matching
  `PROBER_SCENARIOS` (default `scenarios/*/`) and aggregates to a single TAP
  stream, each scenario an indented subtest block — `prove`-consumable. Zero
  matching scenarios is a bail-out, not a green: a typo'd glob must not turn
  the stage into a silent no-op.

`driver.sh` is the orchestration layer. It runs with the server already booted
and gets the master pid, so it can interleave prober runs with signals —
reload under traffic, binary upgrade, worker kill — and assert what happens.
Its stdout is the scenario's TAP; its exit status is the verdict. Exported
contract: `PROBER_CLIENT` (the prober binary), `PROBER_LIB` (lib.sh, for
`prober_stop` and friends), `PROBER_SCENARIO`, `PROBER_PREFIX` (logs +
pidfile live under it), `PROBER_SERVER_BIN`, `PROBER_SERVER_PID`,
`PROBER_RESOLVED_PORT`, `PROBER_BACKEND_PORT` and `PROBER_BACKEND_JOURNAL`
(both empty when the scenario ships no `backend` file, so a driver may read
them under `set -u` without knowing whether it has an upstream).

For reading server state, `lib.sh` gives a driver `prober_probe_body` (one
`/__probe` read, with the retry and timeout discipline in one place),
`prober_probe_pid` (that body's worker pid), `prober_probe_field BODY NAME`
(any flat or nested-leaf numeric field; **returns nonzero for an absent field
rather than an empty string**, so a lost counter cannot be read as a zero
delta), and the two waits — `prober_signal_wait` (a signal was absorbed: a new
worker answers) and `prober_drain_wait` (the previous cycle is *gone*: the
master is back to its configured worker count). The two are not
interchangeable; see `scenarios/reload-cycle` for why measuring between them
is what makes a reload scenario flaky.

A scenario that ships a `backend` file gets a fake upstream, started before
the conf is rendered — it binds an ephemeral port and `@BACKEND_PORT@`
substitutes what it bound, so the value does not exist any earlier. Teardown
takes the backend down before the server, so the module under test never sees
its upstream vanish while still being asked for something, and
`prober_backend_scrape` reports a backend that died mid-scenario as a finding
even when the error log is clean. `PROBER_BACKEND_ALLOW_EXIT` exempts a
scenario that kills it on purpose.

Two engine-level gates apply to every scenario, because each guards an
inference the harness depends on: `worker_processes 1` (the pid oracle) and
`daemon off;` (the engine tracks the master by `$!`; a daemonized server
orphans itself past teardown and holds the port into the next scenario). The
error-log scrape runs per scenario, `PROBER_ALLOW_LOG` and all.

All three entry points share the same engine (`ci/prober/lib.sh`), so boot,
teardown and the log scrape cannot drift apart between them.

### The reference module (`t/module`)

The scenario tree needs a module to boot against: `prober_resolve` requires
`PROBER_MODULE` and `PROBER_DIRECTIVE`, which are the consuming module's to
supply. `t/module` is a minimal one so CI can run the tree without a consumer
— it registers neither probe hook, takes no shm zone, and its whole directive
is `test_ref_probe;`. A module registering no hooks still gets the entire
generic document (flavor, pid, connections, fds, cycle-pool accounting), which
is what every checked-in scenario asserts on.

It is not a template for writing a consumer: the hook API is what a real
module uses, and it is documented in `src/ngx_test_probe.h`. This one exists
only so the harness can be proven end to end.

```sh
# Fetch nginx, unpack it, build with the module, stage objs/ where prober_resolve expects it
mkdir -p /tmp/srv && cd /tmp/srv
curl -fsSL -o srv.tar.gz 'https://nginx.org/download/nginx-1.29.0.tar.gz'
tar -xzf srv.tar.gz --strip-components=1
./configure --with-compat --add-dynamic-module="$HARNESS_ROOT/t/module"
make -j"$(nproc)"
mkdir -p "$HARNESS_ROOT/.build/nginx-1.29.0"
cp -r objs "$HARNESS_ROOT/.build/nginx-1.29.0/"

# Run scenarios against the built module
cd "$HARNESS_ROOT"
PROBER_ROOT="$PWD" \
PROBER_MODULE=ngx_http_test_ref_module.so \
PROBER_DIRECTIVE=test_ref_probe \
PROBER_PROBE='test_ref_probe;' \
    ci/prober/test-scenarios.sh nginx 1.29.0
```

`--without-http_rewrite_module` must NOT be passed: the scenario confs use
`return 200`, which is a rewrite-module directive.

### Scenarios that were once skipped

A scenario that cannot run ships a `requires` gate reporting why, so it shows
as a TAP skip with a reason rather than quietly not running. No checked-in
scenario is skipped today; both that were are recorded here because each was
unrunnable from the day it was written and nothing noticed until CI first
booted a server:

- **`keepalive-bleed`** — needed `pipeline N` with per-response expects. The
  prober's read loop read to EOF, so every rule had to ask for
  `Connection: close`, and a rule that closes the connection is not testing
  keepalive. Un-skipped once the framing-aware reader and the `block` pipeline
  DSL landed; it now asserts per-response non-bleed across a 3-block pipeline.
- **`multi-worker`** — its `worker_processes 4` conf ran afoul of the
  same-master pid oracle until the `PROBER_ALLOW_MULTIWORKER` opt-in below.

### Property-based fuzzing (`scenarios/property-fuzz`)

Every other scenario asserts a hand-written list of adversarial shapes.
`property-fuzz` instead **generates** a fixed-count batch of cases from a
checked-in corpus, through a deterministic PRNG, and holds every one of them
to the same oracle conn-delta and soak-delta use: `delta fds == 0`, `delta
pool.cycle_used == 0`, and the worker stays the same pid throughout (the
default oracle every case gets — see `pid_may_change` above). No new C code:
it is a `driver.sh` that writes a `.rule` file and hands it to the stock
prober.

- **Fixed iteration count (40), never a wall-clock budget** — so the fast leg
  and an ASan-instrumented leg run the identical generated program, and a
  failure reproduces across both.
- **xorshift64 in `gawk`**, seeded from a checked-in `seed` file — not
  `$RANDOM`, which is implementation-defined per bash build. Same seed
  reproduces the same rule byte for byte; `seed + 1` must differ, and both are
  asserted as real TAP tests inside the driver, not merely claimed.
- **`corpus/*.frag`** — one already-escaped request per file (odd header
  casing, an oversize header value, a missing Host, a chunked body, an
  unusual method, embedded control bytes, …). A new regression is pinned by
  adding one file, a one-file reviewable PR.
- **`backend`** — a static fakesrv fault script (`truncate`/`rst`/
  `accept_close`/`lie_bytes`, cycling), routed to by roughly a quarter of the
  generated cases via `/mc`, so the upstream-failure teardown path
  (`ngx_http_upstream_finalize_request`) is exercised on every run, not just
  the request-shape path.
- **The saved rule is the reproduction recipe** — every generated file is
  written to `$PROBER_PREFIX/property-fuzz.generated.rule`, named in the TAP
  diagnostic on failure, and the driver re-runs that exact saved file a
  second time (test 4) to prove replaying it reproduces the same verdict.

See `ci/prober/scenarios/property-fuzz/driver.sh`'s header comment for the full
non-vacuity accounting (three claims, three proofs) and cross-links to the
`mutate.sh` entries and the documented leak negative-control run.

### Stateful property-based fuzzing (`scenarios/stateful-property-fuzz`)

Where `property-fuzz` throws a batch of independent request *shapes* at a fresh
connection each, `stateful-property-fuzz` draws a fixed-count **sequence of
stateful steps** from the same style of deterministic `gawk` xorshift64 PRNG and
walks it in order: connection reuse (keepalive pipeline), client `abort`/
half-close, upstream faults *and* server-lifecycle events — a `SIGHUP` reload
and a `SIGKILL` of the serving worker — interleaved. Request steps run as stock
`.rule` batches (the whole `property-fuzz` generator, reused); after every
lifecycle event the driver runs five **checkpoint oracles**:

- **C1 lineage** — the answering worker is still a child of the *original*
  master (a master that died moves `ppid` or stops answering).
- **C2 no forbidden death** — no `SIGSEGV`/`SIGABRT`/`SIGBUS` worker exit, and
  the `signal 9` count equals exactly the number of kills this run sent (an
  unsent kill or a cascade reds). Exactly `worker-death`'s non-vacuity control,
  folded into every kill step.
- **C3 cycle-pool settlement** — *generation-scoped*: a kill re-forks the same
  cycle so the footprint must match exactly; a reload builds a new cycle so it
  re-baselines but must not climb past a running high-water mark (a per-reload
  cycle-pool leak grows monotonically and breaches it).
- **C4 generation coherence** — after a reload `config_generation` must strictly
  advance and settle (`prober_config_wait` streak — the reload was *absorbed*,
  not rejected-and-old-cycle-kept); after a kill it must hold (a bump would mean
  a spurious reload).
- **C5 zone/probe coherence** — the probe still parses and reports the expected
  `zone.present` after the event.

Determinism and replay work as in `property-fuzz`, with one difference stated in
the driver header: a kill's respawn pid and the shared fakesrv counter make
byte-identical prober-TAP replay impossible, so the replay guarantee here is
**plan-level** — the same seed regenerates the byte-identical step plan (the
`$PROBER_PREFIX/stateful-property-fuzz.plan` file, named in every failure
diagnostic), and each request batch is separately saved as `batch-N.rule` for
`./prober` reproduction. USR2 binary-upgrade is deliberately out of the step
alphabet (it needs the `PROBER_DAEMON_MODE=on` contract, incompatible with the
mandatory `daemon off;`); the USR2 lifecycle is owned by `usr2-mid-transfer` /
`backend-usr2-keepalive` / `usr2-state-machine`.

See `ci/prober/scenarios/stateful-property-fuzz/driver.sh`'s header for the full
non-vacuity accounting — two `mutate.sh`-wired claims (PRNG determinism, plan
persistence) plus four documented manually-run driver mutations, one per
checkpoint oracle C1–C4.

### Named fault matrix (`scenarios/fault-matrix`)

Every named upstream fault the fake backend can express — `rst`, `truncate`
(short read), `lie_bytes` under/overcount, `drip`, idle `close_after` — reaches
a *different* nginx upstream error branch
(`ngx_http_upstream_finalize_request` + the memcached upstream module), and
after that branch has run the request pool and the upstream connection must be
back to exactly what a clean request would leave. `fault-matrix` sweeps them:
one fakesrv script arms all six, each pinned to a distinct 1-based get ordinal
(`on=get:<nth>`), and the driver issues the gets in order so get *N* triggers
exactly matrix row *N* — a stable, byte-reproducible `site:nth` injection with
no timer and no race.

The matrix itself is `matrix.tsv` beside the driver, the plan's required record
`branch → fault → fast target → resource oracle → mutation`; the table, the
backend script and the driver are three views of one list (the driver's plan
count is `2 × row count + 1` — each row gets a fault-fired assertion and a
resource-neutrality assertion — so a drift between the three reds the
scenario). `memcached_read_timeout` is pinned to `200ms` (not a round `1s`):
nginx applies it *between* successive reads, not to the whole response
(`ngx_http_memcached_module` docs), so it has to sit strictly between the
`drip` row's 50ms inter-chunk gap and its ~800ms total transfer time — a
timeout at or above 800ms lets `drip` complete as an ordinary slow-but-clean
transfer and never reach the read-timeout branch its own row claims.

Each row asserts two different things, in order:

- **Fault fired — read from the backend JOURNAL, not inferred.** fakesrv
  journals `{"ev":"fault","nth":N,"action":"...","applied":true|false}` the
  moment it decides to run a fault (`journal_fault()`, `fakesrv.c`); the driver
  polls for THIS row's own `nth`+`action` pair before trusting anything else. A
  backend that silently drops or misnumbers a fault (stale `matrix.tsv` row, a
  deleted `fault` line) serves an ordinary correct reply — the get-ordinal
  guard still matches and the resource oracle still reads clean baseline — so
  without this check every row would print `ok` for having tested nothing. This
  same poll is also what synchronizes the final `close_after` row: its socket
  close is asynchronous on fakesrv's own event loop, and polling to
  `applied:true` is the one wait between issuing that get and taking the
  resource snapshot, so the probe cannot race ahead of the fault being armed.
- **Harness-owned resource neutrality** read from the probe, not the faulted
  reply's status/body (that is `backend-lying-length` / `backend-rst-midreply`):
  - **`cycle_used` — EXACT.** The long-lived cycle pool is deterministic
    (measured identical to the byte across 20 faulted gets); a per-request
    cycle-pool leak on any branch makes it climb. This is the primary oracle.
  - **`fds` — CEILING.** The keepalive upstream pool parks a connection
    between requests, so the worker's fd count legitimately oscillates by one;
    the oracle is therefore a monotonic-growth backstop (baseline = the max
    settled count, a row fails only if it *exceeds* it — a leaked descriptor
    climbs to `baseline + N`, a parked keepalive fd never does), not an
    equality.
  - worker liveness (per-row pid + an error-log signal-death backstop).

Non-vacuity: the fault-fired oracle's own neg-control is deleting a backend
`fault` line — proven by hand (removing `drip`'s line reds its row's fault-fired
assertion and raises the scenario's exit status; restored, re-verified clean).
The resource-neutrality oracle is proven by documented baseline-corruption
controls — the sanctioned fallback used by `stateful-property-fuzz`'s C1–C5.
One is `mutate.sh`-wired (corrupting `BASE_USED` reds every row, proving the
exact `cycle_used` oracle fires and raises the exit status); the fds-ceiling
control is documented-only because `fds` oscillates. Weekly-lane sweep
(`impact.map` `SLOW`), like `property-fuzz` — PR runs only sites mapped from
the diff.

### Deployment canary / shadow verifier (`scenarios/deploy-canary`)

An external sidecar that drives a fixed, synthetic GET/HEAD request plan at a
CONTROL server, then at a CANDIDATE server, and diffs what each answered.
Design pass: `memory/labs/nginx-module-testkit/design-p2h-canary.md`.

- **Sequential boot, one conf.** There is no "previous release" tree to diff
  against in this harness, so control and candidate are the *same*
  nginx/ref-module binary booted twice from the *same* checked-in
  `nginx.conf` — `run-scenario.sh`'s own boot is control, and `driver.sh`
  captures its tuples, `prober_stop`s it, then reboots the identical rendered
  conf as candidate. Neither server is ever live at the same time as the
  other; the driver alone holds both result sets, which is the "external
  sidecar" isolation the design means, not a network service.
- **The request plan** is four fixed requests (GET `/`, HEAD `/canary`, GET
  `/canary`, GET `/__probe`) issued identically to both legs — no writes, no
  timers, no random, so "no PII/credentials in the plan" holds by
  construction: there are none to redact.
- **The oracles (O1–O8):** status/headers/body diffed per request (O1–O3,
  headers masked the same way `prober_probe_normalize` masks run-identity
  probe fields), no candidate worker death (O5), no monotonic cycle-pool or
  RSS growth on the candidate across a post-warmup slope sweep (O7, skipped
  on a sanitizer build for the same reason `rss-slope` skips it — ASan dirties
  its own pages). Latency bucket (O4), lineage (O6) and fd neutrality (O8) are
  documented manual neg-controls in `driver.sh`'s header, the same tier as
  `rss-slope`'s and `fault-matrix`'s own by-hand controls — the repo cannot
  mutate nginx's own timing/fork/fd-holding machinery in-budget.
- **Verdict + evidence bundle.** `promote` iff every oracle is zero-diff (the
  NULL canary, candidate == control, is the default unmutated-tree run);
  `rollback` iff any oracle trips, naming the first tripped oracle and its
  control-vs-candidate values in a small evidence bundle written to the run's
  temp prefix (never committed).
- **Arming a fault is driver-local, not a conf edit.** `CANARY_ARM_SED`, empty
  by default, is a `sed` program `driver.sh` applies to the *rendered* conf
  strictly between the control capture and the candidate reboot — patching
  the checked-in `nginx.conf` directly would arm both legs identically (D-2:
  one conf, read at both boots) and every differential oracle would read a
  false "equal". `EXPECT_SIG9` (O5) and `SLOPE_CEIL_ADJUST` (O7) are corrupted
  the same way `fault-matrix` corrupts `BASE_USED` — the branch under test is
  nginx's own crash/pool-bookkeeping machinery, which this repo cannot mutate
  in-budget, so the oracle's own expectation/bound is corrupted instead,
  proving the comparison is live and raises the exit status.
- Weekly-lane sweep (`impact.map` `SLOW`), like `rss-slope` and
  `stateful-property-fuzz` — two boots plus a slope is not the PR path.

### Reload accounting (`scenarios/reload-cycle`)

A reload builds a new cycle and must release the old one. A module that
allocates or opens something per cycle and never releases it fails silently:
nothing errors, nothing logs, and the server grows one cycle's worth on every
`SIGHUP` for as long as it runs. `reload-cycle` reloads eight times and asserts
that reload *K* costs exactly what reload 1 did.

- **The comparison is exact, not banded.** Every cycle is built by parsing the
  same config with the same binary, so `pool.cycle_used` / `cycle_blocks` /
  `cycle_large` and the worker's `fds` are identical across a healthy series
  (measured on nginx 1.29.0, nginx 1.31.3 and angie 1.12.0). A band would be
  the weaker claim for no gain.
- **Every snapshot is taken after the old cycle has drained**
  (`prober_drain_wait`). `prober_signal_wait` returns when a *new* worker
  answers — at which point the old one is still alive, and both the master and
  the new worker hold handover channel descriptors that belong to no cycle.
  Measuring in that window gave 10, 11 or 12 fds for the same healthy series on
  the same box: the exact shape of a scenario that only fails on a loaded
  runner.
- **The master is asserted separately**, because the worker-side counters can
  only ever see the cycle the worker was forked into. `/proc/<master>/fd` is
  the sharp oracle (a leaked listening socket or old-cycle descriptor is
  countable and deterministic); `/proc/<master>/statm` is a deliberately coarse
  backstop, since an allocator that does not return pages to the OS hides a
  small leak from RSS entirely. Both are skipped **visibly** where `/proc` is
  unreadable, and the RSS one is skipped on sanitized builds (`PROBER_SANITIZED`,
  exported by `prober_heap_env`): ASan's quarantine and shadow state dominate
  the measurement — the same series grew the master 21 pages unsanitized and 402
  under ASan — and widening the band to fit that would leave a gate that can no
  longer fail.
- **A worker that never exits is itself the leak**, so the drain is asserted as
  a result and not only used as a precondition.

Both negative controls are documented in the driver header and were run: a
sub-pagesize allocation from the cycle pool that grows with the cycle count
reds only the `cycle_used` comparison (a page-sized one lands on the large list
instead — the reason the scenario asserts all three pool counters), and a
descriptor opened per config load reds the worker `fds` comparison and the
master descriptor count together.

### `reload-mid-fault` — a reload landing on top of an already-failing request

Every reload scenario above proves a reload absorbs *clean* work in flight
(`backend-reload-inflight`, `hup-storm-mid-transfer`, `reload-compressing`);
`fault-matrix` proves the upstream error branches clean up correctly, but only
at an idle moment. Neither combination is tested: a reload landing while a
request is *already failing* upstream, which is exactly where an unbalanced
allocation or a leaked upstream descriptor becomes visible —
`ngx_http_upstream_finalize_request`'s error-cleanup path and the reload's own
worker-drain teardown now run concurrently on the same worker, instead of at
two separate idle moments.

The upstream fault is a `drip` paced slower than a pinned
`memcached_read_timeout` (400 ms between 4-byte chunks against a 150 ms
budget — `memcached_read_timeout` applies *between* successive reads, the
same citation `fault-matrix`'s `nginx.conf` uses), so nginx's own upstream
read genuinely times out mid-transfer: a real upstream failure, not a
slow-but-clean transfer. `rst`/`truncate`/`lie_bytes` were considered and
rejected — fakesrv's fault vocabulary applies exactly one action per get and
none of those three can be dripped (each sends its reply in one shot), so
none can hold a connection open long enough to genuinely straddle a `SIGHUP`.

A single fixed get ordinal (`on=get:2`, after one clean warmup get settles the
worker) arms the fault, so which fault fires never depends on timing or a
random draw — only the read-timeout's real-time race is time-based, and it is
sized with a 2.7x margin so no non-pathological host blurs the cross.

Oracles: the held request must NOT complete as a clean 200 (proves the fault
actually fired, the anti-vacuity check for this scenario's own failure mode);
the reload must be absorbed while that failing request is in flight; the new
worker's fds/cycle-pool counters must be allocation-neutral across an extra
clean request taken after both the fault's cleanup and the reload's drain
complete (two quiescent post-drain snapshots, `reload-compressing`'s technique
— a direct pre-fault-vs-post-reload compare reads a reproducible ~3.5 KB
`cycle_used` gap that is the same "first post-reload fork carries a one-off"
artifact `hup-storm-mid-transfer` documents, not a leak); no worker died by
signal; the upstream saw the held get exactly once (the timeout was finalized,
not retried); and the reloaded worker serves a clean request afterwards.

Negative control (documented in the driver header, run by hand): corrupting
the first resource-neutrality reading by one byte (`FIRST_USED - 1`) reds the
oracle by exactly the assertion it exists to prove — `not ok 4 - the new
worker's resource state grew after an extra request` — restored and
re-verified clean.

Why the probe and not `t/*.t`: every fault and every reload here could be
thrown at a plain Test::Nginx suite too, but a worker that leaks the upstream
fd or a cycle-pool block *specifically* on the "reload landed while the
read-timeout cleanup was running" branch still returns a plausible 502/504 and
a plausible "worker process ... exiting" log line — nothing in a `.t` file's
assertion surface can tell that apart from a worker that cleaned up correctly.
The unique oracle is the in-worker fd count and cycle-pool footprint read from
the probe after both the fault's cleanup and the reload's drain have
completed.

### `reload-soak` — 100 reloads under concurrent traffic

`reload-cycle` reloads an idle server 8 times; `reload-soak` reloads it **100
times while a background load loop keeps requests in flight across every
signal**. The higher count turns a per-cycle leak from a handful of ambiguous
steps into an unmistakable climb, and the concurrent traffic exercises paths an
idle reload never touches — request cleanup on the retiring worker, and the
listen-socket handover while it is being `accept()`ed on.

The leak oracles are `reload-cycle`'s: the worker `cycle_used`/`cycle_blocks`/
`cycle_large` counters are **exact-equal** across the whole series (taken after
`prober_drain_wait` confirms each old cycle's worker has exited), and the master
descriptor count is flat before vs after. The one deliberate difference is that
the worker **fd count is not** in the exact-equal set here: under load a
background connection can be mid-flight on the freshly-drained worker at snapshot
time (10 vs 11 fds on a few of the 100 reloads), so an exact fd assertion would
flake on one in-flight request rather than a leak — a leaked descriptor still
climbs the *master* fd count instead, which is the oracle that catches it. The
scenario adds one oracle of its own: the background stream must record **no
failed request** (and a non-empty stream), which is what gives "under load" its
teeth — a reload that dropped a connection or refused `accept()` during the
handover shows up there. The `cycle_used`/master-fd leak controls are inherited
from `reload-cycle` (same fields, same config-load site); the load and count are
proven here by driver mutation (force every request `bad` → the load oracle reds;
corrupt the pool-counter reference → the exact-equal oracle reds).

### `worker-death` — a killed worker's blast radius

Every reload scenario above sends `SIGHUP` and asserts that **no** worker died
by signal. `worker-death` is the mirror image: it `SIGKILL`s the single worker
while it is the one serving the probe, lets the master respawn it, and asserts
that the death was **contained**.

The load-bearing oracle is the non-vacuity control. A crash-respawned worker
keeps its master's pid — *measured*, not assumed — so "a different pid answers"
and "still a child of the same master" are both satisfied by a respawn and
cannot tell a crash from a reload. Without a **positive** assertion that a
worker exited on signal 9, every other oracle passes on a server that was never
killed at all. That assertion reads the `exited on signal 9` line out of the
error log, separately from any pid oracle, because the process-identity oracles
are blind to it. A companion oracle then requires **no other** signal death (no
`SIGSEGV`/`SIGABRT`/`SIGBUS`, no second signal-9) — a contained kill leaves
exactly the one line we caused.

The remaining oracles prove the master rode it out: the replacement's
`cycle_used`/`cycle_blocks`/`cycle_large` must **equal** the killed worker's (a
fresh fork of the same master parsing the same already-loaded config — no
reparse, so identical), the master's descriptor count must be flat (it must
close the dead worker's channel fd), the replacement's `ppid` must still be the
original master (the master itself did not die), and a strict prober case proves
the replacement serves a clean 200. The kill's `[alert]` log line is exempted
via the scenario's `env` (`PROBER_ALLOW_LOG`), pinned to `signal 9` only so a
fault signal still reds the log scrape as a backstop. Non-vacuity is proven by
driver mutation (`kill -9` → `kill -0` kills nothing → the signal-9 oracle reds;
corrupt the pool-counter reference → the footprint oracle reds).

### `reload-config-version` — is the server running the config you just loaded?

`reload-cycle` above answers "did a new cycle appear, and did the old one go
away". Neither of its oracles — `prober_signal_wait` ("a different worker pid
answers") and `prober_drain_wait` ("the master is back to its worker count") —
can say **which configuration** the answering worker is running. Both hold
perfectly while the server still serves the old one:

- **A reload nginx rejected.** A config that fails to parse or bind leaves the
  running cycle exactly as it was: the master logs `[emerg]` and keeps going,
  nothing exits non-zero, and the old worker keeps answering. A scenario
  asserting on the new config's behaviour asserts against the old one and
  reports a pass. This is not hypothetical — it is negative control A in the
  driver, and with it planted every other oracle in the scenario (no
  signal-death, drained, final worker serves cleanly) stays **green** while
  all five reloads are silently rejected.
- **Overlapping reloads.** A second `SIGHUP` arriving while the first is still
  being absorbed leaves more than one new cycle in flight, and "a new pid
  answered" cannot say which owns it.

The oracle is `config_generation`, a counter the master bumps once per config
**load** and every worker of that cycle inherits through `fork()`.
`prober_config_wait HOST PORT WAS_GEN STREAK TIMEOUT_MS` requires the new value
to be read `STREAK` times **consecutively**, each on a fresh connection, so a
single read that happened to land on the new worker while the old one is still
accepting cannot settle it. The streak is the probabilistic half; the drain
wait, called alongside it, is the deterministic half — neither replaces the
other and the scenario uses both.

It is deliberately **not** angie's `cycle->generation`: stock nginx has no such
field, so a gate built on it would be silently absent on every nginx leg. The
harness keeps its own counter, which is a plain process global because the only
writer is the master, during config load, strictly before it forks the workers
that read it. It does not survive a binary upgrade (`execve` resets the image),
which is correct for a `SIGHUP` gate and is why the `usr2-state-machine` scenario
below uses the pidfile/`.oldbin` observables instead.

A counter that only asserts about itself would be the classic vacuous gate, so
each reload **rewrites the rendered conf** (a `marker=<n>` in the `/` response
body) and the driver requires the served body to carry the new marker before it
accepts the generation as meaningful. Negative control B neutralises that
rewrite: the generation still advances — reloading an identical config is still
a config load — so the generation oracle stays green and the marker oracle reds,
proving the two are not restating each other.

### `usr2-state-machine` — the binary-upgrade master-generation state machine

A `SIGUSR2` binary upgrade execs a **new master** from the old master's inherited
fd table, so the two generations coexist for a window: the old master renames its
pidfile to `nginx.pid.oldbin` and the new master writes a fresh `nginx.pid`, both
naming a distinct live process. This scenario observes that state machine directly
— pidfile hand-off, `.oldbin` lifecycle, and the survival of the **inherited
listen socket** — where `backend-usr2-keepalive` proves the orthogonal half (the
new-exec worker reconnects an upstream keepalive pool it did not inherit). Split
by subject so a failure names which half broke.

The headline oracle is the listen socket. Because the new master execs from the
inherited fd table, its listening socket is the *same kernel socket object*, not a
fresh `bind()`. The driver reads the inode behind the master's listening fd from
`/proc/<master>/fd` (cross-checked against a `LISTEN` state in `/proc/net/tcp`)
and asserts it is **identical** on the old master, the new master, and the new
master *after the old one is QUIT* — a re-bind would change the inode and would
race a `bind()` against the still-held socket. The port must also keep answering
across every transition (a surviving socket is meaningless with a refused window).
Linux-only: skipped visibly where `/proc` fd links are unreadable.

The `.oldbin` teardown oracle then retires the old master (`WINCH` to drain its
workers, `QUIT` to stop it, targeting the pid from `nginx.pid.oldbin`) and requires
`nginx.pid.oldbin` to **disappear** while `nginx.pid` still holds the new master —
a lingering `.oldbin` is a stuck upgrade. Runs under `PROBER_DAEMON_MODE=on`: USR2
is silently dropped under `daemon off` (see `check_conf` and the fake-upstream USR2
notes), so the boot contract demands a daemonized master tracked by its pidfile.

### Running scenarios under valgrind (optional)

Every scenario asserts fd/pool deltas through the probe's own accounting --
real, but blind to a leaked `malloc` the probe never had a counter for, a
one-time startup leak no delta catches, or a read of freed memory that
happens not to corrupt anything the assertions look at. `valgrind --tool=
memcheck` catches that class directly, at the cost of running the whole
worker 20-50x slower -- too slow for the fast PR gate, but feasible in an
optional separate job (e.g. scheduled weekly in a consumer's CI).

The gate is **belt and suspenders**, not exit-code-only, because memcheck's
own default behaviour makes exit-code-only a vacuous check: it reports every
finding and still exits 0 unless told otherwise. `--error-exitcode=99` is the
belt (fails the process valgrind directly launched); `prober_scrape_valgrind`
in `ci/prober/lib.sh` is the suspenders (greps every `$PROBER_PREFIX/logs/
valgrind.*` log for `ERROR SUMMARY: [1-9]` or `definitely lost: [1-9]`,
regardless of what any exit code said). `ci/prober/valgrind_scrape_test.sh`
proves the pairing is load-bearing: it plants the same leak, shows
`--error-exitcode` catching it and, immediately after, shows the identical
finding exiting 0 *without* that flag -- the vacuity the belt-and-suspenders
shape exists to close.

`ci/prober/valgrind-scenarios.sh` is the entry point: it exports
`PROBER_VALGRIND` (the valgrind command line, no `--log-file` -- `lib.sh`
appends that once the per-run `$PROBER_PREFIX` is known) and
`PROBER_TIMEOUT_SCALE=40`, then runs `test-scenarios.sh` so every scenario in
the tree boots its server under valgrind and folds the memcheck verdict into
its own TAP line. `PROBER_TIMEOUT_SCALE` is the knob that keeps a slow
memcheck run from timing out for HARNESS reasons unrelated to the module: it
scales the prober's own `-t` read timeout, the boot readiness loops, and
`prober.c`'s `DELTA_SETTLE_TRIES` retry budget for the fd/pool delta to
settle after a request's async close -- all three, or a valgrind run reads as
a false leak or a false hang purely from being instrumented. See
`ci/prober/valgrind.supp` for the (deliberately narrow, nginx-core-only)
suppression file consumers inherit for free.

Consumers copy the job below, not `valgrind-scenarios.sh` itself -- it is not
a reusable `workflow_call`, because a cross-repo pin (on top of the module's
own nginx-version pin and the harness submodule pin) is a fourth thing to
drift, for a template short enough to copy-paste and read in one sitting:

```yaml
# Consumer template: schedule a valgrind job in your own CI (optional).
# Stagger off the hour and off other heavy jobs sharing a runner, since
# a shared self-hosted box cannot absorb several heavy crons at once.

name: valgrind (optional)

on:
  schedule:
    - cron: '17 3 * * 1'   # Monday 03:17 UTC; adjust for your schedule
  workflow_dispatch:

jobs:
  valgrind-scenarios:
    runs-on: ubuntu-24.04   # or your self-hosted label
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true   # the harness lives at t/harness

      - name: install valgrind
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends valgrind

      - name: build nginx (DEBUG, not ASan -- valgrind and ASan do not mix)
        run: |
          # your existing debug-build step, e.g.:
          bash tools/ci-build.sh nginx 1.31.3 debug

      - name: run scenarios under valgrind
        working-directory: t/harness/prober
        env:
          PROBER_MODULE: your_module.so
          PROBER_DIRECTIVE: your_probe_directive
          # PROBER_TIMEOUT_SCALE defaults to 40 inside valgrind-scenarios.sh;
          # override lower here on a fast dedicated runner.
        run: |
          ./build.sh
          ./valgrind-scenarios.sh nginx 1.31.3
```

### PR-lane counterpart: `ci/prober/pr-memcheck`

`valgrind-scenarios.sh` is the optional whole-server memcheck (run as a scheduled
job in a consumer's CI, not in this repo). Its PR-lane counterpart is
`ci/prober/pr-memcheck` (P2-F): it consumes `verify-impact`'s diff-selected targets
and runs only the **direct-callable** ones (the unit test binaries and fuzz targets
a change actually touched) under `--leak-check=full --errors-for-leak-kinds=definite
--track-origins=yes`, inside a 45 s outer budget, so a PR pays seconds for its own
targets' leak + uninitialised-read surface instead of minutes for the whole tree.

```sh
ci/prober/pr-memcheck --base <merge-base-sha>   # local-only tool; self-test (pr_memcheck_test.sh) runs in the selftest job, but the adapter is not wired into a PR-lane CI job
```

It **refuses** any selected target that needs a full nginx boot (a `scenarios/*`
row) rather than blow the budget on it, and the refusal names both where that
coverage does live — the native scenario oracles on the PR path
(`test-scenarios.sh`) and the optional whole-server memcheck (`valgrind-scenarios.sh`) —
so an expensive check is never silently skipped. The fd-leak class stays with
the optional whole-server run: `pr-memcheck` does **not** pass `--track-fds`,
because the forking `expect_die` unit binaries inherit the parent's temp-file
descriptor into each short-lived child, which `--track-fds` would report as a leak
in every one. `ci/prober/pr_memcheck_test.sh` proves the memcheck verdict, the refusal
(with a blanked-oracle negative control), the budget refusal and the empty-selection
path are all non-vacuous.

## Ideas and opportunities — ways to break a module we do not yet try

The mission at the top of this file says the tool should break the module under
test by any means available. This is the running list of means we do **not** yet
have, kept here rather than in a private note so a consumer can see the shape of
what is coming and argue for what they need.

Each entry says what it would attack and what is missing today. None is
committed work; a row graduates by becoming a scenario with a mutation-proven
oracle. Ordered roughly by attack value per unit of effort.

**Protocol surface we never exercise.** Every scenario speaks HTTP/1.1 cleartext.
A module that touches request bodies, headers or connection state behaves
differently under other protocols, and none of those paths are attacked:

- **TLS.** Shipped, both halves. The prober has a TLS client leg —
  `http_connect()` and `http_request()` take an optional `http_tls`, and
  `ci/prober/http_test.c` exercises the handshake, a round-trip, side-table
  teardown and a plaintext-peer control against a self-signed in-process
  fixture. `ci/prober/scenarios/tls-listener` is the scenario half: a real
  `listen … ssl` server, a self-signed certificate minted into the run prefix
  at boot (never committed, so it can neither leak a key nor expire into a red
  suite), and four rule cases over the TLS transport. A scenario opts in by
  setting `PROBER_TLS=1` in its `env` file, which run-scenario.sh expands into
  `prober --tls`; the `.rule` grammar stays transport-agnostic, so the same
  rule file runs against a plaintext and a TLS listener unchanged.

  Two limits worth knowing. `concurrent` cases are refused under `--tls`
  (`http_exchange_concurrent()` drives its own connect loop and never
  populates the fd→`SSL*` side table), and the client does not verify the
  peer certificate — it is a transport for a harness pointed at a local
  fixture, not a security boundary. What is still open is a module doing
  something at the connection layer: the SSL handshake is a rich source of
  allocation-failure and lifecycle bugs, and nothing yet drives a fault into
  one.
- **HTTP/2 and HTTP/3.** Different framing, different body delivery, different
  connection lifecycle. A module correct on HTTP/1.1 can leak per-stream state
  on h2. Larger effort (the prober's reader is HTTP/1.1-framed), but this is
  where real production bugs live for anything stream-aware.
- **`stream{}` (raw TCP/UDP).** Already parked pending a consumer that targets
  stream; the trigger to unpark is a stream-shaped module asking.

**Attack shapes the rule language cannot express yet.** These need a directive,
not a scenario:

- **Body-boundary hostility.** `send_slow` splits the send, but the rule
  language could not (until now) send a body that lies in the other direction
  (declared longer than sent, so the body arrives truncated), trickle a chunked
  body one byte per chunk, or
  send an oversized `Content-Length` and stop. `backend-lying-length` does
  this to the *upstream*; the three sub-attacks below are the module's own
  request path.
  ~~declared longer than sent, then stop~~ **GRADUATED:**
  `rules/stock/short-body.rule` sends fewer body bytes than the declared
  Content-Length, half-closes with `shutdown 1`, and asserts
  `expect_close_within` -- no new directive needed, `send` already puts
  arbitrary mismatched bytes on the wire.
  ~~oversized Content-Length and stop~~ **ALREADY GRADUATED:**
  `rules/stock/huge-content-length.rule` (predates this row) sends Content-Length
  values at and past every integer boundary nginx has, with no body at all;
  this backlog line was stale against the tree.
  ~~Trickling a chunked body one byte per chunk is still open: `send_slow`
  paces raw bytes irrespective of chunk framing, so pacing at chunk-unit
  granularity (one `<size>\r\n<data>\r\n` unit per pause, not one arbitrary
  byte-count slice) needs a directive, tracked separately.~~ **GRADUATED:**
  `rules/stock/chunked-trickle.rule` uses the `send_slow_chunks` directive to pace
  the span at chunked-framing granularity (one complete `<hex>[;ext]\r\n<data>\r\n`
  unit per pause, the terminating `0`-chunk included), shipped in PR #155.
- **Concurrency as an attack.** ~~Every scenario is sequential.~~ **GRADUATED:**
  the `concurrent N` directive (documented above) issues N requests in flight and
  asserts the same zero deltas, opening the shared-memory/per-worker race class to
  the prober. What is still sequential is the *scenario* layer: a scenario cannot
  yet overlap two *different* requests, only N copies of one, so a race that needs
  request A and request B to interleave remains out of reach.
- **Fault injection during a lifecycle event.** The `fault_*` knobs and the
  reload scenarios exist separately. Arming a failure *during* a reload, a
  binary upgrade or a worker shutdown attacks the teardown path, which is
  exactly where unbalanced allocations become visible and where almost nobody
  tests. **Partially graduated:** `reload-mid-fault` covers the upstream half —
  a reload landing on a request already failing upstream — using a fakesrv
  ordinal-keyed fault, which needs no hook and runs on the stock ref-probe legs.
  The *allocation* half is still open and is blocked on the fixture rather than
  on effort: `fault_slab=`/`fault_palloc=`/`fault_tempfile=`/`fault_accept=`/
  `fault_codec=`/`fault_codec_end=` arm
  through `ngx_test_probe_arm()`, which returns `NGX_DECLINED` unless the module
  under test registers a fault hook (`fault_set`, or `fault_set_global` for a
  module with no zone), and `t/module/` deliberately registers none. That half
  needs a real module fault site plus a consumer `.so`, the same boundary
  `fault-matrix` documents.

**Coverage-driven work.** Run `ci/prober/coverage-director.sh` and read the map for
*unreached* lines in a consumer's module rather than in our own code. An
unreached line in error handling is a line no test has ever forced to run, and
the `fault_*` knobs exist precisely to force them. This turns the coverage goal
into a generator of concrete adversarial scenarios instead of a number to chase.

**Sharper oracles on what we already do.**

- The `delta` oracles pin fds, pool bytes, slab and timers. A module can still
  leak in places nothing snapshots — cleanup handlers, resolver state. Each is
  a probe field somebody has to add before an oracle can assert on it.
- **Allocation-count oracles.** Every memory oracle we have reads *net
  occupancy*, which is blind to churn: ten thousand matched alloc/free pairs
  per request net to zero and read as clean. A per-request slab
  allocation/free **counter** in the probe turns that into a ceiling oracle —
  not "must be 0" (a leak) but "must be <= K per request" (a bottleneck).
  Cheapest row on this list: no new dependency, no new process, and
  `scenarios/alloc-per-request` is already the shape. The counter itself needs
  a hook or an interposition on the alloc path, where `fault_slab=` already
  sits. Finds slab thrash and an allocation in a path that should reuse; blind
  to anything CPU-bound at flat allocation.
- **Cachegrind ratio, generalized to a consumer's module.** `perf/cachegrind-scale.sh`
  proves the technique on `json_parse_n`; the class it catches in a *module* is
  the per-request scan over a shm structure that goes quadratic as the zone
  fills. The obstacle is stated in that script's own header: Cachegrind must
  **launch** the process it measures and cannot attach to a live worker. Two
  ways out — extract the hot function into a standalone driver the way the fuzz
  targets do, or boot the whole server under `valgrind --tool=cachegrind`. The
  second looks cheap here rather than expensive, because a consumer already
  MUST run `worker_processes 1` and `daemon off;`, which is exactly the
  single-process shape Cachegrind needs, and boot lives in one place
  (`ci/prober/lib.sh`) so it is an env knob rather than a rewrite. Cost is the
  ~20-50x slowdown, on that leg only. Assert the **ratio**, never an absolute
  instruction count: the ratio survives a compiler change, the absolute does
  not.
- **Not a profiler, and deliberately.** `perf` and flamegraphs answer "which
  line is slow", which is a human-read artifact and cannot red a PR — and on
  the current build host `perf` needs `perf_event_paranoid<=1` anyway. The
  right shape is a deterministic gate here plus a manual profiling pass when
  that gate fires, not a profiler wired into CI.

If you have a way to break a module that is not on this list, that is the most
useful thing you can contribute.

## Fake upstream (`ci/prober/fakesrv`)

A scriptable fake redis/memcached backend, for testing modules that talk to an
upstream cache. It exists because a **real** daemon is the wrong instrument for
the cases that matter: it cannot be made to truncate a reply mid-`VALUE`, to
declare a length it then contradicts, to reset after eight bytes, or to close a
parked keepalive connection at the moment of a reload — and those are exactly
the paths where a module's error handling either releases its resources or
leaks them.

It also **reports what it saw**. A real daemon cannot tell you whether a
connection was reused; the JSONL journal can, which turns "the keepalive pool
works" from an assumption into a one-line assertion.

```sh
ci/prober/fakesrv -script mc.backend -listen 127.0.0.1:0 \
               -portfile "$PROBER_PREFIX/backend.port" \
               -journal  "$PROBER_PREFIX/backend.jsonl"
```

`-listen …:0` binds an ephemeral port and writes the real one to `-portfile`
(atomically, before the first `accept()`, so a polling shell can never read it
half-written). `-journal` is the JSONL event log (documented below). `-errfile`
is an optional file where fakesrv's fatal errors are written (used by the harness
to report backend startup failures).

### Script format

Stanza style, mirroring `.rule`. The default with no faults is a **correct**
server backed by a real in-memory store:

```
proto   memcached
seed    hello  world
seed    empty  ""
fault   on=get:3     action=truncate    after=8
fault   on=get:*     action=lie_bytes   delta=+5
fault   on=set:1     action=rst
fault   on=connect:2 action=accept_close
fault   on=get:2     action=drip        bytes=1 ms=5
fault   on=idle      action=close_after ms=100
fault   on=get:4     action=raw         data=VALUE k 0 3\r\nAB\0\r\nEND\r\n
```

`seed <key> <value>` stores a value verbatim, with the same `\r \n \t \\ \" \0
\xNN` escapes the rest of the format uses. A bare `""` seeds a **zero-length**
value — legal memcached (`VALUE k 0 0\r\n\r\nEND\r\n`) and a classic
reply-framing off-by-one, since the payload is empty between two CRLFs. Only
that exact token is special: `"a"` keeps its quotes, and a `seed` with no value
at all stays fatal, because that form is far more often a typo than an
intention.

Faults are **overlays on correct behaviour**, keyed `(command-glob : occurrence)`.
That is the load-bearing design decision, and the obvious alternative was
rejected: a positional list of canned replies cannot express a keepalive test,
because the number of `get`s nginx will issue is precisely what such a test is
trying to discover — a reply list encodes the answer into the question.

`<nth>` is a 1-based occurrence counter (per command, per run) or `*` for every
occurrence. An exact match beats a `*` match, so a script can state a general
rule and except one occurrence from it. Two pseudo-commands cover what is not a
command: `connect:<nth>` fires as the nth connection is accepted, and `idle`
fires on a connection that has gone quiet.

| action | parameters | what it does |
|---|---|---|
| `truncate` | `after=<bytes>` | correct reply, cut after N bytes, then RST |
| `lie_bytes` | `delta=<signed>` | declared length disagrees with the payload |
| `rst` | — | TCP reset instead of a reply |
| `accept_close` | — | accept, then close without reading |
| `drip` | `bytes=<n> ms=<n>` | correct reply, N bytes at a time |
| `close_after` | `ms=<n>` | close this long after the connection goes idle (only for `on=idle`, unrelated to `close_after` in other faults) |
| `raw` | `data=<bytes>` | send these exact bytes instead |
| `cursor_never_zero` | — | RESP `SCAN` that never terminates |

**`on=idle` threshold:** A connection that goes quiet for longer than the idle
threshold fires the `on=idle` fault. The threshold is controlled by fakesrv's
`-idle-ms` flag (default: 50 ms). The harness does not currently pass `-idle-ms`
to fakesrv, so all `on=idle` faults use the 50 ms default. To use a different
threshold, modify the backend script or the harness invocation.

`raw` carries most of the adversarial surface — embedded NULs, oversize declared
lengths, a reply when none was due, `$-1` nil against a malformed near-miss. It
uses the same `\r \n \t \\ \" \0 \xNN` escapes as a rule file's `send`, through
the same lexer, so the two formats cannot drift on what a byte means.

An unknown `action=` is **fatal, never skipped**. A dropped fault leaves a
scenario exercising the happy path while its name and its TAP output both claim
otherwise — and a scenario that tests nothing passes very reliably.

### Journal

```
{"ev":"listen","port":41897}
{"ev":"accept","conn":1,"t_ms":12}
{"ev":"cmd","conn":1,"n":7,"cmd":"get","args":["hello"]}
{"ev":"close","conn":1,"by":"peer","cmds":5}
{"ev":"summary","accepts":1,"conns_max":1,"cmds":5}
```

The `summary` record is the point: `accepts==1 && cmds==5` proves the connection
was reused, `accepts==5` proves it was not. No amount of reading the module's
own logs settles that as directly.

### Verbs

The full memcached verb table is implemented so nothing draws an accidental
`ERROR` — but real *semantics* only for `get`/`set`/`delete`/`flush_all` plus
the RESP set a cache module sends; the rest return correct-shaped canned replies
(`VERSION 1.6.38-fake`, a fixed `STAT` block, `OK`).

**It is deliberately not a real cache.** The moment a scenario needs eviction or
expiry, it should point at a real daemon instead — a fake that grows toward
being a real redis is a second implementation to keep correct, and its bugs
become indistinguishable from the module's.

## Consumer contract

One nginx.conf requirement and a handful of environment variables must be
honored for the harness to run correctly:

**`PROBER_PROBE` / `PROBER_PROBE_ZONE` (required when the conf uses `@PROBE@`)**

The probe location's body is the consumer's, not the harness's — see the
placeholder table under [Scenarios](#scenarios) for the full rendering
contract. `PROBER_PROBE` carries the module's probe directive and
`PROBER_PROBE_ZONE` any http-level declaration it depends on:

```sh
PROBER_PROBE='mymod_probe probezone;' \
PROBER_PROBE_ZONE='mymod_ban_zone probezone:1m;' \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
ci/prober/run.sh nginx 1.31.3
```

A conf using `@PROBE@` with `PROBER_PROBE` unset bails at render. Both values
are escaped before substitution, so a directive containing `&`, `\` or `#`
renders literally rather than corrupting the conf.

**`worker_processes 1` (required in consumer conf)**

The pid oracle — which asserts that the worker pid does not change across
consecutive probe requests — only holds with a single worker process. With
multiple workers, the same healthy server answers each request with a
different worker, changing the reported pid on every case and causing
universal test failure. Because the consumer supplies the nginx.conf, this
cannot be enforced by shipping a default configuration. `run.sh` parses the
rendered config file and exits with a bail-out before the first case if
`worker_processes` is not exactly `1` — unless the scenario opts in with
`PROBER_ALLOW_MULTIWORKER` (below).

**`PROBER_ALLOW_MULTIWORKER` (environment variable, optional)**

Set to `1` (in a scenario's `env` file) to lift the `worker_processes != 1`
bail above. It exists for the one scenario shape whose *point* is behaviour
across several workers: there, a healthy server answers consecutive probes from
different worker pids, so **every case must carry `pid_may_change`**, which
switches the oracle from "same worker" (pid) to "same master" (ppid). That
still catches the probe port being answered by a worker of a *different* master
(a rogue or leaked server), while tolerating the per-request worker rotation a
multi-worker server does by design. Setting this without `pid_may_change` on
every case reproduces the wall of false pid failures the bail exists to
prevent, so it is a per-scenario opt-in, never a run default. The `multi-worker`
scenario is the reference user.

**`PROBER_TLS` (environment variable, optional)**

Set in a scenario's `env` file to make the rules run speak TLS:
`run-scenario.sh` expands `${PROBER_TLS:+--tls}` into the prober invocation, so
any non-empty value arms it. The transport is process-wide rather than
per-case, because it is a property of the LISTENER — a scenario points the
prober at one port, and that port either speaks TLS or it does not. That keeps
the `.rule` grammar transport-agnostic: the same rule file runs unchanged
against a plaintext listener and a TLS one, which is what makes a differing
result evidence about the transport rather than about the rule.

The scenario is responsible for the server side (`listen … ssl` plus a
certificate) and for the fixture. `tls-listener` is the reference user: it
mints a self-signed certificate into `$PROBER_PREFIX` from its `env` file —
which is why the EXIT trap is armed above the env source, so a boot failure
cannot leak it — and gates on `ngx_http_ssl_module` being linked, because
`--with-compat` alone omits it.

The client does NOT verify the peer certificate (see `http_tls.verify` in
`http.h`): it is a transport for a harness pointed at a local fixture, not a
security boundary. `concurrent` cases are refused under `--tls` and fail
loudly, because `http_exchange_concurrent()` drives its own connect loop and
never populates the fd→`SSL*` side table — a silent plaintext fallback there
would make the case pass or fail for a reason unrelated to what it asserts.

**`PROBER_ALLOW_STALE_SO` (environment variable, optional)**

Set to `1` to drive a reference module `.so` that is older than the probe
sources under `src/`. By default the harness bails: a `.so` built before a probe
field was added still loads, still carries the directive, and still boots — it
simply omits that field, so the oracle reading it sees the absent-field sentinel
and fails closed. The red then lands on whichever *flavor* happens to hold the
older artifact, which reads as a flavor-specific bug in the diff under test.
That has cost a full session twice (a `.so` predating `ppid`; an angie `.so`
predating `smaps`/`fds_by_kind`), and CI never reproduces it, because CI
rebuilds every flavor from source on every run.

The check bails when the artifact is older than any
`src/ngx_test_probe*.{c,h}`, and names that source plus the artifact in the
bail. It reports the first such source it finds rather than the newest one —
the question is only whether the `.so` is out of date, and every match answers
it the same way. **Adding a probe
field means rebuilding the reference module for every flavor you run locally**,
or that field's own scenario skips itself green. A tree with no `src/` — a
consumer repo vendoring this harness and building its own module — has nothing
to compare against and is passed silently.

Set it in the environment of the command you run:

```
PROBER_ALLOW_STALE_SO=1 ci/prober/run-scenario.sh scenarios/<name> nginx 1.29.0
```

Unlike `PROBER_ALLOW_LOG` and `PROBER_ALLOW_MULTIWORKER`, **a scenario's `env`
file cannot set this one**. Those are read by `prober_check_conf` and
`prober_scrape_log`, which run after `run-scenario.sh` sources the scenario
`env`; this is read by `prober_detect_load`, several steps earlier, because the
load decision precedes rendering and boot. That asymmetry is deliberate: a stale
artifact is a property of your build tree, not of a scenario's requirements. The
opt-in is honoured only for the exact value `1`, so a stray `=0` cannot quietly
disable it.

**`PROBER_DAEMON_MODE` (environment variable, optional)**

Set to `on` (in a scenario's `env` file) to run the server with `daemon on;`
instead of the harness default `daemon off;`. It exists for exactly one
scenario shape: a **USR2 binary upgrade**. nginx drops the `NGX_CHANGEBIN`
signal when `getppid() == ngx_parent`, which always holds for a foregrounded
(`daemon off`) master whose parent is the harness's `&` launcher — so under the
default the upgrade is silently ignored, the master logs *"the changing binary
signal is ignored"*, and no new master ever forks. `daemon on;` lets the master
double-fork away from the launcher so the upgrade path is reachable.

Because a daemonized master is no longer `$!`, opting in also **requires the
conf to write its pidfile to `@PREFIX@/nginx.pid`**: boot then adopts the
master pid from that file, and teardown reads it (and `nginx.pid.oldbin`, where
a USR2 upgrade moves the retired master) rather than trusting `$!`. `check_conf`
bails if the opt-in is set without `daemon on;` or without that pidfile path.
A driver that upgrades the master mid-run does not need to thread the new pid
back to teardown — teardown re-reads the pidfile, so it always kills the live
generation. The `backend-usr2-keepalive` scenario is the reference user.

**`PROBER_ALLOW_LOG` (environment variable, optional)**

By default, `run.sh` treats any `[alert]`, `[crit]`, or `[emerg]` line in the
error log as a test failure — because a worker that crashes, finalizes a
request twice, or reuses a busy buffer logs at one of these levels, then
carries on serving. Without this gate, the suite passes while the bug ships.

However, fault-injection tests intentionally provoke failures to exercise
out-of-memory and allocation-failure paths. These tests arm the fault
injector to exhaustion, which nginx logs at `[crit]`, and the test must pass
despite the error. Set `PROBER_ALLOW_LOG` to an extended regex matching the
expected error line(s). Each matching line is reported in the test output but
not counted as a failure. The regex is matched per line against the full
error log scrape, so a pattern like `"no memory for"` exempts that specific
condition while leaving segfaults and other unexpected errors fatal.

```sh
PROBER_ALLOW_LOG='no memory for|slab' ci/prober/run.sh nginx 1.31.3
```

**`ngx_test_probe_arm()` in zero-hook mode (optional)**

If your module registers no fault hook at all (zero-hook mode — the generic
probe alone suffices), you **should still call `ngx_test_probe_arm()`** from
your HTTP handler before rendering the snapshot. Pass your zone if you have
one and `NULL` if you do not; `NULL` is a supported argument, not an error, and
is what routes a later `fault_set_global` registration. The harness allows a later
hook registration to arm or disarm faults, so a test that calls `arm()` now
can always be extended with a custom hook later without changing the test
code. If no hook is registered, the call is a no-op and returns `NGX_DECLINED`;
if a hook is later added, it takes effect immediately.

Call it in your HTTP handler as:

```c
(void) ngx_test_probe_arm(mlcf->probe_zone, &r->args);
```

The `&r->args` parse the HTTP query string for fault directives (e.g.,
`?fault_slab=5`). The return value is ignorable — both `NGX_OK` and
`NGX_DECLINED` are success. The timing matters: call `arm()` *before*
rendering the snapshot, so the response reflects the armed state.

## Runtime environment variables

Beyond the consumer contract above, several environment variables tune the harness's
behavior:

**`PROBER_BUILD` (optional)**

Explicit path to the build tree containing the `.so` under test. By default,
`prober_resolve` constructs it from `$PROBER_ROOT/.build/<flavor>-<version>`.
Set this to override the path — e.g., when using multiple build trees or
testing a pre-built `.so` from another location.

**`PROBER_BUILD_JOBS` (optional)**

Controls parallelism during the prober binary's own compilation. Set to `1` to
force serial compilation (useful on tiny or heavily-loaded runners, or when
bisecting a build race). Default: parallel, all compiles launched at once.

**`PROBER_PROBE_TIMEOUT` (optional)**

Wall-clock seconds to wait for each probe request to complete before killing it.
The harness reads the JSON response from the probe's TCP connection;
a stalling probe is bounded by this timeout so the suite never hangs. Default: 2 seconds.

**`PROBER_PROBE_ATTEMPTS` (optional)**

Number of consecutive probe requests to attempt before bailing on a server boot.
Each attempt is spaced 100ms apart to give the server time to stabilize.
Default: 3 attempts.

**`PROBER_TIMEOUT_SCALE` (optional)**

Multiplicative scale factor for all timing budgets throughout the harness: probe
timeouts, boot waits, reachability checks. A value of 2 doubles all timeouts
(e.g., 2-second probes become 4 seconds). Useful on slow runners or systems
under load. Constraints: must be a positive integer in the range 1..1000.
Default: 1 (no scaling).

**`PROBER_SCENARIO_JOBS` (optional)**

Number of scenarios to run in parallel. Default: CPU core count (from
`getconf _NPROCESSORS_ONLN`). Set to 1 for serial scenario runs, or to limit
parallelism on resource-constrained systems.

**`PROBER_SCENARIO_PORT_BASE` (optional)**

Base port number for parallel scenario runs. Scenario `N` (0-indexed) listens on
`PORT_BASE + N`, so slots do not collide on concurrent runs.
Default: 18120. Increase this if the default range conflicts with other services.

**`PROBER_TIMEOUT_SCALE` contract mismatch**

Note: `PROBER_TIMEOUT_SCALE` has two documented contracts that may differ:
`lib.sh:55` enforces 1..1000 and bails outside this range, while `prober.c:327`
silently falls back to 1 if the value is invalid or unset. This asymmetry should
be resolved (both should validate the same way).

## Writing a C unit test (the runner convention)

The harness runs its own parsers and assertion evaluators — the JSON reader, the
rule engine, the scrape splitters — as pure functions under a TAP self-test
suite that needs no server. A consumer module with C worth unit-testing in
isolation (a parser, a small state machine, a buffer walk) uses the **same
convention** rather than hand-rolling a shim runner: four labs modules grew four
slightly different ones before this was written down, which is three too many.

There is nothing to register. The convention is three rules:

1. **Name the file `*_test.c`.** `ci/prober/build.sh` globs `*_test.c` (and
   `../t/*_test.c` for probe-side units), compiles each into its own binary, and
   `ci/prober/test.sh` runs every one. Dropping a file in is the whole wiring step —
   *"a test that has to be registered in two places is a test that eventually is
   not run at all"* (build.sh). A rename that stops matching the glob is caught,
   not silently dropped: **zero discovered suites is a hard failure**, never a
   green no-op.

2. **Emit TAP with a `PLANNED` count.** `main()` ends with
   `printf("1..%d\n", PLANNED)` where `PLANNED` is a `#define` of the number of
   assertions, and each assertion prints `ok N - …` or `not ok N - …`. The plan
   line is load-bearing: a suite that dies after assertion 3 of a planned 10
   reports `1..10` with only 3 results, and the TAP consumer flags the gap — so a
   crash mid-suite fails, it does not pass on the assertions that did run. Bump
   `PLANNED` in the same commit that adds an assertion; a stale-low count hides
   the new one. (`schema_test.c`, `http_test.c`, `rules_test.c` are worked
   examples.)

3. **Shell-only checks use `*_test.sh`** — a separate glob (these are run, not
   compiled), same `echo "1..$PLANNED"` plan discipline. Use it for behaviour
   with no C entry point (a CLI, a driver helper); use `*_test.c` for anything
   callable as a function.

The suite runs before any server boots and, in CI, standalone twice (plain and
`SAN=1`); `test.sh` also turns on `MALLOC_PERTURB_`/`MALLOC_CHECK_` for the
un-sanitized pass so an uninitialised read or use-after-free in the tests
themselves surfaces as garbage instead of a quiet zero. That is deliberate: the
harness decides whether a module's run is green, so a defect *in the harness*
turns every rule that depends on it into a test that cannot fail — worse than a
missing test, because the run still reports success. Unit-testing the harness's
own logic without a server is how that class is caught at all. A consumer's own
C deserves the same treatment; this is where it goes.

**This is a runner convention, not a shared shim.** The harness does not ship a
per-module test framework to link against (that premise was tried and rejected —
it couples every consumer to the harness's build) — it ships the *discovery +
plan contract* above, and each module writes plain C TAP against it. `t/` shows
the one shim that does exist: `ngx_test_probe_arm.c` compiles a `src/` unit
against a tiny stand-in for nginx, because the renderer beside it reads
`ngx_cycle`, the slab pool and `/proc/self/fd` and shimming *that* would mean
reimplementing the server. Shim only the leaf you can isolate; leave the rest to
the compile-against-real-nginx/angie jobs and the live prober run.

## Gotchas worth knowing before you hit them

- **An "unavailable" sentinel cancels under a delta.** `fds`, every
  `fds_by_kind.*` bucket, both `smaps.*` figures and `timers` are `-1` when
  `/proc` is unreadable (or, for `timers`, the timer tree is uninitialised).
  Direct assertions on it fail loudly; `delta fds == 0` would subtract `-1`
  from `-1` and pass. The prober rejects it explicitly — the rejection list
  is `path_is_proc_sentinel_field()` in `ci/prober/assert.c`, kept in step with
  the emitter's own sentinel-documented functions by
  `ci/prober/sentinel_fields_test.sh`.
- **A delta rule fails loudly when the probe lacks the field** — running new
  rules against an older server gives "delta path not present", not a silent
  pass.
- **Field drift a rule does *not* name is guarded by `probe-schema.json`.** The
  loud failure above only fires for a field some rule references. One that is
  renamed, retyped or dropped while nothing references it stays invisible until
  someone writes a rule against it and reads the failure as a bug in their rule.
  `schema_test.c` checks all three document variants (zone present, zone
  absent, zone present but shm not yet mapped) against that file, and
  `schema_emitter_test.sh` checks the file against the format strings in
  `ngx_test_probe.c` — including the reverse direction, so a field the emitter
  gains without being declared is also red. Adding a member to the probe means
  adding it to the schema.
- **Measure the cycle pool, not the request pool.** See above.
- **ASan needs `detect_leaks=0`.** nginx never frees its configuration pool, so
  LeakSanitizer reports the whole config parse as leaked and turns `nginx -t`
  into a bail-out. Everything else ASan catches stays on.

## Never ship it

The whole feature compiles out unless `NGX_TEST_HARNESS` is defined, and it
must stay that way in packaged builds: the probe walks queues under the slab
mutex, scans `/proc`, and exposes internal state unauthenticated. Before a
release, `strings` your production `.so` for `ngx_test_probe` — it must not
be there.

## Who maintains this, and how modules consume it

Built and maintained by **[MyGuard Labs](https://github.com/myguard-labs)**,
which works on security-oriented nginx modules and hardening plugins. This
repo is the CI-focused testing tool of that set: it validates nginx and Angie
module behaviour by introspecting worker internals — open file descriptors,
cycle-pool statistics, slab-page accounting, and shared-zone presence — rather
than by guessing from the outside.

**Consumed as a git submodule.** A module vendors this repo (conventionally at
`t/harness/`) and compiles the probe **conditionally**, so it never reaches a
production build. `nginx-http-shield-module` is the worked example: its
`.gitmodules` points `t/harness` here, and its `config` compiles the probe
sources only when `TEST_HARNESS=1` is exported at configure time, which also
sets `-DNGX_TEST_HARNESS`. A packaged build sets neither, so the probe is not
merely inert — it is not compiled at all.

**Zero-hook mode.** A consumer does not have to implement anything. With no
`ngx_test_probe_hooks_t` registered, the probe still reports the generic
per-worker fields (pid, fds, cycle-pool, slab), which is enough to catch a
per-request fd or memory leak. Hooks are what you add when you want the
module's *own* state rendered into the JSON — inside `zone` via `zone_render`,
or in a top-level `module` object via `module_render` if you have no zone — or
fault injection armed against it. See **Consumer contract** above. Every
`ci/prober/scenarios/consumer-*` scenario in this repo starts zero-hook for
exactly that reason.

**Probe endpoint.** The consumer names a directive and puts it in one throwaway
location; the harness then drives that endpoint and gets JSON back, which it
asserts against a rule set. `shield_probe` is the directive
`nginx-http-shield-module` registers; the reference module in `t/module/` uses
`test_ref_probe`. The name is the consumer's choice — `PROBER_DIRECTIVE` tells
the prober what it is.

**Multi-environment.** The suite runs across nginx and Angie, and across plain
and sanitizer (ASan/UBSan) builds — see the `scenarios` matrix in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). A module path that
behaves differently on Angie, or only faults under a sanitizer, is caught by a
leg rather than by a user.

**Where it is used.** `nginx-http-shield-module` and
`nginx-cache-turbo-module` consume it for automated CI verification.
`ci/prober/scenarios/consumer-*/` here additionally exercises a wider set of
MyGuard Labs modules — api-abuse, coraza-nginx, error-abuse, skeleton,
strip-filter — as a local instrument; those scenarios SKIP in CI, because the
sources they need are gitignored. `nginx-skeleton-module` is the template for
new modules in the organization; it ships its own CI rather than vendoring this
harness, so a new module opts in explicitly.

## See also

- [docs/](docs/README.md) — the long-form documentation: one document per attack
  surface, plus the coverage policy and procedure.
- [nginx-http-shield-module](https://github.com/myguard-labs/nginx-http-shield-module)
  — first consumer; its `t/prober/` rules and probe-hooks file are a worked
  example.
- [nginx-cache-turbo-module](https://github.com/myguard-labs/nginx-cache-turbo-module)
  — second consumer; `ci/prober/scenarios/consumer-cache-turbo/` here is the
  hand-written reference the generated consumer scenarios are modelled on.
- [Introduction article on deb.myguard.nl](https://deb.myguard.nl/articles/nginx-test-harness/)
  — the tour: what it catches, why sanitizers miss it, and the traps.
- [Where to find us](https://deb.myguard.nl/where-to-find-us/) — all our repos,
  packages and Docker images in one place.
