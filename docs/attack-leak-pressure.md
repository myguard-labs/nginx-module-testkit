# Attack surface: resource exhaustion and leak pressure

**What it attacks:** growth. A file descriptor, a cycle-pool block, a slab page
or a resident page that the module acquires per request and never returns.

**Why sanitizers do not see it.** ASan and valgrind watch *memory*. A leaked file
descriptor is not a memory error, so they say nothing while the worker crawls
toward `worker_rlimit_nofile`. The same is true of a slab page lost in a shared
zone. And nginx's own pool design hides a third kind: every request gets its own
pool, freed wholesale when the request ends, so a per-request leak *inside* it
looks like a flat line from outside.

That last point decides the whole design: **the probe measures the cycle pool**,
the one that lives as long as the worker and where normal request handling should
never allocate. Any nonzero cycle-pool delta across a request is unbounded growth,
full stop.

## What the probe exposes

A module registering no hooks at all still gets the full generic document:

- `pid`, `flavor`, connection counts
- `fds` (total) and `fds_by_kind` (socket / file / anon / other)
- `smaps` — `pss` and `private_dirty`, in kB, from `/proc/self/smaps_rollup`
- cycle-pool accounting — `cycle_used`, `cycle_blocks`, `cycle_large`,
  `cycle_cleanup`
- the zone's name, size and slab page accounting

Slab occupancy works for any zone with no module C, because every nginx shm zone
begins with an `ngx_slab_pool_t`, so `zone->shm.addr` *is* the slab pool.

### The `-1` sentinel

Every `/proc`-derived field — `fds`, every `fds_by_kind` bucket, both `smaps`
figures — renders **-1** where `/proc` cannot be read. That is a fail-loud
sentinel, deliberately, not a fabricated zero.

It is also the sharpest trap in this whole surface, and every oracle must reject
it explicitly: `-1 − -1 == 0`, which reads as a clean result. The `delta`,
`probe_baseline` and slope oracles all reject the sentinel rather than subtracting
it. Any consumer writing its own oracle over these fields has to do the same.

## Three oracles, because one is not enough

### `delta` — per-case

```text
delta   fds == 0
delta   pool.cycle_used == 0
```

Reads a before-snapshot and an after-snapshot around one case and asserts the
difference. This is the workhorse, and it has one blind spot — which is
unfortunately the shape most real leaks take.

**`delta` cannot see a steady drip.** It reads its before-snapshot *per case*, so
a resource that grows by one unit on every case is already present in both of
that case's reads. The subtraction cancels, every `delta fds == 0` in the file
passes, and the count climbs from 0 to 200 across a 200-case run without a single
red line.

### `probe_baseline` — from a fixed origin

```text
probe_baseline  fds <= 2
```

Subtracts from one snapshot taken before the *first* case of the run and held for
the whole run. The same leak that is invisible per case fails on whichever case
crosses the bound. Write the `delta` on every case and the `probe_baseline` on
the last one; with two cases the difference is cosmetic, and the point is what
happens when the file has two hundred.

### The post-warmup slope — over many operations

A single `delta` can read zero by luck — an allocation the next request frees, a
page the kernel reclaims — and a `probe_baseline` bound has to be set generously
enough to clear the boot one-off. A slope divides the *total* growth over N
identical operations by N, so a per-op leak of even a few bytes is a nonzero
slope while a healthy server sits flat, and the warmup prefix (discarded, not
averaged in) absorbs the startup allocations that would otherwise read as a leak.

It is driven from a scenario `driver.sh`, because it needs a sequence of
snapshots around repeated operations that no single rule case straddles:

```sh
# field  stimulus  warmup  ops  max-growth-per-op
prober_slope_check "$HOST" "$PORT" cycle_used     / 10 60 0   # flat: 0/op
prober_slope_check "$HOST" "$PORT" private_dirty  / 10 60 4   # bounded: <= 4 kB/op
```

`cycle_used` is asserted **flat** — nothing may allocate on the cycle pool per
request. `private_dirty` (RSS) is **bounded** rather than zero, because the kernel
and glibc settle a healthy worker by a page here and there. `scenarios/rss-slope`
is the reference; like the other soaks its cadence is weekly, not the PR path.

## Applying pressure

The oracles above measure. These scenarios create the conditions worth measuring
under:

| Scenario | Pressure |
|---|---|
| `conn-delta` | The base case: one request, zero deltas. Everything else is this plus a stressor |
| `soak-delta` | Many repetitions of the same request, so a drip crosses a `probe_baseline` bound |
| `rss-slope` | The post-warmup slope, on `cycle_used` and `private_dirty` |
| `fd-starve` | `worker_connections 10` — requests served while descriptors are scarce, asserting the constrained path is still allocation-neutral |
| `open-conns` | Bare parked connections that never send anything, against the connection accounting |
| `backpressure` | A reader that will not drain, against the write path |
| `alloc-per-request` | The direct claim: an ordinary request allocates nothing on the cycle pool |

## What the zero-hook oracles do and do not say

These are counters and totals, so they catch **growth**, not every conceivable
leak. An allocation freed by something else in the same window, or a leak offset
by a legitimate release, nets to zero and passes. It is still the assertion most
consumers actually want, and it is the one the Perl suite cannot make at all.

For the class below counters, there is valgrind: a leaked `malloc` the probe never
had a counter for, a one-time startup leak no delta catches, a read of freed
memory that happens not to corrupt anything the assertions look at.
`prober/valgrind-scenarios.sh` runs the tree under memcheck at 20–50× slowdown —
too slow for the PR gate, cheap enough weekly, with `prober/pr-memcheck` as the
PR-lane counterpart.

## How this class produces a green run that proves nothing

- **The `-1` sentinel subtracted into a zero.** Stated above; it is the one to
  check first when a leak oracle looks suspiciously clean on a container.
- **`delta` alone on a long rule file.** The drip cancels. Carry a
  `probe_baseline` or a slope.
- **Measuring the request pool instead of the cycle pool.** Freed wholesale at
  request end, so it reads flat with a per-request leak sitting inside it.
- **Measuring in the reload handover window.** `prober_signal_wait` returns when a
  *new* worker answers, at which point the old one is still alive and both it and
  the master hold handover descriptors belonging to no cycle. The same healthy
  series measured 10, 11 or 12 fds on the same box. Wait for
  `prober_drain_wait` — see [attack-lifecycle.md](attack-lifecycle.md).
- **A band where an exact comparison holds.** `reload-cycle` asserts exact
  equality because every cycle is built by parsing the same config with the same
  binary; a band there would be the weaker claim for no gain. The inverse mistake
  is equally real — an exact `fds` assertion where a keepalive pool parks a
  connection flakes and then gets widened until it cannot fail.
- **An RSS bound widened to fit a sanitizer build.** ASan's quarantine and shadow
  state dominate the measurement: one series grew the master 21 pages unsanitized
  and 402 under ASan. The RSS oracles skip visibly on `PROBER_SANITIZED` rather
  than widening to a bound that no longer fails.

## See also

- [attack-lifecycle.md](attack-lifecycle.md) — reloads, where module leaks surface, and how to measure across one
- [attack-fault-injection.md](attack-fault-injection.md) — the error branches whose cleanup these oracles judge
- [COVERAGE.md](COVERAGE.md) — the control-mutation rule for new oracles
