# Running fault injection under memcheck, a sanitizer, and coverage

**What this answers:** you have a consumer module with a real fault site and a
scenario that arms it. The scenario passes. What else can that same scenario be
run under, and what does each of those tools actually tell you afterwards?

**Why it is worth doing at all:** fault injection exists to reach error paths,
and error paths are where cleanup bugs live. A module's success path is walked
by every test in the suite; its `NGX_ERROR` branch is walked by nothing. Running
the fault scenario under a memory tool is the only way the branch gets both
*executed* and *watched* in the same run. Running it under coverage is the only
way it stops being reported as dead code.

This document is written from a real integration — `nginx-zstd-module` wiring its
`CODEC` / `CODEC_END` sites into memcheck and gcov — and states the traps in the
order they were actually hit, with the measurements that settled each one.

## First, the honest summary

| Tool | Sees a leak on an error path? | Why |
|---|---|---|
| LSan at process exit | **No** | Nginx frees the request pool on teardown, so anything leaked into `r->pool` is reclaimed before LSan reports. A chain link leaked per request is invisible. |
| ASan under this harness | **No** | `prober_heap_env` exports `detect_leaks=0` unconditionally (`lib.sh`), because nginx never frees its configuration pool. LSan is off; ASan's *memory-error* detection still works. |
| valgrind memcheck | **Yes** | Reports at exit against real allocations, independent of pool semantics. This is the oracle for the class. |
| A `delta` / cycle-pool oracle | **Yes, for the pool classes** | Compares counters across two quiescent snapshots. Catches a leak into a pool nginx never frees, which memcheck also catches, and catches per-request pool growth that memcheck would call "still reachable". |

The two right-hand columns are the point: **ASan and memcheck are not
interchangeable here**, and a consumer that runs the fault scenario under ASan
and calls the leak class covered has covered nothing. Use ASan for memory
*errors* on the error path (a use-after-free in cleanup, an overflow in a
partially-initialised struct), and memcheck or a delta oracle for leaks.

## Trap 1 — `--track-fds=all` makes the gate unsatisfiable on nginx

`ci/prober/valgrind-scenarios.sh` ships `--track-fds=all`, and
`prober_scrape_valgrind` gates on `ERROR SUMMARY: [1-9]`. On valgrind 3.24 those
two combine into a gate no module can pass.

A healthy nginx worker always exits holding descriptors open: `error.log`,
`access.log`, the stderr dup, the listening socket, the AF_UNIX master/worker
channel. `--track-fds=all` reports each one, and on 3.24 each counts toward
`ERROR SUMMARY`.

Measured against a real consumer, scenario with **zero faults armed**, all seven
oracles green:

```text
==1929101==    definitely lost: 0 bytes in 0 blocks
==1929101== ERROR SUMMARY: 9 errors from 9 contexts (suppressed: 2 from 2)
```

All nine contexts were `Open file descriptor N:` / `Open AF_INET socket` /
`Open AF_UNIX socket` headings. No module frames. The identical command without
`--track-fds=all` exits 0.

`valgrind-scenarios.sh`'s own comment anticipates the version split — *"some
fleet valgrinds report it purely informationally and exit 0"* — and names the
log line, not the exit code, as the portable guarantee. So the fix keeps the
flag and discounts the open-fd contexts from the count:
`prober_scrape_valgrind` subtracts `Open (file descriptor|AF_* socket)` headings
from `ERROR SUMMARY`'s figure and gates on the remainder. A genuine fd leak is
still named in the log under its `open()` site, which is what a weekly triage
reads. `definitely lost: [1-9]` is untouched and still trips the gate on its own.

`valgrind_scrape_test.sh` cases 11 and 12 pin both directions: the discount
happens, and a real error sharing a log with open descriptors is still caught —
so the fix is not "ignore the count".

**If you are wiring your own job rather than using `valgrind-scenarios.sh`,**
the fd-leak class is the one to be explicit about. Either take the discounting
scrape, or drop `--track-fds=all` and say in the job that the class is not
covered there. Do not widen the gate until it fits and leave it looking like a
gate.

## Trap 2 — `PROBER_TIMEOUT_SCALE` is not optional

Memcheck runs the worker 20-50x slower. Without `PROBER_TIMEOUT_SCALE`, the
prober's read timeout, its boot readiness loop and `prober.c`'s
`DELTA_SETTLE_TRIES` budget all expire for reasons that have nothing to do with
the module, and the run reads as a hang or a false leak.
`valgrind-scenarios.sh` sets `40`; a hand-rolled job must set it too.

## Trap 3 — arming a fault needs its log line exempted, and only that one

A fault site that logs at `[alert]` or `[crit]` on the failure it was asked to
inject will red the run through `prober_scrape_log`, for the fault the test
requested. `PROBER_ALLOW_LOG` takes an ERE exempting exactly that message:

```yaml
PROBER_ALLOW_LOG: 'zstd: ZSTD_compressStream2\(\) failed'
```

Scope it to the one message. It cannot exempt a sanitizer or valgrind
diagnostic — `PROBER_SANITIZER_RE` is never exemptable — so it does not weaken
the memory oracles, but a loose pattern will hide the next real `[alert]`.

A scenario that arms **no** faults should carry no exemption at all: there, an
`[alert]` is a real defect.

## Coverage: the harness and `--coverage` do coexist

There is no conflict between `TEST_HARNESS` and a `--coverage` build. Measured
on a consumer: the coverage tree builds clean with the probe compiled in, emits
`.gcno` for every unit including `ngx_test_probe.c` and `ngx_test_probe_arm.c`,
and the worker flushes `.gcda` on shutdown like any other process.

What that buys, on the same consumer, running two scenarios against the
coverage build:

```text
src/<module>_filter_module.c        38.98% of 1162 lines
src/<module>_probe_hooks.c          87.23% of 94
ci/t/harness/src/ngx_test_probe.c   76.09% of 138
ci/t/harness/src/ngx_test_probe_arm.c 39.32% of 117
```

Those filter-module lines are the fault branches. No `Test::Nginx` case can
reach them: libzstd cannot be made to fail from outside the process. Before the
scenarios ran, every one of them counted as an uncovered line in the report —
which both understates the number and, worse, points refactoring effort at code
that *is* tested.

Two caveats worth stating plainly:

* **The percentage may barely move.** Compiling the probe in adds the module's
  own `probe_hooks.c` to the denominator. On the consumer above the totals went
  77.6% → 79.5% lines, which looks like nothing; the honest figure is **+82
  covered lines and +10 covered functions**, and the two percentages are not
  like-for-like.
* **Gate on nothing here.** `COVERAGE.md`'s no-percent-gate rule applies with
  extra force: a fault scenario is very good at executing lines. Let the
  scenario suite gate on its own oracles and let the coverage number stay a
  report.

## Trap 4 — `gcov` and `gcovr` rewrite `.gcda` as they read it

This one cost real time. Re-reading the same `.gcda` after a `gcovr` pass
produced, in order: `"not a gcov data file"`, then a bogus `0.00%`, then a bogus
`4.7%` where one translation unit's covered lines were attributed to another
unit's total. None of the three were real.

**Measure once, from a freshly generated `.gcda` set.** Delete `*.gcda` and
re-run the scenarios before any re-measurement. A second reading of the same
files is not evidence.

`gcovr`'s answer also depends on the working directory it is invoked from: from
one directory a translation unit was silently absent from the report, from
another it appeared with wrong numbers. Use the invocation your project already
has (explicit `--root`, `--object-directory`, and an explicit list of the
module's own `.gcda`), and do not hand-roll a different one to check a number.

## What this catches that nothing else does

The integration above found a **vacuous oracle** in the consumer's own,
already-merged, already-green fault scenario.

The oracle armed a zero-output fault on the *second* end-of-frame call. But that
site is called once per response, and arming resets the site's counter, so the
sequence number never reached 2. The fault never fired; the oracle asserted an
ordinary unfaulted request and passed for that reason. `gcov` was unambiguous —
the `CODEC_ZERO` return read `#####`, never executed, while the sibling error
arm read 3 and the site itself 2174.

No existing gate could have seen this. The scenario was green, CI was green, the
assertion was well written, and the mistake was in the *arithmetic of which call
gets faulted*. Coverage of the fault path is what made it visible.

That is the argument for this whole document: running the fault scenario under
coverage is not about the number. It is about being able to answer "did the
fault I armed actually fire?" — and that question has no other oracle.

## See also

- [attack-fault-injection.md](attack-fault-injection.md) — the fault sites, the
  hook boundary, and how a module makes its own faults mean something
- [attack-leak-pressure.md](attack-leak-pressure.md) — the delta oracles, and
  the leak classes a sanitizer structurally cannot see
- [COVERAGE.md](COVERAGE.md) — the reachability classes and the
  control-mutation rule
- [COVERAGE-HOWTO.md](COVERAGE-HOWTO.md) — the procedure for taking a number up
- [../README.md](../README.md#running-scenarios-under-valgrind-optional) — the
  `valgrind-scenarios.sh` entry point and the consumer CI template
