# Import prompt — wire nginx-module-testkit into a module's CI

Hand this file to an LLM working inside a consuming nginx/Angie module repo.
It is written to be pasted whole, or referenced by URL. Everything it asks for
is verifiable from inside the target repo plus a checkout of the harness.

---

## Your task

You are working inside a single nginx (or Angie) module repository. Integrate
[nginx-module-testkit](https://github.com/myguard-labs/nginx-module-testkit)
into that repository's CI so that it runs on every pull request and asserts
something the repo's existing tests structurally cannot assert.

The harness compiles a **probe** into a test build of the module and runs a
standalone **prober** binary against it. The prober takes a JSON snapshot of
the worker's internals before and after each request — cycle-pool bytes, file
descriptor counts, slab page accounting, RSS lineage — and asserts the
difference. That catches the leak class ASan and valgrind are blind to: a
leaked descriptor is not a memory error, and nginx's per-request pools hide
per-request leaks from the outside entirely.

Read the harness `README.md` before writing anything. It is long and it is the
authority; this file only tells you what to do with it.

---

## Hard requirements

### 1. Layout — the testkit goes in `ci/`

Unless the repository you are working in explicitly instructs otherwise (a
`CONTRIBUTING.md`, an `AGENTS.md`/`CLAUDE.md`, a maintainer comment, or an
existing convention that plainly contradicts it), put everything you add under
**`ci/`**:

- driver scripts → `ci/tools/testkit-stage.sh`, `ci/tools/testkit-run.sh`
- scenarios owned by this repo → `ci/prober-scenarios/<name>/`
- rule files → alongside the scenario that uses them

If the repo already has a different, established home for CI scripts, follow
the repo. Consistency inside the target repo beats consistency with this
document. Say in your summary which you chose and why.

### 2. How the harness is obtained

Three options; pick deliberately and record the reasoning in a comment:

- **Pinned checkout in the workflow** (`actions/checkout` with
  `repository: myguard-labs/nginx-module-testkit` and an explicit `ref:` SHA).
  Preferred when the repo has no `.gitmodules` today — it keeps the coupling
  local to one job instead of changing clone semantics repo-wide.
- **Submodule** (`git submodule add ... t/harness`) — reasonable when the repo
  already uses submodules.
- **Vendoring — do not.** The harness's `t/module/config` compiles sources by
  relative climb out of its own tree, so a partial copy does not build; and a
  vendored copy drifts while the port-back never happens.

**Pin the ref.** An unpinned harness produces a red leg whose cause is a commit
in another repo that the failing PR never touched. Bump the pin deliberately,
in its own PR, so the bump is what gets blamed.

### 3. Start zero-hook

Most modules need **no module C at all**. Build the module as a dynamic module
alongside the harness's reference probe (`t/module`) and point a scenario at
both — the probe is a separate `.so`, and you still get pid, connection counts,
`fds`/`fds_by_kind`, `smaps`, and full cycle-pool accounting. Eight of ten
modules wired this way produced a working allocation-neutrality scenario with
zero module-specific lines.

Only promote to the hooked path (`zone_render`, `fault_set`, the
`PROBE_HTTP_TEMPLATE.c` boilerplate) when an oracle you actually want is
unexpressible without it. Do not write the hooks speculatively.

### 4. The scenario must not be able to pass vacuously

This is the requirement that fails most integrations, and it fails them green.

- `1..0 # SKIP` is a **passing TAP plan**. A scenario whose `./requires` gate
  never finds a staged `.so` emits it forever, and a permanently-skipping leg
  is indistinguishable from a green one in a job summary. A finished cache-turbo
  scenario stayed disconnected for a month exactly this way.
- Therefore assert **both directions** in CI: a staged tree must produce real
  assertions, *and* an unstaged tree must SKIP cleanly rather than fail. Neither
  half is sufficient alone. See `ci/tools/testkit-run.sh --expect-skip` in
  nginx-cache-turbo-module for the shape.
- Every new oracle must be proven by **breaking the code under test** and
  watching the test go red (the control-mutation rule in `docs/COVERAGE.md`).
  A test you have never seen fail is a test you have not written.
- Anchor the measurement to a real event. The cache-turbo scenario asserts a
  genuine `X-Cache: HIT` occurred *before* the measured pair, so a pass-through
  filter that allocates nothing cannot score "allocation-neutral".

### 5. Do not duplicate the Perl suite

If a proposed scenario could be written as a `Test::Nginx::Socket` `.t` file
with no probe snapshot — status codes, headers, body content, rewrites,
`error_page`, config permutations — write it as a `.t` file instead. This
harness is for the assertions the Perl suite *cannot* make: what the worker
looks like from the inside, before and after. A second suite asserting the same
thing is another place to update and it dilutes the signal.

### 6. Consumer contract

The test `nginx.conf` must set `worker_processes 1;` and `daemon off;` — the
runner checks and bails otherwise. Give the CI job its **own port band** if the
repo allocates them, and never let a stale-listener sweep widen beyond that
band: a wider sweep kills a sibling job's live fixtures on a shared runner.

---

## Strongly encouraged: adapt the harness

Do not treat the testkit as a fixed appliance to bolt on. **You are encouraged
to extend, bend and repurpose it** for whatever gives this module real signal:

- **Coverage** — use `ci/prober/coverage-director.sh` to find what is *not*
  reached, then write adversarial cases for it. Chase the coverage, never the
  percentage; there is deliberately no coverage-percent gate, because the
  fastest way to move that number is a test that executes lines without
  asserting anything.
- **Speed** — the harness is cheap (a staged scenario run is sub-second). Look
  for where the module's existing suite is slow and whether a probe oracle
  replaces a slow indirect check with a fast direct one.
- **Security** — hostile and malformed input via `property-fuzz` /
  `stateful-property-fuzz`; smuggling and partial-header windows via `pause`,
  `send_slow`, `send_slow_chunks`; client-vanishes paths via `abort`,
  `shutdown`, `hold`.
- **Performance** — algorithmic and allocation cost is a class no `delta`
  oracle sees. `ci/prober/perf/cachegrind-scale.sh` asserts a **shape, not a
  speed** (an 8x document must cost about 8x the instructions, never ~64x),
  which is host-independent where a wall-clock bound would be flaky by
  construction. Generalizing that ratio to a consumer module is an open problem
  and a welcome contribution.
- **Memory** — the three resource oracles are complements, not alternatives:
  `delta` localises a jump to the case that caused it, `probe_baseline` bounds
  the total across a run (it catches the one-unit-per-case drip that every
  `delta` reads as zero), and `prober_slope_check` divides growth over N
  operations after a discarded warmup.
- **Sanitizers** — `SAN=1` builds work. Note the harness's own policy: it does
  not instrument nginx core, because that spends budget re-testing upstream's
  code. Instrument *your module*.
- **Fault injection** — `fault_slab=`, `fault_palloc=`, `fault_tempfile=`,
  `fault_accept=` make the allocator fail on the Nth call. Most module bugs
  live on the error path nobody exercises, because in a healthy test the
  allocator never fails. `fakesrv` does the same for upstream faults a real
  daemon cannot be made to produce.
- **Lifecycle** — reload, binary upgrade, worker death, signal storms
  mid-transfer. Reloads are where module leaks surface, because that is when a
  cycle is torn down and every unbalanced allocation becomes visible.
- **Concurrency** — `concurrent N` in flight, `open_conns` parking bare
  connections, `backpressure` against a reader that will not drain.
- **Environment** — hostile locales, `syscall-allowlist` tracing what the worker
  actually does rather than what it claims, `clock-jump` stepping the wall clock
  backwards to prove timers ride `CLOCK_MONOTONIC`.

**If you can think of another way to break this module, it belongs here.**
Anything genuinely new is more valuable than a faithful copy of the reference
scenario.

---

## Required: feed your findings back

Anything you build that the harness itself could use — a new scenario shape, a
new oracle, a directive that was missing, a bug you hit in the prober, a
technique that generalizes past this one module — goes **back to the testkit
repo**, not only into the module you are working in.

Open a **pull request against `myguard-labs/nginx-module-testkit`** adding a
single new directory:

```
feedback/<YYYY-MM-DD>-<short-description>/
```

for example `feedback/2026-08-26-slab-churn-under-reload/`.

Put in it:

- **The code.** Scenario directories, rule files, driver fragments, patches to
  prober sources — whatever form the finding took. Runnable, not described.
- **Extended documentation.** A `README.md` in that directory covering:
  - what module and what version/SHA of the harness this came from;
  - what the finding or technique is, in plain terms;
  - **the oracle** — what exactly decides pass/fail, and what it does *not*
    assert;
  - **how it can produce a green run proving nothing**, and what closes that;
  - how you proved it non-vacuous (which line you broke, what went red);
  - measured cost (wall-clock, and whether it belongs on a PR gate or a soak);
  - what generalizing it to other modules would take.
- **Anything you had to work around.** A workaround is a finding. If a path
  default silently SKIPped a perfectly good tree, or a directive could not
  express what you needed, write it down even without a fix.

Keep the module's own repo the home for module-specific tests; `feedback/` is
where the *transferable* part goes so the maintainers can adapt it back into the
harness proper. One PR per finding, so each can be judged on its own.

---

## Worked reference

`myguard-labs/nginx-cache-turbo-module` is the finished end-to-end integration:

- `.github/workflows/testkit.yml` — the CI leg, including the pinned harness
  checkout, its own port band, the ccache namespace, and **both** the
  asserts-on-staged-tree and SKIPs-cleanly-when-unstaged steps.
- `ci/tools/testkit-stage.sh` — stages the module plus the harness's reference
  probe into **one** nginx tree. They must share an `objs/`: nginx binds its
  dynamic-module list at configure time, so there is no adding a module to an
  already-built tree.
- `ci/tools/testkit-run.sh` — runs the scenarios. Read its header comment; it
  documents the traps that cost real time, notably that `PROBER_BUILD` must be
  **absolute** because two pieces of the harness resolve the build tree with
  different fallbacks and silently disagree otherwise.

Also worth reading before you start: `docs/README.md` (attack surfaces, one
document per class), `docs/COVERAGE.md` (the four reachability classes and the
control-mutation rule), `docs/COVERAGE-HOWTO.md` (the procedure with commands —
worked end to end on nginx-strip-filter-module, 77.21% → 99.79%, with two tests
caught being vacuous by their own controls), and `PROBE_HTTP_TEMPLATE.c` if you
end up on the hooked path.

---

## Deliverables

1. The CI leg, running on PRs, green, with both directions asserted.
2. At least one oracle this repo did not previously have, proven non-vacuous by
   a deliberate break.
3. A short summary: what you wired, what it asserts, what it explicitly does
   **not** assert, measured cost, and where you deviated from this document.
4. A `feedback/<date>-<description>/` PR against the testkit for anything
   transferable — or an explicit statement that nothing was.
