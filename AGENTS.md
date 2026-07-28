# AGENTS.md — nginx-test-harness (Codex / agent instructions)

Resource/fault/lifecycle verifier for nginx and angie modules. NOT a second
request/response suite: ordinary status/header/body behaviour belongs in
`nginx.pm`. What this harness uniquely proves is **pool, FD, slab, worker,
upstream-journal and allocation-failure** evidence across signals, reloads and
faults.

**MISSION — this is an ADVERSARIAL tool. Its purpose is to break the module
under test, by any means available.** Hostile and malformed input, allocation-
failure injection (`fault_slab=`/`fault_palloc=`/`fault_tempfile=`/
`fault_accept=`), resource exhaustion, lifecycle attacks (reload, binary
upgrade, worker death, signal storms), environmental hostility (clock jumps,
locale). If you think of another way to break a module, it belongs here — see
README "Ideas and opportunities" for the ones already identified and not yet
built. **Coverage goal is 100% of the code under test**, understood as a
direction of travel, not a promise: chase the uncovered lines, never the
percentage, and there is deliberately NO coverage-% merge gate (moving that
number with non-asserting tests is the vacuous-gate failure this repo hunts).
`prober/coverage-director.sh` is the reachability generator — use it to find
what is NOT reached.

**SCOPE (a narrower question — what THIS repo's own CI spends budget on).** The
mission above is what the tool does to a consumer's module; the rule below is
what our CI proves about our own code. We develop a probe TOOL for nginx, not an
nginx MODULE. The thing
under test is our own code: the prober binary, its rule parser, the probe's JSON
emitter, the shell plumbing. nginx is the fixture, never the subject. So: no
ASan/UBSan legs in this repo's CI — not on nginx, and not on our own binary
either (decided 2026-07-28; `SAN=1 prober/test.sh` remains available for a
one-off local run when a parser bug is suspected). No valgrind on nginx, no
whole-server fuzzing, no nginx benchmarking. Fuzzing our OWN parser stays in
scope. Do not add a sanitizer job back without the user asking for it. Full
rationale + the known cost → README "What this repo is — and what it is not".

**DO NOT ADD A TEST HERE THAT THE PERL SUITE CAN ALREADY DO.** A consuming
module has `Test::Nginx::Socket` and its own `.t` files, and that is the right
home for ordinary request/response behaviour — status, headers, body, rewrites,
`error_page`, config permutations. This harness is for what the Perl suite
structurally CANNOT assert: the worker's insides before and after, i.e.
cycle-pool bytes, descriptor counts, slab pages, allocation neutrality across a
request or a reload. **Test to apply to any proposed scenario: could it be
written as a `.t` file with no probe snapshot? Then write it as a `.t` file and
reject it here.** Duplicating the Perl suite is not free — a second suite
asserting the same thing is another place to update on every behaviour change,
and it dilutes the signal this one exists to give.

Superrepo root is `/opt/myguard` — see [/opt/myguard/AGENTS.md](../../AGENTS.md).
Working notes for this repo live OUTSIDE it, at
`/opt/myguard/memory/labs/nginx-test-harness/` (read `HANDOFF.md` first, then
`TODO.md`, `issues.md`, `lessons.md`).

## Layout

- `prober/` — the C prober + its shell library. `lib.sh` is the shared harness
  (boot, render, probe, slope, teardown); `rules.c` parses the `.rule` DSL;
  `http.c` owns wire timing and framing. All three are single-writer files —
  never two branches open against one of them.
- `prober/scenarios/<name>/` — one scenario per directory: `nginx.conf` template,
  `*.rule`, optional `env`, `driver.sh`, `requires` (a gate that SKIPs rather
  than fails when a prerequisite is absent), optional `backend` script.
- `src/` — the reference probe module (`ngx_test_probe*.{c,h}`) compiled into a
  `.so` the scenarios load.
- `t/module` — the minimal consumer module. Deliberately tiny.
- `prober/impact.map` — the reverse-impact DB: which targets a changed file must
  run. A changed executable source that maps to NO target fails closed.

## Build and test

```
cd prober && ./build.sh                 # the prober + its unit tests
prober/test.sh                          # full local gate, 25 suites
prober/verify-impact --explain          # what a diff selects (omit --base for the working tree)
prober/pr-impact --budget 90            # actually run the selected fast lane
```

Repo-root shellcheck, exactly as CI runs it — must exit 0:

```
shellcheck -x --source-path=prober prober/*.sh prober/verify-impact \
  prober/pr-impact prober/pr-memcheck prober/scenarios/*/driver.sh
```

A bare `shellcheck` without `-x` cannot follow `. ./lib.sh` and reports spurious
SC2034 on variables the library consumes. Use the form above.

## House rules that bite

- **Every gate must be mutation-proven.** A new test guards nothing until its
  control fails BY THAT ASSERTION. If a defect has no honest failing test, say so
  in the test's own comment rather than shipping a green assertion that proves
  nothing — a vacuous gate is worse than no gate, and this repo has shipped
  several by accident.
- **`set -euo pipefail` everywhere.** An unguarded `$(cmd)` whose non-match is
  legitimate will kill a TAP suite mid-stream, which reads as a pass to anything
  counting `not ok`. Guard with `|| true`.
- **Local runs need a free port:** `PROBER_PORT=<free>`; 18099 is a hardcoded
  default that collides with concurrent CI on this shared box.
- **A stale reference `.so` fakes flavor-specific failures.** Check its mtime
  against `src/ngx_test_probe.c` before believing any local scenario red.
- Own nginx modules are BSD-2-Clause.

## Reviewing a diff here

Read the changed hunks against `lib.sh`'s existing idiom, not in isolation. The
recurring defect classes, in rough order of how often they have actually bitten:
vacuous gates (an assertion that cannot fail), fail-open guards (a check whose
removal breaks no test), arithmetic that truncates or wraps at a boundary, and
oracles that overshoot the boundary they claim to pin by orders of magnitude.

Do not run the deterministic lint pre-pass from this directory: it lives at
`/opt/myguard/.claude/skills/_shared/review-lint.sh` and a relative path fails.
