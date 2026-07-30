# Coverage — the policy

*Companion how-to: [COVERAGE-HOWTO.md](COVERAGE-HOWTO.md). This file is the
*why*; that one is the keystrokes.*

## The goal

**100% coverage of the code under test.** We will very likely never get there,
and that is fine — the number is a direction of travel, not a promise. What
matters is that every uncovered line is *known* and has one of exactly two
dispositions:

1. a real adversarial test that executes it **and would fail if it broke**, or
2. an honest, written note saying why it is unreachable.

An uncovered line with neither disposition is the actual defect this policy
exists to find. It is not "missing coverage"; it is a branch nobody has ever
reasoned about.

## What we do not do

**There is no coverage-percent merge gate, and adding one would be a mistake.**

The fastest way to move a coverage number is a test that executes lines without
asserting anything. That is the vacuous gate this repo has shipped by accident
several times and now hunts on purpose. A mutation-proven test that covers one
line beats a suite that touches every line and cannot fail.

Concretely, all of these move the number and prove nothing:

- calling a function and discarding its return value
- asserting the output equals whatever the code currently produces, captured by
  running the code (a golden file minted from the implementation asserts that
  the code equals itself)
- asserting a *safety* property — one a healthy program satisfies whether or not
  the feature under test exists at all
- asserting a bound so loose the bug still fits inside it

**Chase the coverage, never the percentage.** The percentage is a report. The
work is the uncovered-line list.

## The rule every new test must pass

> **A new test guards nothing until its control fails by that assertion.**

Before a test counts as covering a line, break the line — invert the condition,
delete the branch, return the wrong constant — rebuild, and confirm the test
goes red **and names the thing you broke**. If the suite stays green, the test
covers the line and asserts nothing about it; it is coverage theatre and must
not be committed as coverage.

Two failure modes that pass a careless control:

- **The test encodes the same misunderstanding as the code.** If you derived the
  expected output by reading the implementation, a control cannot catch you: you
  will faithfully assert the bug. Derive expectations from the *specification* —
  the RFC, the upstream reference implementation, the documented directive
  behaviour — not from a run.
- **The control failed for the wrong reason.** A mutation that makes the program
  crash reds everything. The control must fail *by the assertion you added*, on
  the case you added, not by a segfault three tests over.

## Reachability classes

When you work the uncovered-line list, every line sorts into one of four:

| Class | What it is | What to do |
| --- | --- | --- |
| **Reachable, untested** | Real input drives it; nobody wrote the case | Write the case. This is the work. |
| **Reachable only under fault injection** | `malloc` failure, slab full, short write, EINTR | Use the harness fault injectors (`fault_slab=`, `fault_palloc=`, `fault_tempfile=`, `fault_accept=`), or a seam in the unit build |
| **Defensively unreachable** | `default:` on an exhaustive switch, a re-check of an invariant already held | Annotate. Do **not** contort the code to reach it, and do **not** delete the guard — see below |
| **Dead** | No caller, no input, no path | Delete it. Dead code is the one case where the fix is removal |

Getting a line into the right class is most of the value. "73% covered" tells
you nothing; "129 uncovered lines, of which 94 reachable-untested, 21
fault-only, 12 defensive, 2 dead" is a work plan.

### On defensive lines

A guard that fires but whose removal breaks no test is untestable dead weight —
but the fix is usually *not* to remove the guard. It is to decide, in writing,
whether the invariant it re-checks is actually held everywhere, and record that.
Annotate it in place so the next reader does not re-derive the analysis:

```c
/* COVERAGE: unreachable — callers validate kind against strip_kind_t before
 * dispatch (see ngx_http_strip_filter_module.c:412). Kept as a fail-closed
 * guard against a future caller. */
default:
    return 0;
```

The literal string `COVERAGE:` makes the set greppable, which is what turns
"unreachable" from a claim into a reviewable list.

## Where coverage is measured, and where it is not

Coverage is a **unit-build** measurement. It is instrumented `gcc --coverage`
over the module's own translation units, run under a driver that calls the code
directly.

It is **not** measured through a booted nginx. Instrumenting a running worker
gives numbers that mix module lines with nginx core lines, attributes work to
whichever request happened to land, and costs multi-minute wall clock for a
signal a unit driver produces in under a second. The scenario suite proves
different things — leak neutrality, lifecycle survival, fault-path behaviour —
and those are not coverage claims.

This is why the modules worth taking to high coverage first are the ones with a
**core split out from the nginx glue**: a pure-C file with no nginx headers that
the fuzz harness and the runtime module both call. That file is directly
drivable. The glue around it is thin, and its coverage story is the scenario
suite's, not gcov's.

## The relationship to mutation testing

Coverage answers "was this line executed". Mutation answers "does anything
notice when it changes". Only the second is a proof, so:

- Coverage is the **generator of work** — it produces the uncovered-line list.
- Mutation is the **gate** — it decides whether a test that closed a gap is real.

`prober/mutate.sh` is this repo's mutation runner and `prober/coverage-director.sh`
its per-test reachability map. Neither one gates on a number. The director exists
to answer "what is *not* reached", which is the only question a coverage tool is
good at.

## Contributing coverage work upstream

Tests written under this policy are meant to land in the module's **own**
repository, not to accumulate here. That constrains their shape:

- The core unit tests must depend on **nothing but the module's own sources** —
  no harness submodule, no `prober/`, no shared header from this repo. A plain
  `cc core.c tests.c -o t && ./t` has to work in a clean checkout.
- TAP output, because every consuming repo's CI already understands it.
- One test file per core source file, named after it, so the mapping from a
  failing test to the code it guards needs no explanation in a PR body.
- Anything genuinely requiring the probe — leak deltas, reload survival, fault
  injection into a live worker — stays a harness scenario and ships separately.
  Do not smuggle a harness dependency into the portable suite to reuse a helper.

The split is not bureaucratic. A module's unit suite has to keep working when
this harness is not checked out, or the module's own CI acquires a dependency on
a second repository for the sake of convenience.

## See also

- [COVERAGE-HOWTO.md](COVERAGE-HOWTO.md) — the procedure, with commands
- [../README.md](../README.md) — what the harness is and what its own CI proves
</content>
