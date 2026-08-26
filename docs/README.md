# docs/ — the long-form documentation

The repository [README](../README.md) is the entry point: what the harness is,
how the probe and the prober fit together, the zero-hook path, the rule and
scenario reference. This directory holds the documents that are too long to live
inside it and that a reader wants open beside a terminal.

Two families.

## Coverage

How much of the code under test this tool is expected to reach, and what
separates a test from coverage theatre.

| Document | What it answers |
|---|---|
| [COVERAGE.md](COVERAGE.md) | The policy: the four reachability classes, the control-mutation rule every new test has to pass, how to annotate a genuinely unreachable line, why there is deliberately no coverage-percent merge gate |
| [COVERAGE-HOWTO.md](COVERAGE-HOWTO.md) | The procedure, with commands: find the drivable core, baseline it, classify the uncovered lines, write the case, break the code to prove the case, ship it |

## Attack surfaces

The README states the mission in one line: **this is an adversarial tool, and its
purpose is to break the module under test by any means available.** These
documents are that mission split by *means* — one per class of attack, each
naming the machinery that already exists for it, the oracle that decides a
verdict, and the ways the class can produce a green run that proves nothing.

Read them when you are looking for a way to break a module and want to know what
the harness can already do to it.

| Document | Attack class | Machinery |
|---|---|---|
| [attack-hostile-input.md](attack-hostile-input.md) | Request shapes the module's author did not think of | `property-fuzz`, `stateful-property-fuzz`, the `block` pipeline DSL, `keepalive-bleed` |
| [attack-fault-injection.md](attack-fault-injection.md) | Allocation, codec and upstream failures that never happen in a healthy CI run | `fault_slab=` / `fault_palloc=` / `fault_tempfile=` / `fault_accept=` / `fault_codec=` / `fault_codec_end=`, `fakesrv`, `fault-matrix` |
| [attack-leak-pressure.md](attack-leak-pressure.md) | Descriptors, cycle-pool bytes and slab pages that grow one unit at a time | `delta`, `probe_baseline`, `rss-slope`, `soak-delta`, `fd-starve` |
| [attack-lifecycle.md](attack-lifecycle.md) | Reload, binary upgrade, worker death, signal storms mid-transfer | `reload-*`, `usr2-*`, `hup-storm-mid-transfer`, `worker-death` |
| [attack-environment.md](attack-environment.md) | A hostile clock, a hostile locale, and what the worker actually syscalls | `clock-jump`, `locale-hostility`, `syscall-allowlist` |
| [attack-concurrency.md](attack-concurrency.md) | N requests in flight at once, and the races that only exist there | `concurrent N`, `concurrent-fan`, `multi-worker`, `backpressure` |

## Running the attacks under other tooling

An attack scenario is a program that drives the module into a state. That state
can be watched by more than the scenario's own oracles.

| Document | What it answers |
|---|---|
| [fault-injection-under-tooling.md](fault-injection-under-tooling.md) | You have a fault site and a scenario that arms it. What does running that scenario under memcheck, a sanitizer, or coverage actually tell you — and which leak classes does each one structurally miss? |

The list of attacks we do **not** yet have — TLS, HTTP/2 and HTTP/3, `stream{}`,
body-boundary hostility, allocation faults during a lifecycle event, syscall
*budgets* — is [Ideas and opportunities](../README.md#ideas-and-opportunities--ways-to-break-a-module-we-do-not-yet-try)
in the README. A row there graduates by becoming a scenario with a
mutation-proven oracle, at which point it moves into one of the documents above.

## The rule that governs all of them

Every document here restates the same constraint in its own terms, because it is
the one this repository exists to enforce:

> A gate that cannot fail is worse than no gate, because it reports a pass.

Concretely, for anything you add: the test does not count until its **control**
fails — until you have broken the code the test claims to guard and watched that
specific assertion go red. `ci/prober/mutate.sh` automates that for the prober's own
code; for scenario oracles that mutate nginx's own machinery, the sanctioned
fallback is a documented by-hand control recorded in the driver's header comment.
[COVERAGE.md](COVERAGE.md) states the rule; each attack document names the
control that proves its own class.

## See also

- [../README.md](../README.md) — the tool itself, and the rule/scenario reference
- [../AGENTS.md](../AGENTS.md) — repository conventions for agents
- <https://deb.myguard.nl/articles/nginx-test-harness/> — the long-form article
