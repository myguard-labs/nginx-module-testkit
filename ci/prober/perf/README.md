<!--
Copyright (C) 2026 Thijs Eilander
SPDX-License-Identifier: BSD-2-Clause
-->
# ci/prober/perf — deterministic algorithmic-cost gate

`cachegrind-scale.sh` asserts a **shape**, not a speed: parsing an 8× larger
JSON document must cost about 8× the instructions, never ~64×. A regression that
turns a per-element scan quadratic (a duplicate check, a tail-walking append, a
naive insert) is invisible to a functional test and to a wall-clock timing test
on small inputs, but it changes the cost *curve* — and Cachegrind measures that
curve exactly and reproducibly.

This is the replacement for the rejected `expect time<ms` rule directive:
wall-clock time is host- and load-dependent, an instruction-count ratio is
neither (same binary + same input ⇒ identical `Ir` every run).

## How it works

`cg_scale.c` runs in two modes at a given element count:

- `gen` — build the fixed-shape input string only.
- `parse` — build the same input, then `json_parse_n()` + `json_free()`.

`Ir(parse) − Ir(gen)` at one size is the parser's own instruction count: process
startup, libc init and the O(N) input generation appear in both runs and cancel.
The gate takes that marginal at N and 8N and checks the ratio is in a linear band
`[6, 16]` — far below the ~64 an O(n²) regression produces.

The workload is an array of small objects `{"k":<number>,"s":<string>}`, so the
scaling exercises `parse_array`, `parse_object`, `parse_string` and
`parse_number` together, including both realloc-grown containers at once.

## Run it

```sh
ci/prober/perf/cachegrind-scale.sh        # TAP; exit 0 iff linear
```

Needs `valgrind`. Absent, it emits `1..0 # SKIP`. Runs in the `cachegrind-scale`
CI job (its own job — Cachegrind must launch the process it measures and cannot
attach to a live nginx worker, unlike the strace-based `syscall-allowlist`
scenario).

## Proven non-vacuous

Clean tree: ratio ≈ 9.2 (linear). A planted per-push `O(n)` scan over all prior
items (compute-O(n²)) drives the ratio to ≈ 37 — well past the `16` ceiling —
and reds the gate. See `ci/prober/fuzz/` for the correctness-side (parser crash)
counterpart; this directory is the cost-side.
