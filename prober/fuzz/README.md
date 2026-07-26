# prober/fuzz — parser fuzz targets

Engine-neutral libFuzzer targets for the prober's byte-consuming parsers, plus a
standalone corpus-replay driver so the same targets run on the PR path under
plain gcc without any fuzzing engine.

## Targets

Each `fuzz_<t>.c` defines only `LLVMFuzzerTestOneInput` and nothing else, so it
links equally under `-fsanitize=fuzzer` (clang) and under the standalone driver
(gcc). Chosen because each consumes untrusted, attacker-shaped bytes whose
interesting inputs a live socket will not produce on demand:

| target      | function                    | interesting inputs |
|-------------|-----------------------------|--------------------|
| `json`      | `json_parse_n`              | embedded NUL, deep nesting, double-overflow number, truncated escape |
| `http`      | `http_parse_response`       | no header terminator, body containing CRLFCRLF, embedded NUL, truncated status line |
| `memcached` | `backend_parse_memcached`   | storage command with a lying data-length, too many args, unterminated line |
| `resp`      | `backend_parse_resp`        | lying `$` bulk length, overrunning `*` multibulk count, embedded NUL in a bulk value |
| `rules`     | `load_rules` (via `load_rules_buf`) | malformed directive line, per-directive numeric bounds, bad escape, pipeline sub-block, cross-line budget overflow |
| `backend`   | `backend_load` (via `backend_load_buf`) | unknown proto/directive/action, `fault` with missing/contradictory params, `data=`-carries-spaces line, escape decode, `on=cmd:nth` bounds |

`rules` and `backend` are **file-grammar** parsers: production reads a PATH via
`fopen`/`fgets` and `die()`s (exit(2)) on any syntax error, which would make a
naive fuzz target abort on every malformed input. Two shared pieces make them
work — a `_buf` entry point that `fmemopen`s the fuzzer bytes into the *same*
line-reading parser (`load_rules_fp` / `backend_load_fp`), and the `die()`
recovery hook `prober_die_jmp` (util.h): the target arms an `setjmp` env so a
`die()` `longjmp`s back and a rejected file is a handled non-event, leaving only
a real crash (ASan/UBSan finding) to fail the run. Production `die()` is
unchanged (hook NULL → `exit(2)` byte-identical).

## The two halves

**PR path — deterministic replay, no engine (`fuzz.sh replay`).** Links each
target with `fuzz_standalone.c` (the LLVM StandaloneFuzzTargetMain pattern:
`main` feeds each corpus file once to the target) under gcc + ASan/UBSan, over
the checked-in `corpus/<t>/`. A crash or sanitizer abort exits nonzero and fails
the run. There is no "report and continue" path — only the process living or
dying — which is what makes this gate impossible to render vacuous. Wired into
`ci.yml`'s `fuzz-replay` job.

**Scheduled path — discovery (`fuzz.sh fuzz [seconds]`).** Needs clang
(`-fsanitize=fuzzer,address,undefined`). Mutates unbounded on a time budget,
writing new crashers to `crashes/<t>/`. Off the per-commit path in `fuzz.yml`
(cron + `workflow_dispatch`), staggered against the other scheduled workflows.

## Non-vacuity proof

Plant an out-of-bounds read in `json_parse_n` (e.g. `s.end = text + len + 4;`)
and run `./fuzz.sh replay`: the `bignum`/`obj` seed drives the over-read, ASan
aborts, and the script exits 1. Restore the source and it exits 0. This is the
same mutation ritual every gate in this repo is held to — a fuzzer that reports
but exits 0 is the canonical vacuous fuzz gate, and neither path admits it: the
standalone driver has no reporting path at all (a crash kills the process), and
the scheduled discovery run turns any crasher into a nonzero exit via the
`collect crashers` step in `fuzz.yml` (which greps `crashes/` and `exit 1`s),
since libFuzzer itself already exits nonzero on a crash under ASan.

## Corpus

`corpus/<t>/` holds small valid + edge seeds. Empty files are legitimate seeds
(they exercise the `size == 0` edge) and are carried on purpose. New crashers
found by the scheduled run should be minimized and added here so the PR path
regression-guards them from then on.
