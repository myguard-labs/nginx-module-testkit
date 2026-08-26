# How to take a module's coverage up

*The policy this implements is [COVERAGE.md](COVERAGE.md). Read it first — the
rules about vacuous tests are not optional and this procedure assumes them.*

The loop, once:

1. [Find the drivable core](#1-find-the-drivable-core)
2. [Get a baseline](#2-get-a-baseline)
3. [Turn the uncovered lines into a classified work list](#3-classify-the-uncovered-lines)
4. [Write the case, then break the code to prove it](#4-write-the-case-then-prove-it)
5. [Re-measure, annotate what stays uncovered](#5-re-measure-and-annotate)
6. [Ship it into the module's own repo](#6-ship-it)

Repeat 3–5 until the uncovered list is only classified lines.

---

## 0. Prerequisites

```sh
gcc --version && gcovr --version     # gcov-compatible compiler + gcovr
```

`clang --coverage` needs `llvm-cov`/`llvm-profdata`, a different toolchain that
is often absent. Use `gcc` for coverage runs even when the project's normal
`CC` is clang.

## 1. Find the drivable core

Coverage is measured on a unit build, so you need code you can call without
booting a server. Look for a translation unit that includes no nginx headers:

```sh
cd <module-checkout>
for f in $(git ls-files '*.c'); do
    grep -qE '#include *[<"]ngx_' "$f" || echo "DRIVABLE  $f"
done
```

A module with a clean split (`strip_core.c`, `*_core.c`, anything the `fuzz/`
harness already links) gives you the whole algorithm behind one entry point.
A module with no such file has its logic welded to `ngx_http_request_t`, and the
honest first move is to extract the pure part — that refactor is the coverage
work, and it pays off in the fuzz harness too.

If the module has a `fuzz/` directory, its entry point already **is** a driver.
Read `fuzz/fuzz_*.c` before writing your own.

## 2. Get a baseline

Write the smallest driver that feeds real inputs through the entry point. If the
module ships a fuzz corpus, replay it — that is free coverage you already own,
and it tells you how much of the gap the existing tests were never going to
close anyway.

```sh
MOD=/path/to/module
WORK=$(mktemp -d)

cat > "$WORK/drv.c" <<'EOF'
#include "strip_core.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    static unsigned char buf[1 << 20], out[1 << 20];
    strip_kind_t k = STRIP_HTML;
    FILE *f;
    size_t n;

    /* Longest-match first: "_json" contains "_js". */
    if      (strstr(argv[1], "_json")) k = STRIP_JSON;
    else if (strstr(argv[1], "_css"))  k = STRIP_CSS;
    else if (strstr(argv[1], "_js"))   k = STRIP_JS;
    else if (strstr(argv[1], "_svg"))  k = STRIP_SVG;
    else if (strstr(argv[1], "_xml"))  k = STRIP_XML;

    f = fopen(argv[1], "rb");
    if (f == NULL) return 1;
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);

    (void) strip_minify(k, buf, n, out);
    return 0;
}
EOF

cd "$MOD"
gcc -O0 -g --coverage -I. -o "$WORK/drv" "$WORK/drv.c" strip_core.c
for c in fuzz/corpus_*/*; do "$WORK/drv" "$c"; done
gcov -o "$WORK" "$WORK"/drv-strip_core.gcda
```

```
Lines executed:73.51% of 487
```

> **The `.gcda` path trap.** gcc writes `.gcno`/`.gcda` next to the **object**
> path, which with `-o "$WORK/drv"` means they land in `$WORK`, not beside the
> source. `gcovr --filter` then matches nothing and reports a cheerful
> `TOTAL 0 0 --%` — which reads exactly like "no coverage data" and sends you
> debugging the wrong thing. Point the tool at the object directory
> (`gcov -o "$WORK"`, or `gcovr --gcov-object-directory`), and treat a `0 of 0`
> total as a plumbing bug, never as a result.

> **Check your driver's dispatch before trusting the baseline.** The substring
> chain above is written longest-match-first for a reason: `strstr("_js")`
> matches `corpus_json/` too, so the naive ordering silently routes every JSON
> input through the JS state machine and reports the JSON minifier as 100%
> uncovered. A baseline that says a whole subsystem is dark is more often a
> broken driver than a real hole. Confirm the classification before you believe
> the number.

## 3. Classify the uncovered lines

`gcov` marks unexecuted lines with `#####`:

```sh
grep -n '#####' strip_core.c.gcov | sed 's/ *#####: *//'
```

Do not start writing tests down this list top to bottom. Sort it into the four
[reachability classes](COVERAGE.md#reachability-classes) first — grouping by
*function* rather than by line number usually collapses 129 scattered lines into
six or seven coherent features nobody tested:

```
CSS   url(...) literal passthrough        ~40 lines   reachable, untested
CSS   #aabbcc -> #abc hex shortening      ~18 lines   reachable, untested
JS    regex-literal vs division           ~30 lines   reachable, untested
HTML  boolean-attr / quote removal        ~25 lines   reachable, untested
JSON  string-literal escape handling      ~20 lines   reachable, untested (driver bug, see above)
core  strip_minify default:                 1 line    defensive
```

Now each row is one test file section and one control mutation, which is a work
plan a person can finish.

## 4. Write the case, then prove it

Derive the expected output from the **specification**, not from a run. For a
minifier that means the CSS/JS/HTML grammar and what is semantically preservable
— not `./drv input.css > expected`, which asserts the code equals itself.

Portable TAP, no harness dependency (see
[COVERAGE.md § Contributing coverage work upstream](COVERAGE.md#contributing-coverage-work-upstream)):

```c
/* t/strip_core_test.c — cc -I.. strip_core_test.c ../strip_core.c -o t */
static int plan_n, plan_ok;

static void
is_minify(strip_kind_t kind, const char *in, const char *want, const char *name)
{
    unsigned char out[4096];
    size_t n = strip_minify(kind, (const unsigned char *) in, strlen(in), out);

    plan_n++;
    if (n == strlen(want) && memcmp(out, want, n) == 0) {
        plan_ok++;
        printf("ok %d - %s\n", plan_n, name);
    } else {
        printf("not ok %d - %s\n", plan_n, name);
        printf("#   want: %s\n#    got: %.*s\n", want, (int) n, out);
    }
}
```

Then the control, which is the part that makes it a test:

```sh
# Break the line the new case claims to cover.
sed -i 's/if (sc_is_hex(after))/if (0 \&\& sc_is_hex(after))/' strip_core.c
cc -I. t/strip_core_test.c strip_core.c -o /tmp/t && /tmp/t; echo "exit=$?"
git checkout strip_core.c
```

The run must go **red, on your new case, by your new assertion**. If it stays
green the test is coverage theatre — the line executed and nothing checked it.
If it reds on some *other* case, your mutation was too broad to prove anything
about this one; make it narrower.

Record the mutation you used in a comment on the test. The next person to touch
that assertion needs to know how it was proven, and re-deriving a control is
most of the cost.

## 5. Re-measure and annotate

```sh
rm -f "$WORK"/*.gcda
cc -O0 -g --coverage -I. t/strip_core_test.c strip_core.c -o "$WORK/t" && "$WORK/t" >/dev/null
gcov -o "$WORK" "$WORK"/t-strip_core.gcda
```

Whatever is still `#####` and is *not* going to get a test gets a `COVERAGE:`
annotation in the source saying why, so the set stays greppable:

```sh
grep -rn 'COVERAGE:' *.c | wc -l    # the reviewable unreachable-set
```

Stop when the uncovered list contains only annotated lines. That is the real
finish line; the percentage that comes with it is a report, not a target.

## 6. Ship it

Into the **module's own repository**, as its own PR:

- `t/<core>_test.c` — portable, builds with `cc *.c -o t`, no harness include
- a CI step that builds and runs it (TAP; every runner already parses it)
- optionally a `make coverage` target wrapping steps 2–3, so the next
  contributor regenerates the uncovered list instead of re-deriving this file

Do **not** add a coverage-percent threshold to that CI. The gate is the control
mutation, and it already ran — in review, by hand, on the case it proves.
Anything needing a live worker (leak deltas, reload survival, fault injection)
stays a harness scenario and ships separately from the portable suite. That
split is about where the *test* lives, not about whether its lines count: a
scenario run against a `--coverage` build does contribute `.gcda`, and for a
fault site it is the only thing that reaches the error branches at all. The
procedure, and the `.gcda` traps that make a re-measurement lie, are in
[fault-injection-under-tooling.md](fault-injection-under-tooling.md).

## See also

- [COVERAGE.md](COVERAGE.md) — the policy and its rationale
- [fault-injection-under-tooling.md](fault-injection-under-tooling.md) — coverage of a fault path, and the memory tools that watch it
- [../README.md](../README.md) — the harness itself, and what its own CI proves
</content>
