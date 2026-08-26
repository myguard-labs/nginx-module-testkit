# Attack surface: memory corruption the sanitizers cannot see

**Class:** a linear overflow out of one pool object into the one next to it.

**Machinery:** `ngx_test_probe_palloc()`, `redzone.violations`, `redzone.checked`.

**Oracle:** guard bytes on both sides of a guarded allocation still hold
`0xDB` when the allocation is verified — on demand, and unconditionally at pool
destruction.

---

## Why this exists when ASan exists

The reflex answer to "who catches a heap overflow" is AddressSanitizer, and for
ordinary `malloc` it is the right answer. nginx's pool allocator defeats it, and
the reason is structural rather than a matter of configuration.

`ngx_palloc_small()` is a bump allocator. It does not call `malloc` per object —
it slices objects out of one large block obtained by `ngx_palloc_block()`, by
advancing `p->d.last`:

```c
if ((size_t) (p->d.end - m) >= size) {
    p->d.last = m + size;
    return m;
}
```

So a request pool holding two hundred small objects is, to ASan, **one live
allocation**. ASan's redzones sit at the two ends of that block. Between the
objects there is nothing to poison, because from ASan's point of view there are
no boundaries there — the whole block is addressable and live.

valgrind memcheck is blind for the same structural reason plus one more: it
tracks addressability and definedness of malloc'd blocks, and every byte of that
pool block is both addressable and defined.

### Demonstrated, not assumed

This is the control that justifies the whole file, and it is `test 1` in
[`t/probe_redzone_test.c`](../t/probe_redzone_test.c) rather than a claim in
prose. A 4096-byte block, sliced into two 16-byte objects, the first `memset` to
32 bytes:

```text
ok 1 - the two pool objects really are adjacent
ok 2 - VACUITY PROOF: the overflow corrupted the neighbour and neither ASan nor
       the allocator said a word
```

The test binary is itself built with `-fsanitize=address,undefined`. It exits 0.
ASan prints nothing. The second object's contents are silently replaced.

If ASan ever does learn to catch this, **test 1 fails loudly** and this
document's justification needs revisiting — which is the correct outcome, not a
nuisance to suppress.

## What it does NOT do

Stating this precisely matters, because "we have redzones now" is exactly the
kind of claim that gets over-read into "we no longer need ASan".

| Not covered | Why, and what does cover it |
|---|---|
| Use-after-free | A destroyed pool's blocks go back to libc. ASan's quarantine already applies and reports at the faulting instruction. |
| Overflow of a *large* allocation | `ngx_palloc_large()` calls `ngx_alloc()`, so it is an ordinary malloc block that ASan already guards. |
| An over-*read* that writes nothing | Nothing is disturbed, so no after-the-fact check can notice. |
| The faulting instruction | This reports at **detection** time — the next check, or pool destruction — with the allocation's size and address, not a stack trace of the write. |

**Run both.** They overlap almost nowhere. Where ASan can see a bug at all it
remains the better tool, because it reports the write itself.

## Using it

Route the allocations under test through the guarded allocator:

```c
p = ngx_test_probe_palloc(r->pool, len);   /* instead of ngx_palloc */
if (p == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;  /* an ordinary allocation failure */
}
```

A `NULL` return is an allocation failure, never a violation report. Handle it
exactly as you would handle `ngx_palloc()` returning `NULL`.

Verification is automatic when the pool is destroyed. A module that wants to
localise a corruption to a specific point in its own processing can also ask at
any time:

```c
if (ngx_test_probe_redzone_check(r->pool) > 0) { /* ... */ }
```

Then assert from a rule file:

```text
name   the handler corrupts no guard byte
send   GET /whatever HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect status=200
probe  redzone.checked    > 0
probe  redzone.violations == 0
```

### The opt-in is deliberate

An un-adapted module gets nothing from this, and that is the honest cost of the
approach. Interposing `ngx_palloc()` globally was considered and rejected: it is
a core symbol nginx itself calls thousands of times per request, the overhead
would be charged to code that is not under test, and the registry would grow
without bound on the cycle pool. Opt-in per call site keeps the cost
proportional to what is actually being tested.

### Alignment — the one sharp edge

The returned pointer is **not aligned**. The padded block comes from
`ngx_pnalloc()`, because an aligned allocation lets nginx skip bytes between the
previous object and this one, and an overflow landing entirely in that skipped
padding would go unreported. Immediate adjacency to the neighbour is what makes
the guard meaningful.

That is the `ngx_pnalloc` contract and it is correct for byte buffers. A caller
wanting a guarded struct must round its own size up itself.

## How this class produces a green run proving nothing

Every attack surface document names its own vacuity traps. This one has three.

**1. `redzone.violations == 0` with nothing ever guarded.** Zero violations out
of zero checked allocations is the vacuous pass, and it is exactly what a
consumer gets after wiring in the header but never actually routing an
allocation through `ngx_test_probe_palloc()`. It is indistinguishable from a
clean run on the violations figure alone.

`redzone.checked` exists solely to close this. **An honest oracle asserts both:**

```text
probe  redzone.checked    >  0
probe  redzone.violations == 0
```

**2. A guard that is never verified.** A check that runs only when someone
remembers to call it is a check that silently stops running. The cleanup handler
registered on the pool is what makes the guarantee unconditional — it runs
whether or not the module under test cooperated, and it runs *before*
`ngx_destroy_pool()` frees the blocks, which is load-bearing ordering pinned by
`test 4`.

**3. A detector with its own off-by-one.** A detector that fires on correct code
gets disabled, which is worse than not having one. `test 6` pins both edges:
writing the first and last in-bounds bytes is not a violation; one byte past the
end is.

## Boundaries pinned by tests

| Test | What it pins |
|---|---|
| 1 | ASan is blind to the unguarded case (the vacuity proof) |
| 2 | The same overflow, guarded, is caught and logged with its direction |
| 3 | Underflow is caught too — a single trailing guard would miss it entirely |
| 4 | Pool destruction counts the violation without an explicit check |
| 5 | A clean run is distinguishable from a run that never happened |
| 6 | Exact in-bounds writes are not violations; one byte past is |
| 7 | A size that would wrap when padded is rejected, not wrapped |
| 8 | Allocation failure is reported as failure, not as a violation |

Test 7 is worth its own note: a `size` within `2 * NGX_TEST_PROBE_REDZONE` of
`SIZE_MAX` would wrap when padded, and the guard `memset`s would then scribble
across the heap — making this file the memory-safety bug it exists to find. The
rejection is pinned rather than trusted.

## Guard width

`NGX_TEST_PROBE_REDZONE` is 16 bytes on each side.

16 rather than 8 because the common overflow is a copy whose length was computed
wrong, and byte-count mistakes cluster at small powers of two and at the width
of a pointer or a length prefix. A 16-byte guard catches an 8-byte overshoot
whole.

Not 32 or more because every guarded allocation pays twice this in pool bytes,
and pool growth is itself measured by the `delta` oracles — a fat guard would
move the numbers those assert on.

## See also

- [attack-leak-pressure.md](attack-leak-pressure.md) — the *growth* oracles.
  Complementary: those catch memory that is never released, this catches memory
  that is written past.
- [attack-fault-injection.md](attack-fault-injection.md) — `fault_palloc=`
  makes the allocator fail, which is how the `NULL` return path above gets
  exercised at all.
- [COVERAGE.md](COVERAGE.md) — the control-mutation rule every test here had to
  pass.
