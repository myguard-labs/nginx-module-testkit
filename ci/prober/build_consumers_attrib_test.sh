#!/usr/bin/env bash
#
# TAP self-test for tools/build-consumers.sh's REPORT block: how a .so is
# attributed to a consumer, and how a stale artifact is detected.
#
# WHY THIS EXISTS -- both properties were FALSE GREENS, and both are silent.
#
#   1) ATTRIBUTION was resolved by grepping ngx_module_name= / ngx_addon_name=
#      out of the TOP-LEVEL consumers/<n>/config with no descent. A module whose
#      config sources fragments that declare the real names (http-zstd:
#      filter/config + static/config, with the top level declaring only
#      `ngx_addon_name=ngx_zstd`) was reported NO -- while its two genuinely
#      fresh .so were denounced as belonging to "no module in this run". The
#      advised remediation, delete the stage dir and rebuild, reproduces the
#      same output forever.
#
#   2) The STALENESS SWEEP had no staleness oracle at all. It inspected only
#      .so files it failed to ATTRIBUTE and asserted "these were NOT built now"
#      from a name miss -- the one thing that is not a freshness measurement.
#      A genuinely stale .so whose name DID attribute passed in total silence.
#      That is a false green for every consumer in the run, and it is exactly
#      [[feedback-stale-so-fakes-negative-control]], the bug class the script's
#      own header cites as its reason to exist.
#
# WHY A FAKE SOURCE TREE RATHER THAN A REAL BUILD. The report block is not
# separable from the script, and a real ./configure + make is minutes of CPU per
# assertion. build-consumers.sh runs `./configure` and `make` from $BUILDDIR, so
# a stub tree supplying both drives the REAL script -- every line under test is
# the shipped one -- at zero build cost. The stub writes an objs/Makefile in
# nginx's own shape (a `objs/<name>.so:` target per dynamic module, each .o
# prerequisite carrying a compile rule with the ABSOLUTE source path), because
# that shape is precisely what the fix reads.
#
# Each property below is paired so none is vacuous: an attribution assertion is
# paired with the sweep staying quiet, and the stale assertion is paired with a
# fresh tree producing no stale report.
set -euo pipefail

cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"

PLANNED=9
tests_run=0
failures=0

echo "1..$PLANNED"

ok() {
    tests_run=$((tests_run + 1))
    if [ "$1" -eq 0 ]; then
        echo "ok $tests_run - $2"
    else
        failures=$((failures + 1))
        echo "not ok $tests_run - $2"
        [ -n "${3:-}" ] && printf '%s\n' "$3" | sed 's/^/# /'
    fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bc_attrib_test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---- a staged repo root -----------------------------------------------------
# build-consumers.sh resolves its ROOT as $(dirname $0)/.., and `consumers/` is
# gitignored in this repo, so the fixture consumers cannot live in the real
# tree. Stage a minimal root instead: the script itself plus the fixture dirs it
# reads. t/module must exist because the script adds it to the configure argv.
ROOT="$WORK/root"
mkdir -p "$ROOT/tools" "$ROOT/t/module" "$ROOT/consumers"
cp "$REPO/tools/build-consumers.sh" "$ROOT/tools/build-consumers.sh"
chmod +x "$ROOT/tools/build-consumers.sh"
: >"$ROOT/t/module/config"

# ---- the multi-file consumer fixture ----------------------------------------
# Shaped exactly like labs/http-zstd: the top-level config declares a DIFFERENT
# ngx_addon_name (`ngx_zstd`) and sources two fragments that set the real module
# names. A config-text grep of the top level therefore sees only `ngx_zstd`,
# which is the false negative under test. The files' contents are never executed
# by this test -- the stub configure below reports the module set directly --
# but they are written faithfully so the fixture documents the shape it stands
# for.
mkdir -p "$ROOT/consumers/multi/src" "$ROOT/consumers/multi/filter" "$ROOT/consumers/multi/static"
cat >"$ROOT/consumers/multi/config" <<'CFG'
_root=$ngx_addon_dir
ngx_addon_dir=$_root/src
. $_root/filter/config
ngx_addon_dir=$_root/src
. $_root/static/config
ngx_addon_dir=$_root
ngx_addon_name=ngx_zstd
CFG
cat >"$ROOT/consumers/multi/filter/config" <<'CFG'
ngx_addon_name=ngx_fixture_filter_module
ngx_module_name=ngx_fixture_filter_module
CFG
cat >"$ROOT/consumers/multi/static/config" <<'CFG'
ngx_addon_name=ngx_fixture_static_module
ngx_module_name=ngx_fixture_static_module
CFG
: >"$ROOT/consumers/multi/src/ngx_fixture_filter_module.c"
: >"$ROOT/consumers/multi/src/ngx_fixture_static_module.c"

# ---- the stub source tree ---------------------------------------------------
# STUB_SO is the module set the stub "builds": one `name:source` pair per line.
# The stub writes objs/Makefile in nginx's shape and links (touches) each .so.
#
# PRESEED_STALE names a .so the stub creates with an OLD mtime INSTEAD of a
# fresh one -- the planted stale artifact. It is created by `configure` (before
# the marker's comparison window closes) and deliberately left untouched by
# `make`, which is how a real stale artifact survives: nothing rebuilt it.
make_stub_src() {          # make_stub_src DIR
    local d="$1"
    mkdir -p "$d"
    cat >"$d/configure" <<'STUB'
#!/usr/bin/env bash
# Stub ./configure: writes objs/Makefile in nginx's dynamic-module shape.
#
# The `\`-continued prerequisite list and the separate compile rule carrying the
# ABSOLUTE source path are both load-bearing -- they are exactly what the
# attribution parser in build-consumers.sh reads, so a stub that flattened them
# would test a shape nginx never emits.
set -euo pipefail
mkdir -p objs
{
    echo "modules:"
    while IFS=: read -r nm src; do
        [ -n "$nm" ] || continue
        echo "objs/$nm.so:	objs/addon/src/$nm.o \\"
        echo "	objs/${nm}_modules.o"
        echo ""
        echo "objs/addon/src/$nm.o:	\$(ADDON_DEPS) \\"
        echo "	$src"
        echo "	\$(CC) -c -o objs/addon/src/$nm.o $src"
        echo ""
        echo "objs/${nm}_modules.o:	objs/${nm}_modules.c"
        echo ""
    done <<<"$STUB_SO"
} >objs/Makefile
# The preseeded stale artifact is created HERE, then stamped old, and `make`
# below never touches it again.
if [ -n "${PRESEED_STALE:-}" ]; then
    : >"objs/$PRESEED_STALE"
    touch -d '2020-01-01 00:00:00' "objs/$PRESEED_STALE"
fi
STUB
    cat >"$d/Makefile" <<'STUB'
all:
	@mkdir -p objs/addon/src
	@printf '%s\n' "$$STUB_SO" | while IFS=: read -r nm src; do \
	    [ -n "$$nm" ] || continue; \
	    if [ "$$nm.so" != "$$PRESEED_STALE" ]; then : >"objs/$$nm.so"; fi; \
	 done
	@: >objs/nginx
	@: >objs/ngx_http_test_ref_module.so
STUB
    chmod +x "$d/configure"
}

# run_build DIR -> stdout+stderr of the real build-consumers.sh
run_build() {
    local src="$1"; shift
    # BUILD_CONSUMERS_ALLOW_CONCURRENT=1: the stub tree compiles nothing, so
    # the one-build-at-a-time host rule has nothing to protect here -- and
    # without lifting it this test's verdict would depend on whether an
    # unrelated pdebuild happened to be running on the box. Property 8 below
    # asserts the opt-out is scoped to the literal 1 so it cannot become a
    # blanket off-switch.
    ( cd "$ROOT" && STUB_SO="$STUB_SO" PRESEED_STALE="${PRESEED_STALE:-}" \
        BUILD_CONSUMERS_ALLOW_CONCURRENT=1 \
        tools/build-consumers.sh --src "$src" --keep-src "$@" ) 2>&1 || true
}

# ============================================================================
# PROPERTY 1+2 -- attribution across a sourced multi-file config
# ============================================================================
# Pre-fix this run printed `multi   NO   (no .so; ...)` and then denounced both
# fresh .so as belonging to no module. Both halves are asserted, because either
# one alone can be satisfied by an unrelated change: a tool that attributed
# nothing at all and also swept nothing would pass a single-sided check.
SRC1="$WORK/src1"
STUB_SO="ngx_fixture_filter_module:$ROOT/consumers/multi/src/ngx_fixture_filter_module.c
ngx_fixture_static_module:$ROOT/consumers/multi/src/ngx_fixture_static_module.c"
PRESEED_STALE=""
make_stub_src "$SRC1"
OUT1="$(run_build "$SRC1")"

# Scoped to the `multi` ROW. Verified necessary: `*multi*yes*` against the whole
# output passed PRE-FIX, because the row said NO and the REFERENCE PROBE's own
# "yes" appeared further down -- the assertion was matching a different line
# than the one it named.
ROW1_RAW="$(printf '%s\n' "$OUT1" | grep -E '^multi[[:space:]]' || true)"
case "$ROW1_RAW" in
    *yes*) s=0 ;;
    *) s=1 ;;
esac
ok "$s" "a consumer whose real module names live in SOURCED config fragments is reported BUILT" "row=$ROW1_RAW"

case "$OUT1" in
    *"belong to no module in this run"*) s=1 ;;
    *) s=0 ;;
esac
ok "$s" "its two fresh .so are NOT denounced as belonging to no module" "$OUT1"

# Both names, specifically -- a report naming only one would still match the
# "yes" grep above. The .so column carries the manifest's target names.
#
# THE MATCH IS SCOPED TO THE TABLE ROW, not to the output as a whole. Verified
# necessary: matched against the whole output these two assertions passed
# PRE-FIX, because the old sweep printed both names in its "belong to no module"
# denunciation. A whole-output grep therefore could not tell attribution from
# its exact opposite -- the vacuous shape this file exists to avoid. `|| true`
# guards the grep under set -e; an unmatched grep exits 1 and would truncate the
# TAP stream, which reads as a pass to anything counting failures.
ROW1="$ROW1_RAW"

case "$ROW1" in
    *ngx_fixture_filter_module.so*) s=0 ;;
    *) s=1 ;;
esac
ok "$s" "the multi table ROW names ngx_fixture_filter_module.so from filter/config" "row=$ROW1"

case "$ROW1" in
    *ngx_fixture_static_module.so*) s=0 ;;
    *) s=1 ;;
esac
ok "$s" "the multi table ROW names ngx_fixture_static_module.so from static/config" "row=$ROW1"

# The paired negative for the staleness oracle: a run where every .so really was
# built now must report NOTHING stale. Without this, an oracle that flagged every
# .so unconditionally would pass property 5 below and prove nothing.
case "$OUT1" in
    *"are OLDER than this build started"*) s=1 ;;
    *) s=0 ;;
esac
ok "$s" "an all-fresh tree reports no stale .so" "$OUT1"

# ============================================================================
# PROPERTY 3 -- a stale .so whose name IS attributed is reported stale
# ============================================================================
# THE CORE REGRESSION GUARD, and the false green the old sweep banked. The
# planted artifact is ngx_fixture_filter_module.so: its name is in the manifest,
# so the old attribution-only sweep saw a KNOWN name and said nothing at all,
# while the scenario's requires gate would have found the file and probed a
# module built in 2020.
SRC2="$WORK/src2"
STUB_SO="ngx_fixture_filter_module:$ROOT/consumers/multi/src/ngx_fixture_filter_module.c
ngx_fixture_static_module:$ROOT/consumers/multi/src/ngx_fixture_static_module.c"
PRESEED_STALE="ngx_fixture_filter_module.so"
make_stub_src "$SRC2"
OUT2="$(run_build "$SRC2")"

case "$OUT2" in
    *"are OLDER than this build started"*) s=0 ;;
    *) s=1 ;;
esac
ok "$s" "a .so older than the build start is reported STALE even though its name attributes" "$OUT2"

# And it NAMES the artifact. A sweep that bails for the right reason but prints
# something else sends the next session after the wrong file -- the same pairing
# stale_so_test.sh makes for its own bail message.
# Scoped to the stale block for the same reason as the table rows above: the
# artifact's name appears elsewhere in the output (the BUILT table lists it),
# so a whole-output match would pass even with the stale sweep deleted
# entirely. Take the lines AFTER the stale banner and require the planted
# artifact among them -- and require that the FRESH sibling is not there, which
# is what separates a real per-artifact oracle from one that dumps every .so.
STALE_BLOCK="$(printf '%s\n' "$OUT2" | sed -n '/are OLDER than this build started/,/^$/p' || true)"

case "$STALE_BLOCK" in
    *ngx_fixture_filter_module.so*) s=0 ;;
    *) s=1 ;;
esac
ok "$s" "the stale block names the planted stale artifact" "block=$STALE_BLOCK"

case "$STALE_BLOCK" in
    *ngx_fixture_static_module.so*) s=1 ;;
    *) s=0 ;;
esac
ok "$s" "the stale block does NOT name the freshly-built sibling .so" "block=$STALE_BLOCK"

# ============================================================================
# PROPERTY 4 -- the concurrency opt-out is scoped to the literal value 1
# ============================================================================
# Asserted against the SCRIPT SOURCE rather than by running it: driving the
# refusal needs a pbuilder actually running on the host, which this test must
# not require (and must not fake by spawning one). The blanket-off-switch shape
# is a source property -- a `!= 1` compare rather than a `-n` test -- so reading
# it out of the source is a direct check, not a proxy. `|| true` on the grep is
# load-bearing under set -e: a grep that matches nothing exits 1 and would kill
# the script mid-TAP, which reads as a pass to anything counting failures.
guard="$(grep -c 'BUILD_CONSUMERS_ALLOW_CONCURRENT:-0}" != 1' "$REPO/tools/build-consumers.sh" || true)"
ok "$([ "$guard" -ge 1 ] && echo 0 || echo 1)" \
   "BUILD_CONSUMERS_ALLOW_CONCURRENT is compared against the literal 1, not merely non-empty" \
   "matches=$guard"

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# PLAN MISMATCH: ran $tests_run, planned $PLANNED"
    exit 1
fi

exit $((failures > 0 ? 1 : 0))
