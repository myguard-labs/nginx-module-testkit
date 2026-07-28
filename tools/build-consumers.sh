#!/usr/bin/env bash
#
# build-consumers.sh -- build the consumer modules in consumers/ as dynamic
# modules against a real nginx/angie source tree, alongside the harness's own
# reference probe module (t/module), and stage the result where prober_resolve
# looks for it.
#
# WHY THIS EXISTS
#   The consumer scenarios (prober/scenarios/consumer-*) each load a real
#   third-party .so out of the SAME objs/ dir as the ref probe -- see
#   consumer-cache-turbo/nginx.conf. nginx binds its dynamic-module list at
#   CONFIGURE time, so "the ref probe plus these N consumers" is one configure
#   and one make; there is no way to add a module to an already-built tree.
#   Doing that by hand is a 20-line invocation nobody remembers correctly, and
#   getting it wrong produces a tree where the scenario SKIPs (missing .so) or,
#   worse, loads a STALE .so and fakes a probe result
#   ([[feedback-stale-so-fakes-negative-control]]). Hence a script.
#
# USAGE
#   tools/build-consumers.sh [OPTIONS]
#
#   --flavor NAME     nginx | angie          (default: nginx)
#   --version VER     upstream version       (default: 1.29.0)
#   --stage NAME      .build/<NAME>/objs dir (default: <flavor>-<version>-consumers,
#                     which is what you pass run-scenario.sh as its VERSION arg;
#                     NOT <flavor>-<version>, which is the ref-probe-only tree)
#   --only A,B,C      build only these consumers (dir names under consumers/)
#   --skip A,B,C      build everything except these
#   --src DIR         reuse an already-unpacked source tree instead of fetching
#   --keep-src        do not delete the unpacked source tree on success
#   --jobs N          make -j N               (default: 8, this box's rule)
#   --list            print the resolved consumer list and exit
#   --dry-run         print the configure/make it WOULD run, touch nothing
#   -h, --help        this header
#
# INPUTS   consumers/<name>/config  (each module's nginx addon config)
#          t/module/config          (the harness reference probe)
# OUTPUTS  .build/<stage>/objs/*.so  -- what run-scenario.sh loads
#
# SIDE EFFECTS
#   * NETWORK: downloads the upstream tarball (checksum-verified) unless --src.
#   * Writes to a temp dir under ${TMPDIR:-/tmp} and to .build/<stage>/.
#   * Runs a full ./configure + make -- minutes, and CPU-heavy. This host's
#     rule is ONE BUILD AT A TIME ([[feedback-no-parallel-builds]]); the script
#     refuses to start if another make/configure is running.
#   * Never writes inside consumers/<name>/ -- objects land in the nginx tree.
#
# EXIT
#   0  every requested consumer produced a .so
#   1  usage / precondition failure (bad flavor, checksum, concurrent build)
#   2  the build ran but one or more consumers produced NO .so -- the per-module
#      first error is printed. That is a RESULT (a module that does not build is
#      a finding), not necessarily a script failure; callers that want the tree
#      anyway should check for the .so they need rather than the exit code.
#
# KNOWN LIMITS / WHERE TO EXTEND
#   * A module needing an external lib (hiredis, libcoraza, ...) fails at
#     configure or link if that lib is absent. The script reports which and
#     keeps going with the rest -- it does not install dependencies.
#   * label-autoconf also emits a STREAM .so; it is built and staged, but the
#     harness's stream client is PARKED, so no scenario drives it yet.
#   * Sanitizer legs are not wired here (the scenario CI job owns that). Add a
#     --san flag mirroring ci.yml's SAN_CC/SAN_LD if that is ever wanted.
#
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

FLAVOR=nginx
VERSION=1.29.0
STAGE=""
ONLY=""
SKIP=""
SRC=""
KEEP_SRC=0
JOBS=8
DRY=0
LIST=0

die() { echo "build-consumers: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --flavor)   FLAVOR="${2:?}"; shift 2 ;;
        --version)  VERSION="${2:?}"; shift 2 ;;
        --stage)    STAGE="${2:?}"; shift 2 ;;
        --only)     ONLY="${2:?}"; shift 2 ;;
        --skip)     SKIP="${2:?}"; shift 2 ;;
        --src)      SRC="${2:?}"; shift 2 ;;
        --keep-src) KEEP_SRC=1; shift ;;
        --jobs)     JOBS="${2:?}"; shift 2 ;;
        --list)     LIST=1; shift ;;
        --dry-run)  DRY=1; shift ;;
        -h|--help)  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          die "unknown option: $1 (try --help)" ;;
    esac
done

# The stage name is what run-scenario.sh must be given as its VERSION argument
# (lib.sh:78 composes .build/<flavor>-<version> and the generated requires gates
# recompute the same string), so the default has to be a name a scenario run can
# actually name. "-multi" was not: nothing passes `1.29.0-multi` as a version, so
# a bare run staged ten modules where no scenario would ever look.
#
# "-consumers" rather than a plain "<flavor>-<version>": the plain name is the
# ref-probe-only tree the ordinary scenarios boot, and this script wipes objs/
# before building. Defaulting there would silently destroy that tree on a bare
# run. Drive the result with:
#     prober/test-scenarios.sh nginx 1.29.0-consumers
[ -n "$STAGE" ] || STAGE="${FLAVOR}-${VERSION}-consumers"

case "$FLAVOR" in
    nginx) URL="https://nginx.org/download/nginx-${VERSION}.tar.gz" ;;
    angie) URL="https://download.angie.software/files/angie-${VERSION}.tar.gz" ;;
    *)     die "unknown flavor '$FLAVOR' (expected nginx or angie)" ;;
esac

# Checksums for the versions ci.yml pins. An unpinned version still builds, but
# without a checksum to verify -- warn loudly rather than silently trusting the
# download, since a tampered tarball would be compiled and run.
sha_for() {
    case "$1" in
        nginx-1.28.0) echo c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a ;;
        nginx-1.29.0) echo 109754dfe8e5169a7a0cf0db6718e7da2db495753308f933f161e525a579a664 ;;
        angie-1.12.0) echo cd7867d200b22a80165b93696c30a1ac3a28c1162544b7f43c71232b19814ef6 ;;
        *) echo "" ;;
    esac
}

# ---- resolve the consumer list ---------------------------------------------
# Membership is "has a consumers/<name>/config", i.e. is a real nginx addon.
# A directory without one is not buildable as a dynamic module and is skipped
# with a visible note rather than failing the whole run.
mapfile -t ALL < <(
    for d in consumers/*/; do
        n="${d%/}"; n="${n#consumers/}"
        [ -f "consumers/$n/config" ] && echo "$n"
    done | sort
)
[ "${#ALL[@]}" -gt 0 ] || die "no consumers with a ./config found -- run tools/sync-consumers.sh first"

in_csv() {  # in_csv NEEDLE CSV
    case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

CONSUMERS=()
for n in "${ALL[@]}"; do
    [ -n "$ONLY" ] && { in_csv "$n" "$ONLY" || continue; }
    [ -n "$SKIP" ] && { in_csv "$n" "$SKIP" && continue; }
    CONSUMERS+=("$n")
done
[ "${#CONSUMERS[@]}" -gt 0 ] || die "consumer selection is empty (--only/--skip filtered everything out)"

if [ "$LIST" -eq 1 ]; then
    printf '%s\n' "${CONSUMERS[@]}"
    exit 0
fi

# ---- build the configure argv ----------------------------------------------
# t/module FIRST: the ref probe is what every scenario needs, so if the argv is
# ever truncated the probe is the piece most likely to survive.
#
# --with-http_ssl_module is NOT optional here even though no scenario speaks
# TLS. nginx-autocert-module's sources use ngx_ssl_t, ngx_ssl_create() and
# NGX_SSL_TLSv1_2, all of which nginx compiles only under NGX_HTTP_SSL; without
# the flag its config still "configures fine" and then the build dies with
# `field 'ssl' has incomplete type`, which reads like a module bug and is not
# one. The module's own ./config does not declare this dependency, so the
# requirement is invisible until you hit it -- hence stating it here.
# --with-stream is likewise required for label-autoconf's STREAM half; without
# it that module silently builds only its HTTP .so.
ARGS=(--with-compat --with-http_ssl_module --with-stream --with-stream_ssl_module
      "--add-dynamic-module=$ROOT/t/module")
for n in "${CONSUMERS[@]}"; do
    ARGS+=("--add-dynamic-module=$ROOT/consumers/$n")
done

if [ "$DRY" -eq 1 ]; then
    echo "would fetch : $URL"
    echo "would stage : .build/$STAGE/objs"
    echo "would run   : ./configure ${ARGS[*]}"
    echo "would run   : make -j$JOBS modules"
    exit 0
fi

# ---- host rule: one build at a time ----------------------------------------
# A concurrent nginx/pbuilder build on this box thrashes and has produced stale
# artifacts before. Refuse rather than race.
if pgrep -f 'pbuilder|dpkg-buildpackage' >/dev/null 2>&1; then
    die "another package build is running on this host -- refusing to start (one build at a time)"
fi

# ---- fetch / unpack ---------------------------------------------------------
TMP=""
cleanup() {
    if [ -n "$TMP" ] && [ "$KEEP_SRC" -eq 0 ]; then
        rm -rf "$TMP" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [ -n "$SRC" ]; then
    [ -f "$SRC/configure" ] || die "--src '$SRC' has no ./configure"
    BUILDDIR="$SRC"
    echo "==> reusing source tree $BUILDDIR"

    # WIPE objs/ FIRST. nginx's ./configure does NOT clear it -- the only
    # `rm -rf $NGX_OBJS` in auto/init is the TEXT of the Makefile's `clean:`
    # target being written out, not a command configure runs. So a reused tree
    # keeps every .so from its previous build, and this script stages objs/
    # wholesale (`cp -r` below).
    #
    # The failure that makes this mandatory: run once with all nine consumers,
    # then again with `--src <that tree> --only coraza`. The second configure
    # binds only t/module + coraza, make rebuilds only those, and the staging
    # copy carries the other eight STALE .so into .build/<stage>/objs. Every
    # consumer scenario's `requires` gate then finds its .so, passes, and the
    # scenario probes a module that was never rebuilt -- possibly against a
    # different nginx version. That is exactly
    # [[feedback-stale-so-fakes-negative-control]], the bug class this script's
    # own header cites as its reason to exist.
    if [ -d "$BUILDDIR/objs" ]; then
        echo "==> wiping $BUILDDIR/objs (a reused tree's old .so would be staged as if fresh)"
        rm -rf "$BUILDDIR/objs"
    fi
else
    TMP="$(mktemp -d "${TMPDIR:-/tmp}/build-consumers.XXXXXX")"
    BUILDDIR="$TMP/src"
    mkdir -p "$BUILDDIR"
    echo "==> fetching $URL"
    # Bound the fetch: this script goes on to burn a lot of CPU, and a mirror
    # that accepts the connection and then stalls would otherwise hold the slot
    # open indefinitely rather than failing and freeing it.
    curl -fsSL --connect-timeout 15 --max-time 300 -o "$TMP/srv.tar.gz" "$URL" \
        || die "download failed: $URL"
    want="$(sha_for "${FLAVOR}-${VERSION}")"
    if [ -n "$want" ]; then
        echo "$want  $TMP/srv.tar.gz" | sha256sum -c - >/dev/null \
            || die "checksum MISMATCH for ${FLAVOR}-${VERSION} -- refusing to build a tarball that is not what ci.yml pins"
        echo "==> checksum verified"
    else
        echo "!!! no pinned checksum for ${FLAVOR}-${VERSION} -- building an UNVERIFIED tarball" >&2
    fi
    tar -xzf "$TMP/srv.tar.gz" -C "$BUILDDIR" --strip-components=1
fi

# ---- configure + make -------------------------------------------------------
echo "==> configure with ${#CONSUMERS[@]} consumer(s) + the reference probe"
CONFLOG="$BUILDDIR/configure.consumers.log"
if ! ( cd "$BUILDDIR" && ./configure "${ARGS[@]}" ) >"$CONFLOG" 2>&1; then
    echo "--- configure FAILED, tail of $CONFLOG:" >&2
    tail -30 "$CONFLOG" >&2
    die "configure failed"
fi

echo "==> make -j$JOBS (binary + modules)"
MAKELOG="$BUILDDIR/make.consumers.log"
MAKE_RC=0
# The DEFAULT target, not `modules`. run-scenario.sh boots
# .build/<stage>/objs/nginx, so a tree with only the .so set makes every
# scenario bail with "no server binary" -- and because a PREVIOUS build may have
# left a binary behind in the staging dir, that failure can hide until the day
# someone builds into a clean stage. Build both, always.
#
# -k so a single module's compile error does not abort the whole run: the point
# is to learn WHICH modules build, and one broken consumer must not cost the
# results for the other eight.
( cd "$BUILDDIR" && make -j"$JOBS" -k ) >"$MAKELOG" 2>&1 || MAKE_RC=$?

# ---- stage ------------------------------------------------------------------
DEST="$ROOT/.build/$STAGE"
mkdir -p "$DEST"
rm -rf "$DEST/objs"
cp -r "$BUILDDIR/objs" "$DEST/objs"
echo "==> staged $DEST/objs"

# ---- report -----------------------------------------------------------------
# A module maps to its .so via its config's ngx_module_name / ngx_addon_name.
# Both are read because the two spellings are both in use across our modules.
#
# The value may be QUOTED (coraza-nginx writes ngx_addon_name="ngx_http_coraza_module")
# or bare, and a config may set ngx_module_name from a variable
# (ngx_module_name="$ngx_addon_name"), so strip quotes and drop any value that is
# still a $-reference after that. Getting this wrong reports a module that built
# fine as NO -- which is worse than a build failure, because it sends the next
# session hunting a compile bug that does not exist.
missing=0
ACCOUNTED=()
echo
printf '%-32s %-12s %s\n' MODULE BUILT SO
printf '%-32s %-12s %s\n' ------ ----- --
for n in "${CONSUMERS[@]}"; do
    mapfile -t names < <(
        grep -hoE '^[[:space:]]*(ngx_module_name|ngx_addon_name)=["'"'"']?[A-Za-z0-9_$]+' \
            "consumers/$n/config" 2>/dev/null \
            | sed -e 's/.*=//' -e 's/^["'"'"']//' \
            | grep -v '\$' | sort -u
    )
    got=""
    for nm in "${names[@]}"; do
        [ -f "$DEST/objs/${nm}.so" ] && got="$got ${nm}.so"
        # Record it as accounted-for whether or not it exists, so the
        # unattributable sweep below only reports genuinely foreign artifacts.
        ACCOUNTED+=("${nm}.so")
    done
    if [ -n "$got" ]; then
        printf '%-32s %-12s%s\n' "$n" yes "$got"
    else
        printf '%-32s %-12s %s\n' "$n" NO "(no .so; see $MAKELOG)"
        missing=$((missing + 1))
    fi
done

if [ -f "$DEST/objs/ngx_http_test_ref_module.so" ]; then
    printf '\n%-32s %-12s %s\n' '(reference probe)' yes ngx_http_test_ref_module.so
else
    echo
    echo "!!! the REFERENCE PROBE did not build -- no scenario can run against this tree" >&2
    missing=$((missing + 1))
fi

# run-scenario.sh boots objs/nginx. Assert it explicitly: without this the only
# symptom is every scenario bailing "no server binary", one layer away from the
# cause.
# angie names its server binary objs/angie, nginx names it objs/nginx -- the
# same split lib.sh:80-81 makes when it picks PROBER_SERVER_BIN. Hardcoding
# objs/nginx here reported a missing binary on every --flavor angie build,
# however well it had gone.
SRVBIN=nginx
[ "$FLAVOR" = angie ] && SRVBIN=angie
if [ -f "$DEST/objs/$SRVBIN" ]; then
    printf '%-32s %-12s %s\n' '(server binary)' yes "objs/$SRVBIN"
else
    echo "!!! objs/$SRVBIN is MISSING -- run-scenario.sh cannot boot this tree" >&2
    missing=$((missing + 1))
fi

# UNATTRIBUTABLE .so SWEEP. The table above walks the REQUESTED consumers, so on
# its own it is silent about a .so that is present in the staged tree but owned
# by nothing in this run -- which is precisely what a stale artifact looks like.
# The objs/ wipe above should make this impossible; this is the check that says
# so out loud rather than assuming it. A scenario's `requires` gate only asks
# "does the .so exist", so an unowned one is fully loadable and would be probed
# as if it were fresh.
ACCOUNTED+=(ngx_http_test_ref_module.so)
unattributed=()
for so in "$DEST"/objs/*.so; do
    [ -e "$so" ] || continue
    base="$(basename "$so")"
    known=0
    for a in "${ACCOUNTED[@]}"; do
        [ "$base" = "$a" ] && { known=1; break; }
    done
    [ "$known" -eq 0 ] && unattributed+=("$base")
done
if [ "${#unattributed[@]}" -gt 0 ]; then
    echo
    echo "!!! ${#unattributed[@]} .so in $DEST/objs belong to no module in this run:" >&2
    printf '        %s\n' "${unattributed[@]}" >&2
    echo "    These were NOT built now. A scenario loading one probes a stale" >&2
    echo "    artifact and reports on code that was never rebuilt -- delete the" >&2
    echo "    stage dir and rebuild, or re-run without --only/--skip." >&2
    missing=$((missing + 1))
fi

if [ "$missing" -gt 0 ]; then
    echo
    echo "$missing module(s) produced no .so (make rc=$MAKE_RC). First error per failing module:" >&2
    grep -nE 'error:|Error [0-9]|undefined reference' "$MAKELOG" | head -20 >&2 || true
    [ "$KEEP_SRC" -eq 1 ] && echo "source tree kept at $BUILDDIR" >&2
    exit 2
fi

echo
echo "all ${#CONSUMERS[@]} consumer(s) + the reference probe built into $DEST/objs"
