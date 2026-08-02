#!/usr/bin/env bash
# shellcheck disable=SC2034
#
# Define the expected SKIP scenarios for each flavor/version combination.
#
# Scenarios that are permitted to SKIP are listed here per flavor-version.
# A scenario that SKIPs but is NOT in this allowlist will cause test-scenarios.sh
# to exit non-zero, preventing a silent regression where a new SKIP appears.
#
# Rationale: 8 scenarios skip in CI (consumer modules + reload-compressing not
# built), and syscall-allowlist skips without strace. If a 9th scenario starts
# skipping, we want to notice and decide explicitly whether to allowlist it,
# rather than silently accepting the coverage loss.

# Map flavor-version to scenario allowlist. Format: one scenario name per line
# in the array. Derived from:
# - Consumer scenarios always skip in CI (no consumers built): consumer-*
# - reload-compressing skips when zstd/python3 missing or .so not built: reload-compressing
# - syscall-allowlist skips when strace unavailable or ptrace restricted
#   (CI enables ptrace with sudo sysctl, and installs strace, so this only
#    skips in local runs lacking those; not a concern here since CI has them)

case "${1:-}:${2:-}" in
    nginx:1.28.0)
        PROBER_EXPECTED_SKIPS=(
            consumer-api-abuse
            consumer-cache-turbo
            consumer-coraza
            consumer-error-abuse
            consumer-shield
            consumer-skeleton
            consumer-strip-filter
            reload-compressing
        )
        ;;
    nginx:1.29.0)
        PROBER_EXPECTED_SKIPS=(
            consumer-api-abuse
            consumer-cache-turbo
            consumer-coraza
            consumer-error-abuse
            consumer-shield
            consumer-skeleton
            consumer-strip-filter
            reload-compressing
        )
        ;;
    angie:1.12.0)
        PROBER_EXPECTED_SKIPS=(
            consumer-api-abuse
            consumer-cache-turbo
            consumer-coraza
            consumer-error-abuse
            consumer-shield
            consumer-skeleton
            consumer-strip-filter
            reload-compressing
        )
        ;;
    *)
        # Unknown flavor/version: emit warning but don't fail
        # (local developer builds may use different versions)
        echo "warning: unknown flavor/version '${1:-?}:${2:-?}', skip allowlist validation skipped" >&2
        PROBER_EXPECTED_SKIPS=()
        ;;
esac
