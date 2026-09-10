#!/usr/bin/env bash
#
# Same discipline as lifecycle-journal's and lifecycle-quit-vs-term-drain's
# own mutate-suite.sh (read those first): every assertion in this scenario's
# driver.sh is a negative control, so "the suite exited nonzero" is credited
# only when the SPECIFIC row's own LIFECYCLE-USR1-RED-* marker was printed on
# the way down -- never on a generic boot/port/journal-attach failure, which
# would be the wrong owner.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

case "${MUT_ROW:-}" in
    *"in-flight gate needs"*)    EXPECT='LIFECYCLE-USR1-RED-NOT-INFLIGHT' ;;
    *"inode changes"*)          EXPECT='LIFECYCLE-USR1-RED-NO-REOPEN' ;;
    *"upload survives"*)        EXPECT='LIFECYCLE-USR1-RED-DISTURBED' ;;
    *"worker set unchanged"*)   EXPECT='LIFECYCLE-USR1-RED-WORKER-CHANGED' ;;
    *"fd count unchanged"*)     EXPECT='LIFECYCLE-USR1-RED-FD-LEAK' ;;
    *"no spurious exit"*)       EXPECT='LIFECYCLE-USR1-RED-SPURIOUS-EXIT' ;;
    *"rotated content"*)        EXPECT='LIFECYCLE-USR1-RED-OLD-FILE-CORRUPTED' ;;
    *"worker fd on new inode"*) EXPECT='LIFECYCLE-USR1-RED-WORKER-STALE-FD' ;;
    "")
        EXPECT='LIFECYCLE-USR1-RED-(NOT-INFLIGHT|NO-REOPEN|DISTURBED|WORKER-CHANGED|FD-LEAK|SPURIOUS-EXIT|OLD-FILE-CORRUPTED|WORKER-STALE-FD)' ;;
    *)
        echo "Bail out! scenarios/lifecycle-usr1-reopen/mutate-suite.sh does not" \
             "know which assertion row '$MUT_ROW' claims to red; add it to" \
             "the case above"
        exit 125
        ;;
esac
export MUTATE_REQUIRE_MARKER="$EXPECT"

run_mutate_suite scenarios/lifecycle-usr1-reopen nginx 1.29.0
