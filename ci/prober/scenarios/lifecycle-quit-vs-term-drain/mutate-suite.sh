#!/usr/bin/env bash
#
# Same discipline as lifecycle-journal's own mutate-suite.sh (read that one
# first): this scenario's driver.sh assertions are ALL negative controls, so
# "the suite exited nonzero" is credited only when the SPECIFIC row's own
# LIFECYCLE-DRAIN-RED-* marker was printed on the way down -- never on a
# generic boot/port/journal-attach failure, which would be the wrong owner.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

case "${MUT_ROW:-}" in
    *"QUIT in-flight gate"*)      EXPECT='LIFECYCLE-DRAIN-RED-QUIT-NOT-INFLIGHT' ;;
    *"QUIT drains upload"*)       EXPECT='LIFECYCLE-DRAIN-RED-QUIT-NOT-DRAINED' ;;
    *"QUIT terminal record"*)     EXPECT='LIFECYCLE-DRAIN-RED-QUIT-NO-TERMINAL' ;;
    *"QUIT ordering"*)            EXPECT='LIFECYCLE-DRAIN-RED-QUIT-ORDER' ;;
    *"TERM in-flight gate"*)      EXPECT='LIFECYCLE-DRAIN-RED-TERM-NOT-INFLIGHT' ;;
    *"TERM cuts upload"*)         EXPECT='LIFECYCLE-DRAIN-RED-TERM-DID-NOT-CUT' ;;
    *"TERM terminal record"*)     EXPECT='LIFECYCLE-DRAIN-RED-TERM-NO-TERMINAL' ;;
    *"contrast holds"*)           EXPECT='LIFECYCLE-DRAIN-RED-CONTRAST' ;;
    "")
        EXPECT='LIFECYCLE-DRAIN-RED-(QUIT-NOT-INFLIGHT|QUIT-NOT-DRAINED|QUIT-NO-TERMINAL|QUIT-ORDER|TERM-NOT-INFLIGHT|TERM-DID-NOT-CUT|TERM-NO-TERMINAL|CONTRAST)' ;;
    *)
        echo "Bail out! scenarios/lifecycle-quit-vs-term-drain/mutate-suite.sh does not" \
             "know which assertion row '$MUT_ROW' claims to red; add it to" \
             "the case above"
        exit 125
        ;;
esac
export MUTATE_REQUIRE_MARKER="$EXPECT"

run_mutate_suite scenarios/lifecycle-quit-vs-term-drain nginx 1.29.0
