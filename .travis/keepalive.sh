#!/bin/sh
# Run a long, quiet command while printing a heartbeat so Travis's
# 10-minute no-output watchdog does not kill the job. Exit status is preserved.
( while true; do sleep 240; echo "keepalive: still running $1"; done ) &
HB=$!
"$@"
RC=$?
kill $HB 2>/dev/null
exit $RC
