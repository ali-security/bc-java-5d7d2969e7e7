#!/bin/sh
# Keep the job open until Travis has archived the test summary into this job's
# public log, so the log harvested right after the build finishes is complete.
# after_script cannot change the build result.
CAP="${1:-600}"
MARK="SEAL TEST"
MARK="$MARK TOTAL:"
URL="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
waited=0
while [ "$waited" -lt "$CAP" ]; do
  if curl -fsSL "$URL" 2>/dev/null | grep -q "$MARK"; then
    echo "log archive complete after ${waited}s"
    exit 0
  fi
  echo "waiting for log archive... (${waited}s)"
  sleep 20
  waited=$((waited + 20))
done
echo "log archive wait cap ${CAP}s reached"
exit 0
