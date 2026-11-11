#!/bin/sh
# build1-5to1-8 does not propagate the exit status of "ant build"; fail the job
# when any ant invocation recorded in the log failed.
LOG="$1"
tail -n 40 "$LOG"
if grep -q "BUILD FAILED" "$LOG"; then
  echo "ant build failed:"
  grep -n -B 30 "BUILD FAILED" "$LOG" | head -n 200
  exit 1
fi
if [ ! -f build/artifacts/jdk1.5/jars/bcprov-jdk15to18-17801.jar ]; then
  echo "bcprov-jdk15to18 jar was not produced"
  exit 1
fi
ls -l build/artifacts/jdk1.5/jars/
