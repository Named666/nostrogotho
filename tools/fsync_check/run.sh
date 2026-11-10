#!/bin/sh
# Fsync-before-OK check (Linux, glibc): every OK true leaves the relay only
# after an fdatasync/fsync of the WAL that started after the event's frames
# were written. Runs the default (coalescing VFS on), NG_WAL_COALESCE=0, and
# a db_sync = normal negative control that must report violations.
# Usage: tools/fsync_check/run.sh   (needs build/main and the tests venv)
set -e
cd "$(dirname "$0")"
PY=${PY:-python3}
cc -O2 -shared -fPIC -o /tmp/ng_fsync_trace.so fsync_trace.c -ldl -lpthread
export FSYNC_TRACE_SO=/tmp/ng_fsync_trace.so
$PY run_check.py 1
$PY run_check.py 0
if $PY run_check.py 1 "db_sync = normal"; then echo "negative control did not detect early OKs"; exit 1; fi
echo "fsync_check: OK (FULL sync acknowledges only fsynced commits; the checker catches NORMAL)"
