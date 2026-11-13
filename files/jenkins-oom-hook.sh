#!/bin/bash
# -XX:OnOutOfMemoryError target.
#
# Ordering in HotSpot: the JVM writes the heap dump, then forks this command
# (without waiting), then -XX:+ExitOnOutOfMemoryError tears the JVM down.
# So this keeps running while Jenkins restarts: it renames the dump to a
# timestamped name so retention is ordered, then compresses it at idle IO.
set -u
export LC_ALL=C

[ -r /etc/jenkins-forensics.conf ] && . /etc/jenkins-forensics.conf

ROOT=${FORENSICS_ROOT:-/u/jenkins-forensics}
KEEP_DUMPS=${KEEP_HEAP_DUMPS:-2}
[ -d "$ROOT" ] || exit 0

ts=$(date -u +%Y%m%dT%H%M%SZ)
printf '%s out-of-memory hook fired (ppid %s)\n' "$ts" "${PPID:-?}" \
  >> "$ROOT/oom.log" 2>/dev/null || true

# -XX:HeapDumpPath=<dir> makes the VM write java_pid<PID>.hprof into that dir.
for f in "$ROOT"/java_pid*.hprof; do
  [ -f "$f" ] || continue
  base=$(basename "$f" .hprof)
  pid=${base#java_pid}
  dest="$ROOT/heap-$ts-pid$pid.hprof"
  mv -f -- "$f" "$dest" 2>/dev/null || continue
  printf '%s renamed dump to %s\n' "$ts" "$dest" >> "$ROOT/oom.log" 2>/dev/null || true
  if command -v ionice >/dev/null 2>&1; then
    (nice -n 19 ionice -c 3 gzip -1 -- "$dest") >/dev/null 2>&1 &
  else
    (nice -n 19 gzip -1 -- "$dest") >/dev/null 2>&1 &
  fi
done

# Keep only the newest dumps; runs immediately, does not wait for gzip.
ls -1t "$ROOT"/heap-*.hprof* 2>/dev/null | tail -n +$((KEEP_DUMPS + 1)) | xargs -r rm -f 2>/dev/null

exit 0
