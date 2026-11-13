#!/bin/bash
# ExecStopPost for jenkins.service, invoked as root via the "+" prefix in
# /etc/systemd/system/jenkins.service.d/10-forensics.conf.
#
# Preserves an incident bundle only when the stop was not clean, so ordinary
# puppet-driven restarts do not accumulate directories.
set -u
export LC_ALL=C

[ -r /etc/jenkins-forensics.conf ] && . /etc/jenkins-forensics.conf

ROOT=${FORENSICS_ROOT:-/u/jenkins-forensics}
GC_DIR=${GC_LOG_DIR:-/u/jenkins-forensics/gc}
KEEP_DUMPS=${KEEP_HEAP_DUMPS:-2}
KEEP_INC=${KEEP_INCIDENTS:-20}
OWNER=${JENKINS_USER:-jenkins}
GROUP=${JENKINS_GROUP:-jenkins}

log() { printf 'jenkins-postmortem: %s\n' "$*" >&2; }

result=${SERVICE_RESULT:-unknown}
status=${EXIT_STATUS:-unknown}
code=${EXIT_CODE:-unknown}

# One-line breadcrumb on every stop: this makes the crash timeline obvious
# without needing the full bundle.
printf '%s service_result=%s exit_code=%s exit_status=%s main_pid=%s\n' \
  "$(date -u +%FT%TZ)" "$result" "$code" "$status" "${MAINPID:-unknown}" \
  >> "$ROOT/exits.log" 2>/dev/null || true

# Clean stop (systemctl stop / puppet restart): nothing to preserve.
case "$result:$status" in
  success:0) exit 0 ;;
esac

ts=$(date -u +%Y%m%dT%H%M%SZ)
dir="$ROOT/incidents/$ts"
mkdir -p "$dir" || exit 0

{
  printf 'captured=%s\n' "$ts"
  printf 'service_result=%s\n' "$result"
  printf 'exit_code=%s\n' "$code"
  printf 'exit_status=%s\n' "$status"
  printf 'main_pid=%s\n' "${MAINPID:-unknown}"
  printf 'invocation_id=%s\n' "${INVOCATION_ID:-unknown}"
} > "$dir/status.txt"

# The JVM's own last words: this is where the OutOfMemoryError lines land.
journalctl -u jenkins.service --since "-12h" --no-pager -o short-iso \
  > "$dir/journal.txt" 2>/dev/null || true

# Kernel side, to distinguish JVM heap OOM from the host running out of memory.
journalctl -k --since "-24h" --no-pager -o short-iso 2>/dev/null \
  | grep -iE 'out of memory|oom-kill|killed process|swap' > "$dir/kernel.txt" || true

# What the sampler saw right before the crash (heap %, thresholds hit).
journalctl -t jenkins-forensics --since "-12h" --no-pager -o short-iso \
  > "$dir/sampler.txt" 2>/dev/null || true

# Tail of the newest GC logs, bounded to ~16 MiB total.
if [ -d "$GC_DIR" ]; then
  ls -1t "$GC_DIR"/*.log 2>/dev/null | head -n 4 | while read -r f; do
    [ -f "$f" ] || continue
    {
      printf '===== %s (last 4MiB) =====\n' "$(basename "$f")"
      tail -c 4194304 -- "$f"
      printf '\n'
    } >> "$dir/gc-tail.log"
  done
fi

# Which dumps were on disk at crash time.
ls -1t "$ROOT"/heap-*.hprof* 2>/dev/null | head -n 4 > "$dir/heapdumps.txt" || true

# Compress any dump still uncompressed (the OOM hook is best-effort).
for f in "$ROOT"/*.hprof; do
  [ -f "$f" ] || continue
  if command -v ionice >/dev/null 2>&1; then
    (nice -n 19 ionice -c 3 gzip -1 -- "$f") >/dev/null 2>&1 &
  else
    (nice -n 19 gzip -1 -- "$f") >/dev/null 2>&1 &
  fi
done

# Retention by count.
ls -1t "$ROOT"/heap-*.hprof* 2>/dev/null | tail -n +$((KEEP_DUMPS + 1)) | xargs -r rm -f 2>/dev/null
ls -1dt "$ROOT"/incidents/*/ 2>/dev/null | tail -n +$((KEEP_INC + 1)) | xargs -r rm -rf 2>/dev/null
ls -1t "$GC_DIR"/*.log 2>/dev/null | tail -n +9 | xargs -r rm -f 2>/dev/null

# Keep heap.csv from growing without bound (it is a handful of bytes per tick).
if [ -f "$ROOT/heap.csv" ] && [ "$(stat -c %s "$ROOT/heap.csv" 2>/dev/null || echo 0)" -gt 10485760 ]; then
  tail -n 50000 "$ROOT/heap.csv" > "$ROOT/heap.csv.tmp" 2>/dev/null \
    && mv -f "$ROOT/heap.csv.tmp" "$ROOT/heap.csv"
fi

# Everything above ran as root; hand ownership back to the service account.
chown -R "$OWNER:$GROUP" "$ROOT" 2>/dev/null || true

log "incident bundle written to $dir"
exit 0
