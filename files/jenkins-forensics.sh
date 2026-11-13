#!/bin/bash
# Cheap, space-bounded JVM evidence capture for the Jenkins controller.
#
# Runs every few minutes from jenkins-forensics.timer as the *jenkins* user,
# because jcmd can only attach to a JVM owned by the same UID.
#
# Ladder (evaluated once per JVM generation, state keyed on pid+starttime):
#   baseline (<50%)  jcmd GC.class_histogram   -> the "before" picture for diffing
#   >=70%            jcmd Thread.print + fd/thread/ssh counters
#   >=80%            jcmd GC.class_histogram   -> the "after" picture (forces one full GC)
#   >=88%            jcmd JFR.dump             -> allocation stacks + path-to-GC-roots
#   >=95% (armed)    jcmd GC.heap_dump -gz=1   -> only if HEAP_DUMP_PERCENT > 0
#
# Everything it writes is bounded by count; /etc/tmpfiles.d/jenkins-forensics.conf
# bounds it by age as a backstop.
set -u
export LC_ALL=C

[ -r /etc/jenkins-forensics.conf ] && . /etc/jenkins-forensics.conf

ROOT=${FORENSICS_ROOT:-/u/jenkins-forensics}
JFR_NAME=${JFR_NAME:-jenkins}
MIN_FREE_MB=${MIN_FREE_MB:-102400}
KEEP_DUMPS=${KEEP_HEAP_DUMPS:-2}
KEEP_SMALL=${KEEP_SMALL:-20}
KEEP_JFR=${KEEP_JFR:-4}
THR_PCT=${THREAD_PERCENT:-70}
HIST_PCT=${HISTOGRAM_PERCENT:-80}
HIST_MAX=${HISTOGRAM_MAX_PERCENT:-92}
JFR_PCT=${JFR_PERCENT:-88}
DUMP_PCT=${HEAP_DUMP_PERCENT:-0}
JCMD=${JCMD:-jcmd}

log() { printf 'jenkins-forensics: %s\n' "$*" >&2; }

PID=$(systemctl show -p MainPID --value jenkins 2>/dev/null || true)
case "${PID:-0}" in '' | 0) exit 0 ;; esac
[ -d "/proc/$PID" ] || exit 0

# Prefer the jcmd that ships with the JRE the controller actually runs: jcmd's
# attach protocol is not guaranteed across JDK versions.
JAVA_EXE=$(readlink -f "/proc/$PID/exe" 2>/dev/null || true)
if [ -n "${JAVA_EXE:-}" ] && [ -x "$(dirname "$JAVA_EXE")/jcmd" ]; then
  JCMD="$(dirname "$JAVA_EXE")/jcmd"
fi
[ -x "$JCMD" ] || JCMD=$(command -v jcmd 2>/dev/null || true)
[ -n "${JCMD:-}" ] && [ -x "$JCMD" ] || { log "no usable jcmd"; exit 1; }

# $22 of /proc/<pid>/stat is the start time in clock ticks: a stable generation id.
START=$(awk '{print $22}' "/proc/$PID/stat" 2>/dev/null || echo 0)
STATE="$ROOT/state/${PID}-${START}"
mkdir -p "$STATE" 2>/dev/null || exit 0

info=$("$JCMD" "$PID" GC.heap_info 2>/dev/null) || exit 0
read -r total used < <(printf '%s\n' "$info" \
  | sed -n 's/.*total \([0-9][0-9]*\)K, used \([0-9][0-9]*\)K.*/\1 \2/p' | head -n 1)
[ -n "${used:-}" ] && [ "${total:-0}" -gt 0 ] || { log "cannot parse GC.heap_info"; exit 0; }

pct=$((used * 100 / total))
stamp=$(date -u +%Y%m%dT%H%M%SZ)
free_mb=$(df -Pm "$ROOT" 2>/dev/null | awk 'NR==2{print $4}')
free_mb=${free_mb:-0}

csv="$ROOT/heap.csv"
[ -s "$csv" ] || printf 'ts_utc,pid,used_mib,total_mib,used_pct\n' > "$csv"
printf '%s,%s,%s,%s,%s\n' "$stamp" "$PID" "$((used / 1024))" "$((total / 1024))" "$pct" >> "$csv"
log "used ${pct}% ($((used / 1024)) MiB / $((total / 1024)) MiB) pid=$PID free=${free_mb}MiB"

# --- baseline: only worth taking while the heap is still small -----------------
if [ ! -e "$STATE/base" ] && [ "$pct" -lt 50 ]; then
  if "$JCMD" "$PID" GC.class_histogram > "$ROOT/histogram-$stamp-base.txt" 2>/dev/null; then
    : > "$STATE/base"
  fi
fi

# --- >=70%: thread dump + cheap counters (ssh sessions test the Ganymed theory) -
if [ "$pct" -ge "$THR_PCT" ] && [ ! -e "$STATE/threads" ]; then
  threads="$ROOT/threads-$stamp.txt"
  if "$JCMD" "$PID" Thread.print > "$threads" 2>/dev/null; then
    # grep -c prints "0" and exits 1 on no match: capture stdout only, never "|| echo 0".
    connect_threads=$(grep -c 'Connect thread' "$threads" 2>/dev/null)
    timer_threads=$(grep -c 'jenkins.util.Timer' "$threads" 2>/dev/null)
    {
      printf 'captured=%s\n' "$stamp"
      printf 'heap_used_pct=%s\n' "$pct"
      printf 'ssh_conn_established=%s\n' "$(ss -Htn state established '( sport = :22 or dport = :22 )' 2>/dev/null | wc -l)"
      printf 'tcp_conn_total=%s\n' "$(ss -Htn 2>/dev/null | wc -l)"
      printf 'threads=%s\n' "$(ls "/proc/$PID/task" 2>/dev/null | wc -l)"
      printf 'fds=%s\n' "$(ls "/proc/$PID/fd" 2>/dev/null | wc -l)"
      printf 'rss_kb=%s\n' "$(awk '/^VmRSS/{print $2}' "/proc/$PID/status" 2>/dev/null)"
      printf 'connect_thread_count=%s\n' "${connect_threads:-0}"
      printf 'timer_thread_count=%s\n' "${timer_threads:-0}"
    } > "$ROOT/conns-$stamp.txt"
    : > "$STATE/threads"
  fi
fi

# --- >=80%: the histogram that matters; diff it against the baseline ------------
# This forces one full GC, which is itself risky on an almost-full heap: never
# run it above HIST_MAX (a GC at 95% can throw OOM and, with ExitOnOutOfMemoryError,
# take the controller down). The JFR dump covers that case instead.
if [ "$pct" -ge "$HIST_PCT" ] && [ "$pct" -lt "$HIST_MAX" ] && [ ! -e "$STATE/histogram" ]; then
  if "$JCMD" "$PID" GC.class_histogram > "$ROOT/histogram-$stamp-${pct}pct.txt" 2>/dev/null; then
    : > "$STATE/histogram"
  fi
fi

# --- >=88%: dump the flight recording (bounded, includes path-to-GC-roots) -----
if [ "$pct" -ge "$JFR_PCT" ] && [ ! -e "$STATE/jfr" ]; then
  if ! "$JCMD" "$PID" JFR.check 2>/dev/null | grep -q "name=$JFR_NAME"; then
    "$JCMD" "$PID" JFR.start name="$JFR_NAME" settings=default disk=true \
      maxsize=256m maxage=4h path-to-gc-roots=true >/dev/null 2>&1
  fi
  if "$JCMD" "$PID" JFR.dump name="$JFR_NAME" filename="$ROOT/jfr-$stamp.jfr" >/dev/null 2>&1; then
    : > "$STATE/jfr"
    log "JFR dumped to $ROOT/jfr-$stamp.jfr"
  fi
fi

# --- optional: capture while alive instead of via the OOM dump ------------------
if [ "$DUMP_PCT" -gt 0 ] && [ "$pct" -ge "$DUMP_PCT" ] && [ ! -e "$STATE/dump" ]; then
  if [ "$free_mb" -lt "$MIN_FREE_MB" ]; then
    log "refusing heap dump: ${free_mb}MiB free < ${MIN_FREE_MB}MiB"
  else
    out="$ROOT/heap-$stamp.hprof"
    if "$JCMD" "$PID" GC.heap_dump -gz=1 "$out.gz" >/dev/null 2>&1; then
      log "gzip heap dump written to $out.gz"
      : > "$STATE/dump"
    elif "$JCMD" "$PID" GC.heap_dump "$out" >/dev/null 2>&1; then
      log "heap dump written to $out (compressing in background)"
      (nice -n 19 gzip -1 -- "$out") >/dev/null 2>&1 &
      : > "$STATE/dump"
    else
      log "heap dump failed (not armed or command rejected)"
    fi
  fi
fi

# --- retention by count -------------------------------------------------------
ls -1t "$ROOT"/histogram-* 2>/dev/null | tail -n +$((KEEP_SMALL + 1)) | xargs -r rm -f 2>/dev/null
ls -1t "$ROOT"/threads-* 2>/dev/null | tail -n +$((KEEP_SMALL + 1)) | xargs -r rm -f 2>/dev/null
ls -1t "$ROOT"/conns-* 2>/dev/null | tail -n +$((KEEP_SMALL + 1)) | xargs -r rm -f 2>/dev/null
ls -1t "$ROOT"/jfr-*.jfr 2>/dev/null | tail -n +$((KEEP_JFR + 1)) | xargs -r rm -f 2>/dev/null
ls -1t "$ROOT"/heap-*.hprof* 2>/dev/null | tail -n +$((KEEP_DUMPS + 1)) | xargs -r rm -f 2>/dev/null
find "$ROOT/state" -mindepth 1 -maxdepth 1 -type d -mtime +2 -exec rm -rf {} + 2>/dev/null

exit 0
