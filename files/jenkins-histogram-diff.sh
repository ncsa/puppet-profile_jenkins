#!/bin/bash
# Diff two `jcmd <pid> GC.class_histogram` snapshots and show what grew.
#
# This is the cheapest possible answer to "what is filling the heap": two
# histograms taken hours apart are ~500 KiB and the delta names the classes
# directly, with no 28 GiB dump involved.
#
# usage: jenkins-histogram-diff.sh <baseline.txt> <later.txt> [min_delta_instances]
#        jenkins-histogram-diff.sh /u/jenkins-forensics/histogram-*-base.txt \
#                                  /u/jenkins-forensics/histogram-*-80pct.txt
set -u
export LC_ALL=C

if [ $# -lt 2 ]; then
  printf 'usage: %s <base.txt> <later.txt> [min_delta_instances]\n' "$0" >&2
  exit 2
fi

base=$1
later=$2
min=${3:-100000}

extract() {
  awk 'NF >= 4 && $1 ~ /^[0-9]+:$/ { print $4 "\t" $2 }' "$1" | sort -t "$(printf '\t')" -k1,1
}

join -t "$(printf '\t')" -a1 -a2 -e0 -o 0,1.2,2.2 \
  <(extract "$base") <(extract "$later") 2>/dev/null \
  | awk -F'\t' -v m="$min" '
      { d = $3 - $2
        if (d >= m) printf "%14d  +%7.1f%%  %s\n", d, ($2 > 0 ? 100 * d / $2 : 0), $1
      }' \
  | sort -rn -k1,1 | head -n 25
