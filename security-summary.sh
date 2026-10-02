#!/usr/bin/env bash
# security-summary.sh
# Purpose : Summarize security events on this server (firewall blocks, logins, bad usernames).
# Safety  : READ-ONLY. Reads the system journal and writes one report file. Changes nothing else.
# Usage   : ~/scripts/security-summary.sh                (events since midnight)
#           ~/scripts/security-summary.sh "1 hour ago"   (custom time window)

set -euo pipefail

since="${1:-today}"
report_dir="$HOME/evidence"
report_file="$report_dir/summary-$(date +%F).txt"

if ! id -nG | grep -qwE 'adm|systemd-journal'; then
  echo "ERROR: $(whoami) is not in the 'adm' group, so the system logs can't be read." >&2
  exit 1
fi

mkdir -p "$report_dir"
logs="$(journalctl --since "$since" --no-pager)"

count() { grep -c -- "$1" <<< "$logs" || true; }

{
  echo "Security summary for $(hostname)"
  echo "Period : since $since"
  echo "Created: $(date '+%F %T')"
  echo
  echo "Firewall blocks       : $(count 'UFW BLOCK')"
  echo "Successful logins     : $(count 'Accepted ')"
  echo "Invalid-user attempts : $(count 'Invalid user')"
  echo "Sudo commands run     : $(count 'COMMAND=')"
  echo
  echo "Top blocked sources (count  source):"
  { grep 'UFW BLOCK' <<< "$logs" | grep -o 'SRC=[0-9.]*' | sort | uniq -c | sort -rn | head -n 5; } || echo "  none"
  echo
  echo "Successful logins (count  method / user / from):"
  { grep -o 'Accepted [a-z]* for [^ ]* from [0-9.]*' <<< "$logs" | sort | uniq -c; } || echo "  none"
  echo
  echo "Invalid usernames tried (count  user / from):"
  { grep -o 'Invalid user [^ ]* from [0-9.]*' <<< "$logs" | sort | uniq -c; } || echo "  none"
} | tee "$report_file"

echo
echo "Saved to: $report_file"
