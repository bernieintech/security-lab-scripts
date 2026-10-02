#!/usr/bin/env bash
# security-summary.sh
# Purpose : Summarize security events on this server and flag warnings.
# Safety  : READ-ONLY. Reads the system journal and one config file; writes one report file.
# Usage   : ~/scripts/security-summary.sh                (events since midnight)
#           ~/scripts/security-summary.sh "1 hour ago"   (custom time window)
# Config  : ~/.config/security-summary/known-sources     (one trusted admin IP per line)

set -euo pipefail

since="${1:-today}"
report_dir="$HOME/evidence"
report_file="$report_dir/summary-$(date +%F).txt"
known_file="${XDG_CONFIG_HOME:-$HOME/.config}/security-summary/known-sources"

# Warning thresholds (per source address, within the time window)
scan_ports=5        # distinct blocked ports = possible port scan
burst_invalid=5     # invalid-user attempts = possible brute force

if ! id -nG | grep -qwE 'adm|systemd-journal'; then
  echo "ERROR: $(whoami) is not in the 'adm' group, so the system logs can't be read." >&2
  exit 1
fi

mkdir -p "$report_dir"
logs="$(journalctl --since "$since" --no-pager | grep -vE '^[^ ]+ [^ ]+ [^ ]+ [^ ]+ security-summary\.sh\[' || true)"

count() { grep -c -- "$1" <<< "$logs" || true; }

# ---- Warnings ----
warnings=()

have_known=0
known=""
if [[ -r "$known_file" ]]; then
  have_known=1
  known="$(grep -vE '^[[:space:]]*(#|$)' "$known_file" | awk '{print $1}' || true)"
else
  warnings+=("known-sources file not found ($known_file): login sources were NOT checked")
fi

# Rule 1 + 2: password logins, and logins from addresses not on the known list
while read -r n method user ip; do
  [[ -z "${ip:-}" ]] && continue
  if [[ "$method" == "password" ]]; then
    warnings+=("password login: $n x $user from $ip (password logins should be disabled)")
  fi
  if (( have_known )) && ! grep -qxF -- "$ip" <<< "$known"; then
    warnings+=("login from unknown source: $n x $user from $ip ($method)")
  fi
done < <(grep 'Accepted ' <<< "$logs" \
          | sed -nE 's/.* Accepted ([a-z-]+) for (.+) from ([0-9a-fA-F:.]+) port [0-9]+.*/\1 \2 \3/p' \
          | sort | uniq -c)

# Rule 3: bursts of invalid usernames from one source (IP is taken from the END of the line)
while read -r n ip; do
  [[ -z "${ip:-}" ]] && continue
  if (( n >= burst_invalid )); then
    warnings+=("possible brute force: $n invalid-user attempts from $ip")
  fi
done < <(grep 'Invalid user ' <<< "$logs" \
          | sed -nE 's/.* from ([0-9a-fA-F:.]+) port [0-9]+.*$/\1/p' \
          | sort | uniq -c)

# Rule 4: one source blocked on many different ports
while read -r src nports; do
  [[ -z "${nports:-}" ]] && continue
  if (( nports >= scan_ports )); then
    warnings+=("possible port scan: $src was blocked on $nports different ports")
  fi
done < <(grep 'UFW BLOCK' <<< "$logs" \
          | sed -nE 's/.* SRC=([^ ]+) .* DPT=([0-9]+) .*/\1 \2/p' \
          | sort -u | awk '{c[$1]++} END {for (s in c) print s, c[s]}')

{
  echo "Security summary for $(hostname)"
  echo "Period : since $since"
  echo "Created: $(date '+%F %T %Z')"
  echo
  echo "WARNINGS              : ${#warnings[@]}"
  if (( ${#warnings[@]} )); then
    printf '  WARN %s\n' "${warnings[@]}"
  else
    echo "  none"
  fi
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
