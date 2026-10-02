# Security Lab Scripts

Small, read-only security tools built in my Hyper-V home lab.

## security-summary.sh
Summarizes security events on a Linux server from the system journal:
- Firewall blocks (ufw) and the top source IPs
- Successful SSH logins (method, user, source)
- Invalid-username attempts

**Safety:** read-only. Runs as a normal user in the `adm` group (no sudo).
Writes one report to `~/evidence/summary-YYYY-MM-DD.txt`.

**Usage:**
    ./security-summary.sh                # since midnight (server time)
    ./security-summary.sh "1 hour ago"   # custom window
