# Security Lab Scripts

Read-only Linux security reporting, built and tested in my Hyper-V home lab.

`security-summary.sh` turns a server's raw system logs into a short daily report: who logged in, how, from where, what the firewall blocked, and how often admin rights were used. It runs on a schedule inside a systemd sandbox that makes it **read-only by enforcement**, not just by design.

## Why this exists

Small businesses rarely have anyone reading their server logs. Problems like password logins that should be disabled, unexpected source addresses, or repeated failed logins go unnoticed until something breaks. This tool is the first step of a larger goal: automated, read-only security reporting that a human reviews and approves.

## What the report shows

| Section | Source in the journal | Why it matters |
|---|---|---|
| Firewall blocks + top sources | `[UFW BLOCK]` kernel messages | Spots scans and unwanted connection attempts |
| Successful logins (method / user / source) | `Accepted ...` from sshd | Confirms only expected users, methods, and addresses |
| Invalid usernames tried | `Invalid user ...` from sshd | Early sign of brute-force or username guessing |
| Sudo commands run | `COMMAND=` from sudo | Every use of admin rights should be explainable |

### Sample report

IP addresses below are replaced with documentation ranges (RFC 5737).

```text
Security summary for lab-server
Period : since 24 hours ago
Created: 2026-10-02 13:48:46 UTC

Firewall blocks       : 7
Successful logins     : 9
Invalid-user attempts : 1
Sudo commands run     : 35

Top blocked sources (count  source):
      7 SRC=192.0.2.20

Successful logins (count  method / user / from):
      9 Accepted publickey for labadmin from 192.0.2.1

Invalid usernames tried (count  user / from):
      1 Invalid user baduser from 192.0.2.1
```

## Security design: three layers of read-only

| Layer | How | What it prevents |
|---|---|---|
| 1. By design | The script only reads the journal and writes one report file | No commands that change the system |
| 2. Least privilege | Runs as a normal user in the `adm` group, never root | Linux blocks changes to system files |
| 3. Sandbox | systemd `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`; the only writable path is the report folder | Even a modified script cannot write elsewhere or gain extra privileges (for example through `sudo`) |

The sandbox was verified by running a write attempt under the same settings. It failed with `Read-only file system`, as intended.

## How it was tested

| Test | Result |
|---|---|
| Normal data | Counts matched a manual review of the same logs |
| Empty window | Report shows `0` and `none` cleanly |
| Hostile input | Checked against sample log lines: a username crafted to look like the script's own log tag is still reported, not hidden |
| Failure (by design) | Exits with an error if the user cannot read system logs, instead of reporting false zeros. Not yet tested on a live system |
| Feedback loop | Found that scheduled runs re-counted their own journal output; fixed with a position-anchored filter (see commit history) |

## Usage

Run manually as a user in the `adm` group (no `sudo`):

```bash
./security-summary.sh                # since midnight, server time
./security-summary.sh "1 hour ago"   # custom time window
```

Each run writes `~/evidence/summary-YYYY-MM-DD.txt` and prints the same report on screen.

## Scheduling with systemd

The `systemd/` folder contains a sandboxed service and a daily timer (11:00 UTC, catches up after downtime with `Persistent=true`). Edit `User=` and the paths to match your account, then:

```bash
sudo cp systemd/security-summary.service systemd/security-summary.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now security-summary.timer
systemctl list-timers security-summary.timer
```

## Requirements

- Linux with systemd and journald (built and tested on Ubuntu Server 26.04 LTS)
- `ufw` with logging on, for firewall data
- The running user is a member of the `adm` group

## Limitations

- Matches log text patterns, so a change in log format could undercount. Verify against raw logs after OS upgrades.
- Reports facts only; it does not judge whether activity is good or bad yet.

## Roadmap

- Flag warnings automatically: password logins, unknown source addresses, unusual sudo use
- Cross-check key counts two independent ways
- AI-written plain-English summary, read-only and human-approved

## Lab context

Built in a Hyper-V lab on an isolated internal network: an Ubuntu Server host with key-only SSH and a default-deny firewall, and a Kali Linux VM used for authorized test scans against it.

## Skills applied

Concepts from the CompTIA and Cisco exam domains I have studied, and where each one shows up in this project.

| Area | Concepts | Where in this project |
|---|---|---|
| Security+ | Least privilege, defense in depth, hardening, logging and monitoring, change management | `adm` group instead of root; key-only SSH with no root or password login; default-deny firewall; daily log report; every change reviewed through a pull request |
| Network+ | Private addressing (RFC 1918), /24 subnetting, NAT, ports and protocols, documentation ranges (RFC 5737) | Isolated `10.x.x.0/24` lab network behind host NAT; SSH on 22/TCP; sample report uses `192.0.2.x` addresses |
| Linux+ | systemd services and timers, permissions and ownership, groups, journald, SSH server configuration, Bash, Git | Sandboxed oneshot service and daily timer; `chmod 700` script; log reading with `journalctl`; `sshd_config.d` drop-in |
| Server+ | Baselines, time synchronization, change control, snapshots for rollback | Before/after scan evidence; servers on UTC with NTP sync; Hyper-V checkpoints before every major change |
| CCNA | ACL logic (first match, implicit deny), network segmentation | Single allow rule for SSH from the admin host, everything else denied; lab traffic kept on an internal virtual switch |
| Pentest+ (studying) | Authorized scope, host discovery and port scanning, verification testing | Nmap scans only against my own lab hosts; open vs. filtered results used to prove the firewall works |
| Scripting and automation | Defensive scripting, scheduling, version control | `set -euo pipefail` and explicit error checks; systemd timer; branch, pull request, and protected `main` |
