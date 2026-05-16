# server-audit

`server-audit` is a local Linux security audit script for quickly checking common server hardening basics. It is read-only: it reports findings and suggested remediation commands, but it does not change system configuration.

## What It Checks

- System overview: OS, kernel, uptime, CPU, memory, disk usage, package count, reboot status.
- SSH hardening: root login, password authentication, public key auth, protocol, port, keepalive, and max auth attempts.
- Firewall posture: UFW, firewalld, iptables, IP forwarding, and wildcard-bound TCP listeners.
- Sensitive file permissions: `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, SSH config, and root SSH files.
- Sudo configuration: syntax validation, sudo logging, and `NOPASSWD` entries.
- Package hygiene: available security updates where implemented, last update age, and automatic updates.
- Service exposure: SSH service status and commonly unnecessary services.
- Logging and brute-force signals: system logging status and failed SSH login attempts.

## Requirements

- Bash
- Linux
- Common base tools such as `awk`, `grep`, `stat`, `sort`, `wc`, `df`, `sysctl`
- Optional tools for deeper checks: `sudo`, `ss`, `netstat`, `systemctl`, `journalctl`, `visudo`, `ufw`, `firewall-cmd`, `iptables`

For complete results, run as `root` or with passwordless `sudo`. Without elevated privileges, checks that require protected files or privileged commands are marked `SKIP` instead of producing unreliable failures.

## Usage

Run directly from the project directory with root privileges:

```bash
sudo ./server-audit
```

## Notes

- This is not a compliance scanner.
- Some findings are intentionally conservative and may need context. For example, wildcard-bound listeners are not automatically wrong, but they deserve review.
- Package security update checks are currently implemented for `apt`; other package managers may be reported as not implemented.
- `systemctl`-dependent checks are skipped if `systemctl` exists but cannot query the running system manager.
- The script avoids prompting for sudo credentials. If passwordless sudo is unavailable, privileged checks are skipped unless you run the script with `sudo`.
