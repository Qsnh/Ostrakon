# Ostrakon

Ostrakon protects a Linux server from SSH and web brute-force attacks and scans without any rules to write: it watches your logs, asks TypeSafe's Jev decision model whether a source address is attacking, and bans it in nftables until the ban expires.

Unlike fail2ban there are no jails, filters, regexes or thresholds to configure. The only thing you provide is a Jev API key.

## How it works

- It finds the logs itself: sshd (`/var/log/auth.log`, `/var/log/secure`, or the `ssh`/`sshd` journald units) and nginx (`/var/log/nginx/access.log`). It starts at the end of each file and follows log rotation.
- When one address becomes active enough (for example a few failed SSH logins within ten minutes), Ostrakon sends its recent events to Jev. Jev decides whether it is an attack and how long to ban it: 10 minutes, 1 hour, 24 hours or 7 days. There are no permanent bans.
- It looks for logs only when it starts. If you install nginx (or start using another of these logs) later, run `sudo systemctl restart ostrakon`.
- Bans are elements with a timeout in sets of Ostrakon's own nftables table, `inet ostrakon`. The table drops traffic at prerouting, before Docker's port forwarding, so it also protects published container ports. nftables lifts each ban on time, even if Ostrakon is stopped. Ostrakon leaves your other firewall rules alone.
- Ostrakon remembers active bans in `/var/lib/ostrakon/state.json` and puts them back after a reboot, never for longer than the ban was given.
- If something removes its table while it runs (`nft flush ruleset`, reloading `nftables.service`), Ostrakon notices within a minute, or at its next ban, rebuilds the table and puts the active bans back.
- Some addresses are never banned and never sent to Jev: loopback, private and link-local ranges, the server's own addresses, the addresses of current terminal login sessions (those in utmp, as `who` shows them), addresses that logged in over SSH successfully in the last 24 hours, Cloudflare's ranges, and anything you add with `ostrakon allow`. SSH connections without a terminal (`scp`, `sftp`, `ssh host command`) are not in utmp, but their successful login exempts the address for 24 hours all the same.

## Install

You need a Linux server with systemd and nftables (the `nft` command), root access, and a TypeSafe Jev API key. There is no binary release yet, so you build Ostrakon from source, on any machine with Go 1.25.

1. Build the binary from a checkout of this repository (see [Building](#building) for other architectures, and for `go install`):

   ```sh
   git clone https://github.com/Qsnh/Ostrakon.git
   cd Ostrakon
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ostrakon ./cmd/ostrakon
   ```

2. Copy `ostrakon` to the server and run setup there as root:

   ```sh
   chmod +x ostrakon
   sudo ./ostrakon setup
   ```

Setup checks that `nft` is available, asks for your Jev API key (or takes it from the `TYPESAFE_API_KEY` environment variable), checks the key with one Jev call and saves it to `/etc/ostrakon/key` (mode 0600). It then lists the logs it found, installs itself as `/usr/local/bin/ostrakon`, and installs and starts the `ostrakon` systemd service. There is nothing else to do.

To use a different key later, run `sudo ostrakon setup` again. The service reads the key before every request, so the new key takes effect without a restart.

To upgrade, build the new binary, run `sudo ./ostrakon setup` with it (it replaces `/usr/local/bin/ostrakon`), then `sudo systemctl restart ostrakon`: setup does not restart a service that is already running.

## Commands

The service's control socket is only open to root, so run these with `sudo`.

| Command | What it does |
| --- | --- |
| `ostrakon setup` | Save your Jev API key, then install and start the service. |
| `ostrakon status` | Show whether protection is running, paused or degraded (and why), the watched logs, the number of bans, the last decision and its outcome, the last Jev request, and any firewall error. |
| `ostrakon bans` | List the active bans with their category and remaining time. |
| `ostrakon unban <ip>` | Lift the ban on an address. |
| `ostrakon allow <ip\|cidr>` | Never ban this address or range, and lift its current bans. |
| `ostrakon disallow <ip\|cidr>` | Remove an entry added with `allow`. |
| `ostrakon run [--dry-run]` | Run the daemon in the foreground (the service runs this). With `--dry-run` it logs the bans it would make without applying them. |

Every decision is logged with its probability and token usage: `journalctl -u ostrakon`. Lines carry journald priorities, so `journalctl -u ostrakon -p warning` shows only the problems.

`ostrakon status` looks like this:

```
status:  running
mode:    normal
sources: sshd(/var/log/auth.log), nginx-access(/var/log/nginx/access.log)
bans:    3
last:    2026-10-18T20:00:05Z 203.0.113.7 ssh_bruteforce p=0.93 ban 1h
jev:     2026-10-18T20:00:05Z ok
```

- `status:` is `running`, `paused (reason: ..., since ...)` or `degraded (...)`, which means the last 5 or more decisions in a row failed without pausing protection. Both are explained under [When Jev is unavailable](#when-jev-is-unavailable).
- `last:` is the latest decision and what came of it: `ban 1h`, `ban 1h failed: <error>`, `no ban`, `would ban 1h` (dry run) or `skipped (allowlisted)`.
- `jev:` is the time and outcome of the latest Jev decision request, `ok` or `error: ...`.
- A `firewall:` line appears only while there is a firewall problem (a ban that failed, a table that could not be checked or rebuilt) and shows the latest error.

## Jev costs

Every Jev call is billed to your TypeSafe account at TypeSafe's prices. Ostrakon does not call Jev for every log line: it calls once an address has been active enough, sends at most 50 of that address's events, and remembers a "benign" verdict for an hour unless the address's activity doubles. It makes at most 4 calls at a time. There is no spending cap.

## When Jev is unavailable

Ostrakon has no fallback rules. It pauses protection at once if Jev rejects the key (or there is none), and after about a minute of failed attempts if Jev cannot be reached (network errors, 429, 5xx). While paused:

- It makes no new bans. Existing bans stay and expire on schedule.
- `ostrakon status` shows `paused` with the reason and the time it started, and the pause is logged as an error (`journalctl -u ostrakon -p err`).
- It keeps reading the logs and checks Jev again after 1 minute, then 2, 4 and every 5 minutes. As soon as Jev answers, protection resumes by itself.

Requests Jev rejects as malformed (400, 413, 415, 422) and answers Ostrakon cannot use do not pause protection, since one odd log line must not switch it off. That decision is dropped and the address is not asked about again for 5 minutes. After 5 failed decisions in a row the error is logged and `ostrakon status` shows `degraded` with it, until a decision succeeds.

## Known limitations

- Linux with nftables only. There is no iptables backend and no other platform.
- Sites behind a CDN or public reverse proxy (such as Cloudflare) are not protected: nginx logs the proxy's address, not the attacker's, and banning it would not stop the attacker anyway. Cloudflare's ranges are never banned so that your site stays up. SSH protection is not affected.
- Logs of applications running in Docker containers are not read; only log files on the host and journald.
- Only sshd and the nginx access log are understood.
- Log fields are sent to TypeSafe. For an address under judgment Ostrakon sends the address, how often and when it was last banned, and up to 50 of its recent events as structured fields: time, source, event type, user name, HTTP method, path, status and user agent, each cut to 128 characters. Whole log lines are never sent.
- No notifications (email, webhooks) yet.

## Building

Ostrakon is a single static binary. It needs Go 1.25.

```sh
GOOS=linux CGO_ENABLED=0 go build -o ostrakon ./cmd/ostrakon
```

Set `GOARCH` to build for another architecture (for example `GOARCH=arm64`).

Without a checkout, `go install` fetches and builds the latest version:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go install github.com/Qsnh/Ostrakon/cmd/ostrakon@latest
```

The binary is written to `$(go env GOPATH)/bin/linux_amd64/ostrakon` (`GOBIN` must be unset: Go does not install cross-compiled binaries into it). On a Linux machine of the target architecture you can leave out `GOOS` and `GOARCH`; the binary then goes to `$(go env GOPATH)/bin/ostrakon` (or to `GOBIN`).

Tests: `go test ./...` runs everywhere. `bash test/e2e/e2e.sh` runs the end-to-end suite against real nftables in a privileged Docker container; it needs Docker and takes a few minutes.
