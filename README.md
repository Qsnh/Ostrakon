# Ostrakon

Ostrakon protects a Linux server from SSH and web brute-force attacks and scans without any rules to write: it watches your logs, asks TypeSafe's Jev decision model whether a source address is attacking, and bans it in nftables until the ban expires.

Unlike fail2ban there are no jails, filters, regexes or thresholds to configure. The only thing you provide is a Jev API key.

## How it works

- It finds the logs itself: sshd (`/var/log/auth.log`, `/var/log/secure`, or the `ssh`/`sshd` journald units) and nginx (`/var/log/nginx/access.log`). It starts at the end of each file and follows log rotation.
- When one address becomes active enough (for example a few failed SSH logins within ten minutes), Ostrakon sends its recent events to Jev. Jev decides whether it is an attack and how long to ban it: 10 minutes, 1 hour, 24 hours or 7 days. There are no permanent bans.
- Bans are elements with a timeout in sets of Ostrakon's own nftables table, `inet ostrakon`. The table drops traffic at prerouting, before Docker's port forwarding, so it also protects published container ports. nftables lifts each ban on time, even if Ostrakon is stopped. Ostrakon leaves your other firewall rules alone.
- Ostrakon remembers active bans in `/var/lib/ostrakon/state.json` and puts them back after a reboot.
- Some addresses are never banned and never sent to Jev: loopback, private and link-local ranges, the server's own addresses, addresses with a live login session, addresses that logged in over SSH successfully in the last 24 hours, Cloudflare's ranges, and anything you add with `ostrakon allow`.

## Install

You need a Linux server with systemd and nftables (the `nft` command), root access, and a TypeSafe Jev API key.

1. Download the `ostrakon` binary for your architecture onto the server, or build it (see [Building](#building)).
2. Run setup as root:

   ```sh
   chmod +x ostrakon
   sudo ./ostrakon setup
   ```

Setup checks that `nft` is available, asks for your Jev API key (or takes it from the `TYPESAFE_API_KEY` environment variable), checks the key with one Jev call and saves it to `/etc/ostrakon/key` (mode 0600). It then lists the logs it found, installs itself as `/usr/local/bin/ostrakon`, and installs and starts the `ostrakon` systemd service. There is nothing else to do.

To use a different key later, run `sudo ostrakon setup` again. The service reads the key before every request, so the new key takes effect without a restart.

## Commands

The service's control socket is only open to root, so run these with `sudo`.

| Command | What it does |
| --- | --- |
| `ostrakon setup` | Save your Jev API key, then install and start the service. |
| `ostrakon status` | Show whether protection is running or paused (and why), the watched logs, the number of bans, and the last decision. |
| `ostrakon bans` | List the active bans with their category and remaining time. |
| `ostrakon unban <ip>` | Lift the ban on an address. |
| `ostrakon allow <ip\|cidr>` | Never ban this address or range. |
| `ostrakon disallow <ip\|cidr>` | Remove an entry added with `allow`. |
| `ostrakon run [--dry-run]` | Run the daemon in the foreground (the service runs this). With `--dry-run` it logs the bans it would make without applying them. |

Every decision is logged with its probability and token usage: `journalctl -u ostrakon`.

## Jev costs

Every Jev call is billed to your TypeSafe account at TypeSafe's prices. Ostrakon does not call Jev for every log line: it calls once an address has been active enough, sends at most 50 of that address's events, and remembers a "benign" verdict for an hour unless the address's activity doubles. It makes at most 4 calls at a time. There is no spending cap.

## When Jev is unavailable

Ostrakon has no fallback rules. It pauses protection at once if Jev rejects the key (or there is none), and after about a minute of failed attempts if Jev cannot be reached (network errors, 429, 5xx). While paused:

- It makes no new bans. Existing bans stay and expire on schedule.
- `ostrakon status` shows `paused` with the reason and the time it started, and the pause is logged as an error.
- It keeps reading the logs and checks Jev again after 1 minute, then 2, 4 and every 5 minutes. As soon as Jev answers, protection resumes by itself.

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

Tests: `go test ./...` runs everywhere. `bash test/e2e/e2e.sh` runs the end-to-end suite against real nftables in a privileged Docker container; it needs Docker and takes a few minutes.
