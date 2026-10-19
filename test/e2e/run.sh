#!/usr/bin/env bash
# Runs inside the privileged e2e container (see Dockerfile; e2e.sh starts it).
# Drives a real ostrakon daemon against real nftables and a fake Jev, and
# prints E2E PASS as its last line on success. On any failure it prints what
# failed, the daemon's and fake Jev's logs and `nft list ruleset`, and exits 1.
set -euo pipefail

readonly AUTH_LOG=/var/log/auth.log
readonly FAKEJEV_LOG=/tmp/fakejev.log
readonly JEV_URL=http://127.0.0.1:8099

daemon_pid=
daemon_log=
runs=0
step="starting"

diagnostics() {
	echo "==== E2E FAIL in step $step"
	echo "---- ostrakon status"
	ostrakon status 2>&1 || true
	local f
	for f in /tmp/ostrakon-*.log; do
		echo "---- daemon log $f"
		cat "$f" 2>&1 || true
	done
	echo "---- fake Jev log $FAKEJEV_LOG"
	cat "$FAKEJEV_LOG" 2>&1 || true
	echo "---- nft list ruleset"
	nft list ruleset 2>&1 || true
}

on_exit() {
	local rc=$?
	if ((rc != 0)); then
		diagnostics
	fi
	exit "$rc"
}
trap on_exit EXIT

fail() {
	echo "FAIL: $*"
	exit 1
}

# wait_for DESC SECONDS CMD...: retries CMD until it succeeds; fails the test
# if it still has not after SECONDS.
wait_for() {
	local desc=$1 secs=$2
	shift 2
	local start=$SECONDS
	until "$@"; do
		if ((SECONDS - start >= secs)); then
			fail "timed out after ${secs}s waiting for: $desc"
		fi
		sleep 0.2
	done
	echo "ok: $desc ($((SECONDS - start))s)"
}

# status_is WORD: `ostrakon status` says "status:  WORD...".
status_is() {
	local out
	out=$(ostrakon status 2>&1) || return 1
	grep -q "^status:  $1" <<<"$out"
}

# banned IP / not_banned IP: whether IP is in the banned_v4 set. Both fail if
# the set cannot be listed, so a missing table never passes for "not banned".
banned() {
	local out
	out=$(nft list set inet ostrakon banned_v4 2>&1) || return 1
	grep -qwF "$1" <<<"$out"
}
not_banned() {
	local out
	out=$(nft list set inet ostrakon banned_v4 2>&1) || return 1
	! grep -qwF "$1" <<<"$out"
}

# failed_passwords IP COUNT: appends COUNT sshd password failures from IP.
failed_passwords() {
	local ip=$1 n
	for ((n = 1; n <= $2; n++)); do
		echo "Oct 18 20:00:0$n web sshd[1]: Failed password for root from $ip port 5000$n ssh2" >>"$AUTH_LOG"
	done
}

fakejev_up() { fakejev mode attack 2>/dev/null; }

# start_daemon: starts `ostrakon run` in the background, each run logging to
# its own file.
start_daemon() {
	runs=$((runs + 1))
	daemon_log=/tmp/ostrakon-$runs.log
	TYPESAFE_API_KEY=test OSTRAKON_JEV_URL=$JEV_URL ostrakon run >"$daemon_log" 2>&1 &
	daemon_pid=$!
}

daemon_gone() { ! kill -0 "$daemon_pid" 2>/dev/null; }
daemon_started() { grep -q "ostrakon started" "$daemon_log"; }

step="1: start the fake Jev and the daemon"
echo "== step $step"
fakejev >"$FAKEJEV_LOG" 2>&1 &
wait_for "fake Jev accepts requests" 10 fakejev_up
touch "$AUTH_LOG"
start_daemon
wait_for "ostrakon status: running" 10 status_is running

step="2: a password brute force from 203.0.113.7 is banned"
echo "== step $step"
failed_passwords 203.0.113.7 3
wait_for "203.0.113.7 in banned_v4" 10 banned 203.0.113.7
bans=$(ostrakon bans) || fail "ostrakon bans failed: $bans"
grep -qwF 203.0.113.7 <<<"$bans" || fail "ostrakon bans does not list 203.0.113.7:"$'\n'"$bans"
echo "ok: ostrakon bans lists 203.0.113.7"

step="3: an address that logged in successfully is not banned"
echo "== step $step"
echo "Oct 18 20:00:10 web sshd[1]: Accepted password for admin from 198.51.100.4 port 1 ssh2" >>"$AUTH_LOG"
failed_passwords 198.51.100.4 5
sleep 5 # a negative check: give the daemon time to (wrongly) ban
not_banned 198.51.100.4 || fail "198.51.100.4 is banned although it had just logged in successfully"
echo "ok: 198.51.100.4 not banned 5s after 5 failures"

step="4: a rejected API key pauses protection at once"
echo "== step $step"
fakejev mode unauthorized
failed_passwords 203.0.113.8 3
wait_for "ostrakon status: paused" 10 status_is paused
not_banned 203.0.113.8 || fail "203.0.113.8 was banned while protection was paused"
echo "ok: 203.0.113.8 not banned while paused"

step="5: protection resumes by itself once Jev answers again"
echo "== step $step"
fakejev mode attack
wait_for "ostrakon status: running again (the first probe is after 1m)" 150 status_is running
failed_passwords 203.0.113.9 3
wait_for "203.0.113.9 in banned_v4" 10 banned 203.0.113.9

step="6: ostrakon unban lifts a ban"
echo "== step $step"
out=$(ostrakon unban 203.0.113.7) || fail "ostrakon unban 203.0.113.7 failed: $out"
[[ $out == ok ]] || fail "ostrakon unban 203.0.113.7 printed: $out"
not_banned 203.0.113.7 || fail "203.0.113.7 is still in banned_v4 after ostrakon unban"
echo "ok: 203.0.113.7 removed from banned_v4"

step="7: a restart that lost the nftables table restores the bans"
echo "== step $step"
kill "$daemon_pid"
wait_for "the daemon exits on SIGTERM" 10 daemon_gone
rc=0
wait "$daemon_pid" || rc=$?
((rc == 0)) || fail "the daemon exited with status $rc on SIGTERM"
nft delete table inet ostrakon
start_daemon
wait_for "203.0.113.9 restored into banned_v4" 10 banned 203.0.113.9
# "ostrakon started" is logged after every stored ban has been restored.
wait_for "the restarted daemon finished starting" 10 daemon_started
not_banned 203.0.113.7 || fail "203.0.113.7 was restored after a restart although it had been unbanned"
echo "ok: 203.0.113.7 stays unbanned after the restart"

echo "E2E PASS"
