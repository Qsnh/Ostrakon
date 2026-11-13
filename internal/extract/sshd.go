// Package extract turns raw log lines into normalized events.
//
// Log lines contain attacker-controlled text (user names, request paths,
// user agents). Every pattern here is anchored at both ends and the
// attacker-controlled field is matched greedily, so the source IP is always
// taken from the sshd-generated tail of the message and can never be forged
// by text inside the user name. Messages whose tail is controlled by the
// client are deliberately not supported.
package extract

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/Qsnh/Ostrakon/internal/event"
)

// sshdSyslogPrefix matches a syslog (RFC3164 or RFC3339 timestamp) prefix
// whose program is sshd or sshd-session, anchored at the start of the line.
// The program name is checked here, before any message text, so an sshd-looking
// string embedded in another program's line is rejected.
var sshdSyslogPrefix = regexp.MustCompile(
	`^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ (?:sshd|sshd-session)\[\d+\]: (.*)$`)

type sshdRule struct {
	re   *regexp.Regexp
	kind event.Kind
	user int // submatch index of the user group, or -1
	ip   int // submatch index of the ip group
}

// sshdRules are tried in order; each is anchored with ^...$. {user} is greedy
// so that the last "from <ip> port <n>" in the message supplies the address:
// the user name is attacker-controlled and comes before the sshd-generated
// tail. The Accepted rule is the exception and uses the lazy {lazyuser}: its
// user is a real local account, while the free-form tail after "ssh2: "
// (e.g. a certificate key ID) is the part that can carry forged text, so the
// first "from <ip> port <n> ssh2" must win.
var sshdRules = []sshdRule{
	newSSHDRule(`^Failed \S+ for (?:invalid user )?{user} from {ip} port \d+(?: ssh2)?$`, event.KindAuthFail),
	newSSHDRule(`^maximum authentication attempts exceeded for (?:invalid user )?{user} from {ip} port \d+ ssh2 \[preauth\]$`, event.KindAuthFail),
	newSSHDRule(`^Invalid user {user} from {ip} port \d+$`, event.KindInvalidUser),
	newSSHDRule(`^(?:Disconnected from|Connection closed by) invalid user {user} {ip} port \d+ \[preauth\]$`, event.KindInvalidUser),
	newSSHDRule(`^(?:Disconnected from|Connection closed by) authenticating user {user} {ip} port \d+ \[preauth\]$`, event.KindPreauthClose),
	newSSHDRule(`^Connection closed by {ip} port \d+ \[preauth\]$`, event.KindPreauthClose),
	newSSHDRule(`^Accepted \S+ for {lazyuser} from {ip} port \d+ ssh2(?:: .*)?$`, event.KindAuthSuccess),
}

var sshdPlaceholders = strings.NewReplacer(
	"{user}", `(?P<user>.*)`,
	"{lazyuser}", `(?P<user>.*?)`,
	"{ip}", `(?P<ip>[0-9A-Fa-f:.]+)`,
)

func newSSHDRule(pattern string, kind event.Kind) sshdRule {
	re := regexp.MustCompile(sshdPlaceholders.Replace(pattern))
	return sshdRule{
		re:   re,
		kind: kind,
		user: re.SubexpIndex("user"), // -1 when the pattern has no user group
		ip:   re.SubexpIndex("ip"),
	}
}

// ParseSSHDSyslog parses a line from an sshd log file: it strips the syslog
// prefix (requiring the program to be sshd or sshd-session) and parses the
// remaining message with ParseSSHDMessage. All events are stamped with now.
func ParseSSHDSyslog(line string, now time.Time) (event.Event, bool) {
	m := sshdSyslogPrefix.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}
	return ParseSSHDMessage(m[1], now)
}

// ParseSSHDMessage parses a bare sshd message such as journald -o cat emits.
// All events are stamped with now.
func ParseSSHDMessage(msg string, now time.Time) (event.Event, bool) {
	for _, r := range sshdRules {
		m := r.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		addr, err := netip.ParseAddr(m[r.ip])
		if err != nil {
			// Fail closed: an unparsable address is never retried as another shape.
			return event.Event{}, false
		}
		ev := event.Event{
			Time:   now,
			Source: "sshd",
			IP:     addr.Unmap(),
			Kind:   r.kind,
		}
		if r.user >= 0 {
			ev.User = m[r.user]
		}
		return ev, true
	}
	return event.Event{}, false
}
