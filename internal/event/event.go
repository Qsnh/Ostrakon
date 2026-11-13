// Package event defines the normalized log event shared by every extractor,
// the tracker and the decision pipeline.
package event

import (
	"net/netip"
	"time"
)

// MaxField is the longest string field, in runes, that Ostrakon keeps from a
// log line (tracker) or sends to Jev (judge.MaxField).
const MaxField = 128

// Kind classifies what a log line told us about a source IP.
type Kind string

const (
	// KindAuthFail: "Failed <m> for ..."; "maximum authentication attempts exceeded ...".
	KindAuthFail Kind = "auth_fail"
	// KindInvalidUser: "Invalid user ..."; "Disconnected from invalid user ...";
	// "Connection closed by invalid user ...".
	KindInvalidUser Kind = "invalid_user"
	// KindPreauthClose: "Connection closed by authenticating user ...";
	// "Connection closed by <ip> port <n> [preauth]".
	KindPreauthClose Kind = "preauth_close"
	// KindAuthSuccess: "Accepted <m> for <user> from <ip> port <n> ssh2...".
	KindAuthSuccess Kind = "auth_success"
	// KindHTTPRequest: one nginx access-log request.
	KindHTTPRequest Kind = "http_request"
)

// Event is one normalized observation about a source IP. Every field except
// IP is attacker-influenced text or metadata and must be treated as untrusted.
type Event struct {
	Time      time.Time
	Source    string     // "sshd" | "nginx-access"
	IP        netip.Addr // always Unmap()ed
	Kind      Kind
	User      string
	Method    string
	Path      string
	Status    int
	UserAgent string
}
