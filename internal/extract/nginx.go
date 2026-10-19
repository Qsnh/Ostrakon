package extract

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Qsnh/Ostrakon/internal/event"
)

// ParseNginxAccess parses one line of an nginx access log in the default
// "combined" format (or a close relative). The event is stamped with now.
//
// The source IP is the first space-delimited field ($remote_addr) and nothing
// else: the request, referer and user agent are attacker-controlled and are
// never consulted for it. nginx escapes a literal '"' in those fields as
// \x22, so splitting on '"' yields the quoted fields reliably. Fields are
// attributed by position (1st quoted: request, 2nd: referer, 3rd: user
// agent); any further quoted fields are ignored. A line whose
// first field is not an IP address (a hostname, "unix:", an address with a
// zone) is rejected.
//
// Beyond the address the parser is lenient: a line with an unrecognized shape
// still yields an event carrying only the IP (Status 0).
func ParseNginxAccess(line string, now time.Time) (event.Event, bool) {
	field, rest, found := strings.Cut(line, " ")
	if !found {
		return event.Event{}, false
	}
	addr, err := netip.ParseAddr(field)
	if err != nil || addr.Zone() != "" {
		return event.Event{}, false
	}
	ev := event.Event{
		Time:   now,
		Source: "nginx-access",
		IP:     addr.Unmap(),
		Kind:   event.KindHTTPRequest,
	}

	// parts[1], parts[3], ... are the quoted fields; only those followed by
	// a closing quote count, so a truncated line cannot yield a half field.
	parts := strings.Split(rest, `"`)
	closed := (len(parts) - 1) / 2
	if closed == 0 {
		return ev, true
	}

	// The request line is the first quoted field: "METHOD PATH PROTO". Any
	// other shape (TLS probe bytes, empty, extra spaces) is kept whole as Path.
	if req := strings.Split(parts[1], " "); len(req) == 3 {
		ev.Method, ev.Path = req[0], req[1]
	} else {
		ev.Path = parts[1]
	}

	// The status is the first token after the request's closing quote.
	if tok := strings.Fields(parts[2]); len(tok) > 0 {
		if n, err := strconv.Atoi(tok[0]); err == nil {
			ev.Status = n
		}
	}

	// The user agent is anchored by position: the third quoted field, after
	// the request and the referer, as in the combined format. It is not "the
	// last quoted field": formats such as nginx's stock "main" append
	// "$http_x_forwarded_for", which is client-controlled and must not be
	// reported as the user agent. Formats with fewer quoted fields yield "".
	if closed >= 3 {
		ev.UserAgent = parts[5]
	}
	return ev, true
}
