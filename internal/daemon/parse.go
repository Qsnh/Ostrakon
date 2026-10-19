package daemon

import (
	"time"

	"ostrakon/internal/event"
	"ostrakon/internal/extract"
	"ostrakon/internal/source"
)

// parse turns one line from spec into an event stamped with now, using the
// extractor for that source. sshd log files carry a syslog prefix naming the
// program; journald lines are bare messages (journalctl -o cat), already
// limited to the sshd units. A line no extractor recognizes is dropped.
func parse(spec source.Spec, text string, now time.Time) (event.Event, bool) {
	switch spec.Name {
	case source.NameSSHD:
		if spec.Path != "" {
			return extract.ParseSSHDSyslog(text, now)
		}
		return extract.ParseSSHDMessage(text, now)
	case source.NameNginxAccess:
		return extract.ParseNginxAccess(text, now)
	}
	return event.Event{}, false
}
