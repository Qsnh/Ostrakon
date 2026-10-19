// Package notify defines how Ostrakon tells the outside world that protection
// has been paused or resumed.
package notify

import "time"

// Notifier is told when Ostrakon stops making ban decisions because Jev is
// unusable, and when it starts again. Implementations must be safe for
// concurrent use and must not block for long: callers invoke them inline.
type Notifier interface {
	// Paused is called once when protection pauses; reason is the error text
	// that caused it.
	Paused(reason string, at time.Time)
	// Resumed is called once when protection resumes after a pause.
	Resumed(at time.Time)
}

// Noop is a Notifier that does nothing. It is the default: pauses and resumes
// are always logged, a Notifier only adds an external channel.
type Noop struct{}

var _ Notifier = Noop{}

func (Noop) Paused(string, time.Time) {}
func (Noop) Resumed(time.Time)        {}
