// Package logging holds what Ostrakon's log output shares: the Notice level
// and the handler that, under systemd, starts each line with the priority
// journald files it under.
package logging

import (
	"context"
	"io"
	"log/slog"
	"sync"
)

// LevelNotice sits between Info and Warn: a normal but significant event,
// such as protection resuming after a pause.
const LevelNotice = slog.Level(2)

// Prefix returns the sd-daemon priority prefix (sd-daemon(3)) for level:
// <3> error, <4> warning, <5> notice, <6> info, <7> debug.
func Prefix(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "<3>"
	case level >= slog.LevelWarn:
		return "<4>"
	case level >= LevelNotice:
		return "<5>"
	case level >= slog.LevelInfo:
		return "<6>"
	default:
		return "<7>"
	}
}

// ReplaceLevel is a slog.HandlerOptions.ReplaceAttr that names LevelNotice
// "NOTICE" (slog would print INFO+2).
func ReplaceLevel(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.LevelKey {
		if l, ok := a.Value.Any().(slog.Level); ok && l == LevelNotice {
			a.Value = slog.StringValue("NOTICE")
		}
	}
	return a
}

// NewHandler returns the daemon's handler: text lines to w, Info and above.
// With journal set (the process's stderr is connected to journald, which
// sets JOURNAL_STREAM) each line starts with Prefix of its level.
func NewHandler(w io.Writer, journal bool) slog.Handler {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo, ReplaceAttr: ReplaceLevel}
	if !journal {
		return slog.NewTextHandler(w, opts)
	}
	pw := &prefixWriter{w: w}
	return &journalHandler{inner: slog.NewTextHandler(pw, opts), pw: pw}
}

// journalHandler sets the prefix for a record, then lets the text handler
// write it. The text handler writes each record with a single Write, which
// prefixWriter turns into a single prefixed Write.
type journalHandler struct {
	inner slog.Handler
	pw    *prefixWriter // shared with every handler derived by WithAttrs/WithGroup
}

type prefixWriter struct {
	mu     sync.Mutex // held from setting prefix until the record is written
	w      io.Writer
	prefix string
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	line := make([]byte, 0, len(p.prefix)+len(b))
	line = append(append(line, p.prefix...), b...)
	if _, err := p.w.Write(line); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (h *journalHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *journalHandler) Handle(ctx context.Context, r slog.Record) error {
	h.pw.mu.Lock()
	defer h.pw.mu.Unlock()
	h.pw.prefix = Prefix(r.Level)
	return h.inner.Handle(ctx, r)
}

func (h *journalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &journalHandler{inner: h.inner.WithAttrs(attrs), pw: h.pw}
}

func (h *journalHandler) WithGroup(name string) slog.Handler {
	return &journalHandler{inner: h.inner.WithGroup(name), pw: h.pw}
}
