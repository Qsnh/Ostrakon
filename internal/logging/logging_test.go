package logging

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestPrefix(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelError, "<3>"},
		{slog.LevelError + 4, "<3>"},
		{slog.LevelWarn, "<4>"},
		{LevelNotice, "<5>"},
		{slog.LevelInfo, "<6>"},
		{slog.LevelInfo + 1, "<6>"},
		{slog.LevelDebug, "<7>"},
	}
	for _, tt := range tests {
		if got := Prefix(tt.level); got != tt.want {
			t.Errorf("Prefix(%v) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

// Under systemd every line starts with the priority journald should file it
// under, so that `journalctl -p err` shows a pause.
func TestJournalHandlerPrefixesEachLine(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(&buf, true))
	log.Debug("not shown")
	log.Info("ostrakon started", "workers", 4)
	log.Log(context.Background(), LevelNotice, "protection resumed")
	log.Warn("decision queue full")
	log.Error("protection paused", "reason", "jev: HTTP 401")

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	want := []struct{ prefix, text string }{
		{"<6>", `level=INFO msg="ostrakon started" workers=4`},
		{"<5>", `level=NOTICE msg="protection resumed"`},
		{"<4>", `level=WARN msg="decision queue full"`},
		{"<3>", `level=ERROR msg="protection paused" reason="jev: HTTP 401"`},
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d (Debug is below the handler's level):\n%s", len(lines), len(want), buf.String())
	}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w.prefix+"time=") || !strings.HasSuffix(lines[i], w.text) {
			t.Errorf("line %d = %q, want %q time=... %s", i, lines[i], w.prefix, w.text)
		}
	}
}

func TestJournalHandlerKeepsPrefixThroughWith(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(&buf, true)).With("component", "tail").WithGroup("g")
	log.Warn("file missing", "path", "/var/log/auth.log")
	if got := buf.String(); !strings.HasPrefix(got, "<4>time=") ||
		!strings.Contains(got, `component=tail g.path=/var/log/auth.log`) {
		t.Errorf("output = %q", got)
	}
}

// Loggers share one writer from many goroutines: no line may get another
// line's prefix.
func TestJournalHandlerConcurrent(t *testing.T) {
	var buf syncBuffer
	log := slog.New(NewHandler(&buf, true))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 50 {
				if (i+j)%2 == 0 {
					log.Error("e", "n", j)
				} else {
					log.Info("i", "n", j)
				}
			}
		})
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 400 {
		t.Fatalf("got %d lines, want 400", len(lines))
	}
	for _, l := range lines {
		ok := (strings.HasPrefix(l, "<3>") && strings.Contains(l, "level=ERROR")) ||
			(strings.HasPrefix(l, "<6>") && strings.Contains(l, "level=INFO"))
		if !ok || strings.Count(l, "time=") != 1 {
			t.Fatalf("bad line %q", l)
		}
	}
}

// Outside systemd (a terminal) lines carry no prefix.
func TestPlainHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(&buf, false))
	log.Debug("not shown")
	log.Log(context.Background(), LevelNotice, "protection resumed")
	log.Error("protection paused")
	got := buf.String()
	if strings.Contains(got, "<") || strings.Contains(got, "not shown") {
		t.Errorf("output = %q", got)
	}
	for _, want := range []string{`level=NOTICE msg="protection resumed"`, `level=ERROR msg="protection paused"`} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
}

func TestReplaceLevelLeavesOthers(t *testing.T) {
	for _, l := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError, slog.LevelInfo + 1} {
		a := ReplaceLevel(nil, slog.Any(slog.LevelKey, l))
		if got := fmt.Sprint(a.Value.Any()); got != l.String() {
			t.Errorf("ReplaceLevel(%v) = %v", l, got)
		}
	}
	if a := ReplaceLevel([]string{"g"}, slog.Any(slog.LevelKey, LevelNotice)); fmt.Sprint(a.Value.Any()) != LevelNotice.String() {
		t.Errorf("an attribute named level inside a group was renamed: %v", a)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
