package source

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDiscover(t *testing.T) {
	journal := []string{"ssh.service", "sshd.service"}
	tests := []struct {
		name           string
		files          []string
		haveJournalctl bool
		want           []Spec
	}{
		{
			name:           "auth.log and nginx",
			files:          []string{"/var/log/auth.log", "/var/log/nginx/access.log"},
			haveJournalctl: true,
			want: []Spec{
				{Name: NameSSHD, Path: "/var/log/auth.log"},
				{Name: NameNginxAccess, Path: "/var/log/nginx/access.log"},
			},
		},
		{
			name:  "only secure",
			files: []string{"/var/log/secure"},
			want:  []Spec{{Name: NameSSHD, Path: "/var/log/secure"}},
		},
		{
			name:  "auth.log wins over secure",
			files: []string{"/var/log/secure", "/var/log/auth.log"},
			want:  []Spec{{Name: NameSSHD, Path: "/var/log/auth.log"}},
		},
		{
			name:           "no files but journalctl",
			haveJournalctl: true,
			want:           []Spec{{Name: NameSSHD, JournalUnits: journal}},
		},
		{
			name: "no files and no journalctl",
			want: nil,
		},
		{
			name:  "nginx only, no journalctl",
			files: []string{"/var/log/nginx/access.log"},
			want:  []Spec{{Name: NameNginxAccess, Path: "/var/log/nginx/access.log"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			present := map[string]bool{}
			for _, f := range tc.files {
				present[f] = true
			}
			got := Discover(func(p string) bool { return present[p] }, tc.haveJournalctl)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Discover = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestJournalArgs(t *testing.T) {
	got := JournalArgs([]string{"ssh.service", "sshd.service"})
	want := []string{"-f", "-n", "0", "-o", "cat", "-u", "ssh.service", "-u", "sshd.service"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JournalArgs = %v, want %v", got, want)
	}
}

func TestStartWrapsLinesWithSpec(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	spec := Spec{Name: NameSSHD, Path: path}
	out := make(chan Line)
	Start(ctx, []Spec{spec}, out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	time.Sleep(startSettle)
	appendFile(t, path, "hello\n")

	select {
	case l := <-out:
		if l.Text != "hello" || !reflect.DeepEqual(l.Spec, spec) {
			t.Fatalf("got %#v, want text %q with spec %#v", l, "hello", spec)
		}
	case <-time.After(recvTimeout):
		t.Fatal("timed out waiting for a line")
	}
}

// TestStartStopsWhenContextDone gets every goroutine of a file source stuck in
// a send nobody receives (the forwarder on out, the tailer on the forwarder),
// then checks that cancelling ctx lets all of them exit.
func TestStartStopsWhenContextDone(t *testing.T) {
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	path := filepath.Join(t.TempDir(), "access.log")
	writeFile(t, path, "")
	out := make(chan Line) // nobody reads
	Start(ctx, []Spec{{Name: NameNginxAccess, Path: path}}, out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	time.Sleep(startSettle)
	appendFile(t, path, "x\ny\n")
	// Wait out more than one 250ms poll so the lines are in flight and both
	// sends are blocked.
	time.Sleep(2 * filePoll)
	cancel()

	deadline := time.Now().Add(recvTimeout)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d after cancel, want %d", runtime.NumGoroutine(), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestForwardReturnsWhenSendBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	raw := make(chan string, 1)
	raw <- "x"
	out := make(chan Line) // nobody reads
	done := make(chan struct{})
	go func() {
		forward(ctx, Spec{Name: NameSSHD}, raw, out)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond) // forward has taken "x" and is stuck sending it
	cancel()

	select {
	case <-done:
	case <-time.After(recvTimeout):
		t.Fatal("forward did not return after cancel")
	}
}

// syncBuffer is a log sink safe to write from the source goroutines while the
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForLog(t *testing.T, b *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(recvTimeout)
	for !strings.Contains(b.String(), substr) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %q; got:\n%s", substr, b.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartLogsFileProblems(t *testing.T) {
	t.Run("missing file is an info, not a warning", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		path := filepath.Join(t.TempDir(), "access.log")
		var logs syncBuffer
		Start(ctx, []Spec{{Name: NameNginxAccess, Path: path}}, make(chan Line), slog.New(slog.NewTextHandler(&logs, nil)))

		waitForLog(t, &logs, "does not exist yet")
		if got := logs.String(); !strings.Contains(got, "level=INFO") || !strings.Contains(got, path) || strings.Contains(got, "level=WARN") {
			t.Fatalf("want one INFO naming %s and no WARN, got:\n%s", path, got)
		}
	})

	t.Run("unreadable file is a warning", func(t *testing.T) {
		skipIfRoot(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		path := filepath.Join(t.TempDir(), "auth.log")
		writeFile(t, path, "old\n")
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		var logs syncBuffer
		Start(ctx, []Spec{{Name: NameSSHD, Path: path}}, make(chan Line), slog.New(slog.NewTextHandler(&logs, nil)))

		waitForLog(t, &logs, "cannot read log file")
		got := logs.String()
		if !strings.Contains(got, "level=WARN") || !strings.Contains(got, path) || !strings.Contains(got, "permission denied") {
			t.Fatalf("want a WARN naming %s and the cause, got:\n%s", path, got)
		}
	})
}
