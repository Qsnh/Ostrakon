package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testPoll    = 10 * time.Millisecond
	recvTimeout = 2 * time.Second
	// startSettle gives a freshly started tailer time to open the file and
	// seek to its end before the test touches the file again.
	startSettle = 100 * time.Millisecond
)

// startTail runs TailFile on path and returns its output channel. The tailer
// is cancelled and waited for when the test ends.
func startTail(t *testing.T, path string) <-chan string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan string, 16)
	done := make(chan error, 1)
	go func() { done <- TailFile(ctx, path, testPoll, out) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(recvTimeout):
			t.Error("TailFile did not return after cancel")
		}
	})
	time.Sleep(startSettle)
	return out
}

func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(recvTimeout):
		t.Fatal("timed out waiting for a line")
		return ""
	}
}

func expectNone(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case s := <-ch:
		t.Fatalf("unexpected line %q", s)
	case <-time.After(100 * time.Millisecond):
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTailStartsAtEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "old\n")
	out := startTail(t, path)
	appendFile(t, path, "new\n")
	if got := recv(t, out); got != "new" {
		t.Fatalf("got %q, want %q", got, "new")
	}
	expectNone(t, out)
}

func TestTailRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "")
	out := startTail(t, path)

	appendFile(t, path, "a\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "b\n")

	if got := recv(t, out); got != "a" {
		t.Fatalf("got %q, want %q", got, "a")
	}
	if got := recv(t, out); got != "b" {
		t.Fatalf("got %q, want %q", got, "b")
	}
	expectNone(t, out)
}

func TestTailRenameFlushesOldPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "")
	out := startTail(t, path)

	appendFile(t, path, "done\nhalf")
	if got := recv(t, out); got != "done" {
		t.Fatalf("got %q, want %q", got, "done")
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "next\n")

	// The old file's unterminated tail is emitted as-is, not glued to the
	// first line of the new file.
	if got := recv(t, out); got != "half" {
		t.Fatalf("got %q, want %q", got, "half")
	}
	if got := recv(t, out); got != "next" {
		t.Fatalf("got %q, want %q", got, "next")
	}
}

func TestTailCopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "0123456789\n")
	out := startTail(t, path)

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "c\n")
	if got := recv(t, out); got != "c" {
		t.Fatalf("got %q, want %q", got, "c")
	}
	expectNone(t, out)
}

func TestTailMissingThenCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	out := startTail(t, path)

	time.Sleep(50 * time.Millisecond)
	writeFile(t, path, "d\n")
	if got := recv(t, out); got != "d" {
		t.Fatalf("got %q, want %q", got, "d")
	}
}

func TestTailRemovedAndRecreatedLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "")
	out := startTail(t, path)

	appendFile(t, path, "before\n")
	if got := recv(t, out); got != "before" {
		t.Fatalf("got %q, want %q", got, "before")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	writeFile(t, path, "e\n")
	if got := recv(t, out); got != "e" {
		t.Fatalf("got %q, want %q", got, "e")
	}
}

func TestTailPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "")
	out := startTail(t, path)

	appendFile(t, path, "par")
	time.Sleep(20 * time.Millisecond)
	appendFile(t, path, "tial\n")
	if got := recv(t, out); got != "partial" {
		t.Fatalf("got %q, want %q", got, "partial")
	}
	expectNone(t, out)
}

func TestTailStripsTerminatorsAndSkipsEmptyLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "")
	out := startTail(t, path)

	appendFile(t, path, "crlf\r\n\r\n\nplain\n")
	for _, want := range []string{"crlf", "plain"} {
		if got := recv(t, out); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	expectNone(t, out)
}

func TestTailTruncatesLongLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "")
	out := startTail(t, path)

	appendFile(t, path, strings.Repeat("x", 3*maxLineBytes)+"\nafter\n")
	if got := recv(t, out); got != strings.Repeat("x", maxLineBytes) {
		t.Fatalf("long line: got %d bytes, want %d", len(got), maxLineBytes)
	}
	if got := recv(t, out); got != "after" {
		t.Fatalf("got %q, want %q", got, "after")
	}
	expectNone(t, out)
}

func TestTailReturnsOnCancelEvenWhenOutputBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeFile(t, path, "")
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan string) // unbuffered and never read
	done := make(chan error, 1)
	go func() { done <- TailFile(ctx, path, testPoll, out) }()
	time.Sleep(startSettle)
	appendFile(t, path, "stuck\n")
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(recvTimeout):
		t.Fatal("TailFile did not return after cancel")
	}
}
