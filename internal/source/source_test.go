package source

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

func TestStartStopsWhenContextDone(t *testing.T) {
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())

	path := filepath.Join(t.TempDir(), "access.log")
	out := make(chan Line) // nobody reads, so a send is stuck until ctx is done
	Start(ctx, []Spec{{Name: NameNginxAccess, Path: path}}, out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	appendFile(t, path, "x\n")
	time.Sleep(100 * time.Millisecond)
	cancel()

	deadline := time.Now().Add(recvTimeout)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d after cancel, want %d", runtime.NumGoroutine(), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
