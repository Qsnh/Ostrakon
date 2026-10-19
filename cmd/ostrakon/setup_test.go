package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ostrakon/internal/setup"
	"ostrakon/internal/source"
)

// noopSetupEnv is a setup.Env that succeeds without touching the machine.
func noopSetupEnv(out *bytes.Buffer) setup.Env {
	return setup.Env{
		Out:           out,
		Getenv:        func(string) string { return "k-1" },
		ReadSecret:    func(string) (string, error) { return "", errors.New("unexpected prompt") },
		Validate:      func(context.Context, string) error { return nil },
		IsRoot:        func() bool { return true },
		HaveNFT:       func() bool { return true },
		Discover:      func() []source.Spec { return nil },
		MkdirAll:      func(string, os.FileMode) error { return nil },
		WriteFile:     func(string, []byte, os.FileMode) error { return nil },
		InstallBinary: func(string) error { return nil },
		Systemctl:     func(...string) error { return nil },
	}
}

func TestRunSetup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := runSetup(nil, &errb, noopSetupEnv(&out))
		if code != 0 || errb.Len() != 0 || !strings.Contains(out.String(), "Ostrakon is running") {
			t.Errorf("code = %d, stdout = %q, stderr = %q", code, out.String(), errb.String())
		}
	})
	t.Run("failure", func(t *testing.T) {
		var out, errb bytes.Buffer
		env := noopSetupEnv(&out)
		env.IsRoot = func() bool { return false }
		code := runSetup(nil, &errb, env)
		if code != 1 || errb.String() != "ostrakon setup: setup must run as root\n" {
			t.Errorf("code = %d, stderr = %q", code, errb.String())
		}
	})
	t.Run("arguments are a usage error", func(t *testing.T) {
		var out, errb bytes.Buffer
		env := noopSetupEnv(&out)
		env.IsRoot = func() bool { t.Error("setup ran despite a bad argument"); return true }
		code := runSetup([]string{"--force"}, &errb, env)
		if code != 2 || errb.String() != "usage: ostrakon setup\n" {
			t.Errorf("code = %d, stderr = %q", code, errb.String())
		}
	})
}

// dispatch must route setup to runSetup (not to the control commands), and
// reject extra arguments before touching the machine.
func TestDispatchSetup(t *testing.T) {
	var out, errb bytes.Buffer
	code := dispatch([]string{"setup", "extra"}, &out, &errb)
	if code != 2 || out.Len() != 0 || errb.String() != "usage: ostrakon setup\n" {
		t.Errorf("code = %d, stdout = %q, stderr = %q", code, out.String(), errb.String())
	}
}

func TestUsageListsSetup(t *testing.T) {
	if !strings.Contains(usageText, "\n  setup ") {
		t.Errorf("usage does not list setup:\n%s", usageText)
	}
}

func TestValidateKey(t *testing.T) {
	const key = "sk-secret-123"

	t.Run("accepted", func(t *testing.T) {
		var gotAuth, gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
			w.Write([]byte(`{"model":"jev-1.13.0","answers":{"ok":{"type":"noul","noul":0.5}}}`))
		}))
		defer srv.Close()
		if err := validateKey(context.Background(), srv.URL, key); err != nil {
			t.Fatalf("validateKey: %v", err)
		}
		if gotAuth != "Bearer "+key || gotPath != "/v1/systemone" {
			t.Errorf("request: auth = %q, path = %q", gotAuth, gotPath)
		}
	})

	t.Run("rejected without leaking the key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		defer srv.Close()
		err := validateKey(context.Background(), srv.URL, key)
		if err == nil {
			t.Fatal("a 401 was accepted")
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("error contains the key: %v", err)
		}
	})

	t.Run("unreachable without leaking the key", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close()
		err := validateKey(context.Background(), url, key)
		if err == nil || strings.Contains(err.Error(), key) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestReadLine(t *testing.T) {
	tests := []struct{ in, want string }{
		{"k-1\n", "k-1"},
		{"k-1\r\n", "k-1"},
		{"k-1", "k-1"},
		{"k-1\nsecond line\n", "k-1"},
		{"", ""},
		{"\n", ""},
	}
	for _, tt := range tests {
		got, err := readLine(strings.NewReader(tt.in))
		if err != nil || got != tt.want {
			t.Errorf("readLine(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestReadSecretFromPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("k-piped\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	var out bytes.Buffer
	got, err := readSecret(&out, r, "Jev API key: ")
	if err != nil || got != "k-piped" {
		t.Errorf("readSecret = %q, %v", got, err)
	}
	if !strings.HasPrefix(out.String(), "Jev API key: ") {
		t.Errorf("prompt not printed: %q", out.String())
	}
}

func TestCopyBinary(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("new binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old binary, longer than the new one"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := copyBinary(src, dst); err != nil {
		t.Fatalf("copyBinary: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new binary" {
		t.Errorf("dst = %q", got)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o755 {
		t.Errorf("dst mode = %04o, want 0755", fi.Mode().Perm())
	}
	if _, err := os.Stat(dst + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file left behind: %v", err)
	}
}

func TestCopyBinaryCreatesDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("bin"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyBinary(src, dst); err != nil {
		t.Fatalf("copyBinary: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "bin" {
		t.Errorf("dst = %q", got)
	}
}

func TestCopyBinarySameFileIsSkipped(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bin")
	if err := os.WriteFile(src, []byte("bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Link(src, link); err != nil { // a hard link is the same file
		t.Fatal(err)
	}
	if err := copyBinary(src, link); err != nil {
		t.Fatalf("copyBinary: %v", err)
	}
	if fi, _ := os.Stat(src); fi.Mode().Perm() != 0o600 {
		t.Errorf("the file was touched: mode %04o", fi.Mode().Perm())
	}
	if _, err := os.Stat(link + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a copy was made: %v", err)
	}
}

func TestCopyBinaryMissingSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(dst, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyBinary(filepath.Join(dir, "missing"), dst); err == nil {
		t.Fatal("copyBinary succeeded without a source")
	}
	if got, _ := os.ReadFile(dst); string(got) != "old" {
		t.Errorf("the destination was damaged: %q", got)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	// An existing, too permissive file must end up with the requested mode.
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("k-1\n"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "k-1\n" {
		t.Errorf("content = %q", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file left behind: %v", err)
	}
}

func TestWriteFileAtomicMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "key")
	if err := writeFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Fatal("writeFileAtomic succeeded in a missing directory")
	}
}

func TestRunCommandReportsOutput(t *testing.T) {
	if err := runCommand("sh", "-c", "exit 0"); err != nil {
		t.Errorf("a successful command failed: %v", err)
	}
	err := runCommand("sh", "-c", "echo boom >&2; exit 3")
	if err == nil {
		t.Fatal("a failing command succeeded")
	}
	for _, want := range []string{"sh -c", "exit status 3", "boom"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if err := runCommand("ostrakon-no-such-command"); err == nil {
		t.Error("a missing command succeeded")
	}
}
