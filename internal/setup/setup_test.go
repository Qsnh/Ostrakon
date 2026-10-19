package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Qsnh/Ostrakon/internal/source"
)

const wantUnit = `[Unit]
Description=Ostrakon brute-force protection
After=network-online.target nftables.service time-sync.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ostrakon run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`

type written struct {
	data string
	perm os.FileMode
}

// rig is an Env made of recording fakes. Every call is appended to calls, in
// order, so tests can assert the exact sequence of side effects.
type rig struct {
	env   Env
	out   bytes.Buffer
	calls []string
	files map[string]written
}

// newRig returns a rig for a root user with nft installed, no environment
// key, a prompt that answers "k-1", a Validate that accepts everything and no
// log sources. Tests override fields of r.env to vary that.
func newRig() *rig {
	r := &rig{files: map[string]written{}}
	r.env = Env{
		Out:    &r.out,
		Getenv: func(string) string { return "" },
		ReadSecret: func(prompt string) (string, error) {
			r.calls = append(r.calls, "readsecret:"+prompt)
			return "k-1", nil
		},
		Validate: func(_ context.Context, key string) error {
			r.calls = append(r.calls, "validate:"+key)
			return nil
		},
		IsRoot:  func() bool { r.calls = append(r.calls, "isroot"); return true },
		HaveNFT: func() bool { r.calls = append(r.calls, "havenft"); return true },
		Discover: func() []source.Spec {
			r.calls = append(r.calls, "discover")
			return nil
		},
		MkdirAll: func(path string, perm os.FileMode) error {
			r.calls = append(r.calls, fmt.Sprintf("mkdir:%s:%04o", path, perm))
			return nil
		},
		WriteFile: func(path string, data []byte, perm os.FileMode) error {
			r.calls = append(r.calls, fmt.Sprintf("write:%s:%04o", path, perm))
			r.files[path] = written{string(data), perm}
			return nil
		},
		InstallBinary: func(dst string) error {
			r.calls = append(r.calls, "install:"+dst)
			return nil
		},
		Systemctl: func(args ...string) error {
			r.calls = append(r.calls, "systemctl:"+strings.Join(args, " "))
			return nil
		},
	}
	return r
}

func (r *rig) run() error { return Run(context.Background(), r.env) }

// sideEffects reports whether any call changed the machine.
func (r *rig) sideEffects() []string {
	var got []string
	for _, c := range r.calls {
		switch {
		case strings.HasPrefix(c, "mkdir:"), strings.HasPrefix(c, "write:"),
			strings.HasPrefix(c, "install:"), strings.HasPrefix(c, "systemctl:"):
			got = append(got, c)
		}
	}
	return got
}

func TestUnit(t *testing.T) {
	if got := Unit(); got != wantUnit {
		t.Errorf("Unit() =\n%s\nwant\n%s", got, wantUnit)
	}
}

func TestSetupHappyPath(t *testing.T) {
	r := newRig()
	r.env.Discover = func() []source.Spec {
		r.calls = append(r.calls, "discover")
		return []source.Spec{
			{Name: "sshd", Path: "/var/log/auth.log"},
			{Name: "nginx-access", Path: "/var/log/nginx/access.log"},
		}
	}

	if err := r.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	wantCalls := []string{
		"isroot",
		"havenft",
		"readsecret:Jev API key: ",
		"validate:k-1",
		"mkdir:/etc/ostrakon:0700",
		"write:/etc/ostrakon/key:0600",
		"discover",
		"install:/usr/local/bin/ostrakon",
		"write:/etc/systemd/system/ostrakon.service:0644",
		"systemctl:daemon-reload",
		"systemctl:enable --now ostrakon",
	}
	if !reflect.DeepEqual(r.calls, wantCalls) {
		t.Errorf("calls =\n%q\nwant\n%q", r.calls, wantCalls)
	}
	if got := r.files["/etc/ostrakon/key"]; got != (written{"k-1\n", 0o600}) {
		t.Errorf("key file = %q mode %04o, want \"k-1\\n\" mode 0600", got.data, got.perm)
	}
	if got := r.files["/etc/systemd/system/ostrakon.service"]; got != (written{Unit(), 0o644}) {
		t.Errorf("unit file = %q mode %04o, want Unit() mode 0644", got.data, got.perm)
	}
	wantOut := "  - sshd: /var/log/auth.log\n" +
		"  - nginx-access: /var/log/nginx/access.log\n" +
		"Ostrakon is running. Check with: ostrakon status\n"
	if got := r.out.String(); got != wantOut {
		t.Errorf("output = %q, want %q", got, wantOut)
	}
}

func TestSetupJournaldSource(t *testing.T) {
	r := newRig()
	r.env.Discover = func() []source.Spec {
		return []source.Spec{{Name: "sshd", JournalUnits: []string{"ssh.service", "sshd.service"}}}
	}
	if err := r.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantOut := "  - sshd: journald\nOstrakon is running. Check with: ostrakon status\n"
	if got := r.out.String(); got != wantOut {
		t.Errorf("output = %q, want %q", got, wantOut)
	}
}

func TestSetupNoSourcesWarnsButSucceeds(t *testing.T) {
	r := newRig()
	if err := r.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantOut := "warning: no supported logs found (sshd / nginx)\nOstrakon is running. Check with: ostrakon status\n"
	if got := r.out.String(); got != wantOut {
		t.Errorf("output = %q, want %q", got, wantOut)
	}
	if len(r.sideEffects()) != 6 {
		t.Errorf("setup stopped early: %q", r.calls)
	}
}

func TestSetupUsesEnvKey(t *testing.T) {
	r := newRig()
	r.env.Getenv = func(name string) string {
		if name == "TYPESAFE_API_KEY" {
			return "k-env"
		}
		return ""
	}
	r.env.ReadSecret = func(string) (string, error) {
		t.Error("ReadSecret was called although the environment has a key")
		return "", nil
	}
	if err := r.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := r.files["/etc/ostrakon/key"]; got != (written{"k-env\n", 0o600}) {
		t.Errorf("key file = %q mode %04o, want \"k-env\\n\" mode 0600", got.data, got.perm)
	}
	if !contains(r.calls, "validate:k-env") {
		t.Errorf("the environment key was not validated: %q", r.calls)
	}
	if strings.Contains(r.out.String(), "Jev API key") {
		t.Errorf("a prompt was printed for an environment key: %q", r.out.String())
	}
}

func TestSetupTrimsKey(t *testing.T) {
	tests := []struct {
		name   string
		getenv string
		secret string
	}{
		{"environment", "  k-2\t\n", ""},
		{"prompt", "", "  k-2 \r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			r.env.Getenv = func(string) string { return tt.getenv }
			r.env.ReadSecret = func(string) (string, error) { return tt.secret, nil }
			if err := r.run(); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !contains(r.calls, "validate:k-2") {
				t.Errorf("Validate did not get the trimmed key: %q", r.calls)
			}
			if got := r.files["/etc/ostrakon/key"].data; got != "k-2\n" {
				t.Errorf("key file = %q, want \"k-2\\n\"", got)
			}
		})
	}
}

func TestSetupBlankEnvKeyFallsBackToPrompt(t *testing.T) {
	r := newRig()
	r.env.Getenv = func(string) string { return "  \n" }
	if err := r.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !contains(r.calls, "readsecret:Jev API key: ") || !contains(r.calls, "validate:k-1") {
		t.Errorf("calls = %q", r.calls)
	}
}

func TestSetupNotRoot(t *testing.T) {
	r := newRig()
	r.env.IsRoot = func() bool { r.calls = append(r.calls, "isroot"); return false }
	err := r.run()
	if err == nil || err.Error() != "setup must run as root" {
		t.Fatalf("err = %v, want \"setup must run as root\"", err)
	}
	if !reflect.DeepEqual(r.calls, []string{"isroot"}) {
		t.Errorf("calls after the root check: %q", r.calls)
	}
	if len(r.files) != 0 {
		t.Errorf("files written: %v", r.files)
	}
}

func TestSetupNoNFT(t *testing.T) {
	r := newRig()
	r.env.HaveNFT = func() bool { r.calls = append(r.calls, "havenft"); return false }
	err := r.run()
	if err == nil || err.Error() != "nftables (nft) is required but was not found" {
		t.Fatalf("err = %v, want the nft error", err)
	}
	if !reflect.DeepEqual(r.calls, []string{"isroot", "havenft"}) {
		t.Errorf("calls: %q", r.calls)
	}
	if len(r.files) != 0 {
		t.Errorf("files written: %v", r.files)
	}
}

func TestSetupValidateFails(t *testing.T) {
	r := newRig()
	r.env.Validate = func(_ context.Context, key string) error {
		r.calls = append(r.calls, "validate:"+key)
		return errors.New("HTTP 401 unauthorized")
	}
	err := r.run()
	if err == nil || err.Error() != "Jev key check failed: HTTP 401 unauthorized" {
		t.Fatalf("err = %v, want \"Jev key check failed: HTTP 401 unauthorized\"", err)
	}
	if got := r.sideEffects(); len(got) != 0 {
		t.Errorf("side effects after a failed key check: %q", got)
	}
	if len(r.files) != 0 {
		t.Errorf("files written: %v", r.files)
	}
	if r.out.Len() != 0 {
		t.Errorf("output after a failed key check: %q", r.out.String())
	}
}

func TestSetupNoKey(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		err    error
	}{
		{"empty answer", "", nil},
		{"blank answer", " \t\r\n", nil},
		{"prompt fails", "", errors.New("read terminal: boom")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			r.env.ReadSecret = func(prompt string) (string, error) {
				r.calls = append(r.calls, "readsecret:"+prompt)
				return tt.secret, tt.err
			}
			err := r.run()
			if err == nil {
				t.Fatal("Run succeeded without a key")
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Errorf("err = %v, want it to wrap %v", err, tt.err)
			}
			if contains(r.calls, "validate:") || len(r.sideEffects()) != 0 {
				t.Errorf("work was done without a key: %q", r.calls)
			}
		})
	}
}

func TestSetupRejectsKeyWithInnerWhitespaceOrControl(t *testing.T) {
	keys := map[string]string{
		"space":      "ab cd",
		"tab":        "ab\tcd",
		"newline":    "ab\ncd",
		"nul":        "ab\x00cd",
		"escape":     "ab\x1bcd",
		"delete":     "ab\x7fcd",
		"no-break":   "ab cd",
		"line-sep":   "ab cd",
		"c1 control": "ab\u0085cd",
	}
	for name, key := range keys {
		for _, via := range []string{"env", "prompt"} {
			t.Run(name+"/"+via, func(t *testing.T) {
				r := newRig()
				if via == "env" {
					r.env.Getenv = func(string) string { return key }
				} else {
					r.env.ReadSecret = func(string) (string, error) { return key, nil }
				}
				err := r.run()
				if err == nil || err.Error() != "invalid key: contains whitespace or control characters" {
					t.Fatalf("err = %v", err)
				}
				for _, c := range r.calls {
					if strings.HasPrefix(c, "validate:") {
						t.Errorf("Validate was called for a malformed key: %q", r.calls)
					}
				}
				if len(r.sideEffects()) != 0 {
					t.Errorf("side effects: %q", r.sideEffects())
				}
				if strings.Contains(err.Error(), "ab") {
					t.Errorf("error repeats the key: %v", err)
				}
			})
		}
	}
}

// A failure at any step must stop setup there: nothing later may run.
func TestSetupStopsAtFirstFailure(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name     string
		break_   func(*rig)
		wantLast string // the last call that may have happened
		wantErr  string
	}{
		{"mkdir", func(r *rig) {
			r.env.MkdirAll = func(path string, perm os.FileMode) error {
				r.calls = append(r.calls, "mkdir:"+path)
				return boom
			}
		}, "mkdir:/etc/ostrakon", "create /etc/ostrakon: boom"},
		{"key file", func(r *rig) {
			r.env.WriteFile = func(path string, data []byte, perm os.FileMode) error {
				r.calls = append(r.calls, "write:"+path)
				return boom
			}
		}, "write:/etc/ostrakon/key", "write /etc/ostrakon/key: boom"},
		{"install", func(r *rig) {
			r.env.InstallBinary = func(dst string) error {
				r.calls = append(r.calls, "install:"+dst)
				return boom
			}
		}, "install:/usr/local/bin/ostrakon", "install /usr/local/bin/ostrakon: boom"},
		{"daemon-reload", func(r *rig) {
			r.env.Systemctl = func(args ...string) error {
				r.calls = append(r.calls, "systemctl:"+strings.Join(args, " "))
				return boom
			}
		}, "systemctl:daemon-reload", "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			tt.break_(r)
			err := r.run()
			if err == nil || err.Error() != tt.wantErr || !errors.Is(err, boom) {
				t.Fatalf("err = %v, want %q wrapping boom", err, tt.wantErr)
			}
			if last := r.calls[len(r.calls)-1]; last != tt.wantLast {
				t.Errorf("last call = %q, want %q (calls: %q)", last, tt.wantLast, r.calls)
			}
			if strings.Contains(r.out.String(), "Ostrakon is running") {
				t.Errorf("success message printed after a failure: %q", r.out.String())
			}
		})
	}
}

func TestSetupUnitWriteFailsBeforeSystemctl(t *testing.T) {
	r := newRig()
	r.env.WriteFile = func(path string, data []byte, perm os.FileMode) error {
		r.calls = append(r.calls, "write:"+path)
		if path == UnitPath {
			return fs.ErrPermission
		}
		return nil
	}
	err := r.run()
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want permission error", err)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "systemctl:") {
			t.Errorf("systemctl ran after the unit file failed: %q", r.calls)
		}
	}
}

func TestSetupEnableFailureIsReported(t *testing.T) {
	r := newRig()
	r.env.Systemctl = func(args ...string) error {
		r.calls = append(r.calls, "systemctl:"+strings.Join(args, " "))
		if args[0] == "enable" {
			return errors.New("Failed to enable unit")
		}
		return nil
	}
	err := r.run()
	if err == nil || !strings.Contains(err.Error(), "Failed to enable unit") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(r.out.String(), "Ostrakon is running") {
		t.Errorf("success message printed: %q", r.out.String())
	}
}

func contains(calls []string, prefix string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}
