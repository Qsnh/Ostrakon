// Package setup implements `ostrakon setup`: it checks and saves the Jev API
// key, installs the binary and a systemd unit, and starts the service. All
// interaction with the machine goes through Env so that tests run without
// root, without a network and without touching the filesystem.
package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"ostrakon/internal/apikey"
	"ostrakon/internal/source"
)

const (
	// BinaryPath is where setup installs the executable.
	BinaryPath = "/usr/local/bin/ostrakon"
	// UnitPath is where setup installs the systemd unit.
	UnitPath = "/etc/systemd/system/ostrakon.service"

	keyPrompt = "Jev API key: "
)

// Env is everything Run needs from the machine it runs on.
type Env struct {
	Out    io.Writer
	Getenv func(string) string
	// ReadSecret asks the user for a line without echoing it. The real
	// implementation uses golang.org/x/term.ReadPassword.
	ReadSecret func(prompt string) (string, error)
	// Validate checks that key is accepted by Jev.
	Validate func(ctx context.Context, key string) error
	IsRoot   func() bool
	HaveNFT  func() bool
	Discover func() []source.Spec
	MkdirAll func(path string, perm os.FileMode) error
	// WriteFile replaces the file at path with data, creating it with perm.
	WriteFile func(path string, data []byte, perm os.FileMode) error
	// InstallBinary copies the running executable to dst with mode 0755. It
	// does nothing when the running executable already is dst.
	InstallBinary func(dst string) error
	Systemctl     func(args ...string) error
}

// Unit returns the systemd unit file text.
func Unit() string {
	return `[Unit]
Description=Ostrakon brute-force protection
After=network-online.target nftables.service time-sync.target
Wants=network-online.target

[Service]
ExecStart=` + BinaryPath + ` run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`
}

// Run performs the setup. Nothing is written until the key has been accepted
// by Jev. Errors are meant to be shown to the administrator as they are.
func Run(ctx context.Context, env Env) error {
	if !env.IsRoot() {
		return errors.New("setup must run as root")
	}
	if !env.HaveNFT() {
		return errors.New("nftables (nft) is required but was not found")
	}

	key, err := obtainKey(env)
	if err != nil {
		return err
	}
	if err := env.Validate(ctx, key); err != nil {
		return fmt.Errorf("Jev key check failed: %w", err)
	}

	// The service does not see the caller's environment, so the key is saved
	// to the key file even when it came from TYPESAFE_API_KEY.
	dir := filepath.Dir(apikey.Path)
	if err := env.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := env.WriteFile(apikey.Path, []byte(key+"\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", apikey.Path, err)
	}

	printSources(env.Out, env.Discover())

	if err := env.InstallBinary(BinaryPath); err != nil {
		return fmt.Errorf("install %s: %w", BinaryPath, err)
	}
	if err := env.WriteFile(UnitPath, []byte(Unit()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", UnitPath, err)
	}
	if err := env.Systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := env.Systemctl("enable", "--now", "ostrakon"); err != nil {
		return err
	}
	fmt.Fprintln(env.Out, "Ostrakon is running. Check with: ostrakon status")
	return nil
}

// obtainKey returns the API key from the environment or, failing that, from
// the prompt, trimmed and checked for stray characters. The key never appears
// in the errors.
func obtainKey(env Env) (string, error) {
	key := strings.TrimSpace(env.Getenv(apikey.EnvVar))
	if key == "" {
		answer, err := env.ReadSecret(keyPrompt)
		if err != nil {
			return "", fmt.Errorf("read the key: %w", err)
		}
		key = strings.TrimSpace(answer)
	}
	if key == "" {
		return "", errors.New("no key given")
	}
	// A key with a space or newline inside would be rejected by Jev with a
	// confusing message, or worse, split the key file into several lines.
	if strings.IndexFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("invalid key: contains whitespace or control characters")
	}
	return key, nil
}

// printSources lists the log sources found, or warns that there are none.
func printSources(w io.Writer, specs []source.Spec) {
	if len(specs) == 0 {
		fmt.Fprintln(w, "warning: no supported logs found (sshd / nginx)")
		return
	}
	for _, s := range specs {
		where := s.Path
		if where == "" {
			where = "journald"
		}
		fmt.Fprintf(w, "  - %s: %s\n", s.Name, where)
	}
}
