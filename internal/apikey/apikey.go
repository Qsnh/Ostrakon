// Package apikey locates the Jev API key: the TYPESAFE_API_KEY environment
// variable first, then the key file written by `ostrakon setup`.
package apikey

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

const (
	// Path is where `ostrakon setup` stores the key (mode 0600).
	Path = "/etc/ostrakon/key"
	// EnvVar overrides the key file when set to a non-blank value.
	EnvVar = "TYPESAFE_API_KEY"
)

// ErrNoKey means neither the environment nor the key file yielded a key.
var ErrNoKey = errors.New("no Jev API key configured")

// Load returns the trimmed API key. A non-blank environment variable wins and
// the file is not read. A blank or missing key file yields ErrNoKey; any other
// read failure (for example permission denied) also wraps ErrNoKey, with the
// cause attached, so callers treat it like a missing key and the reason still
// shows up in logs.
func Load(getenv func(string) string, readFile func(string) ([]byte, error)) (string, error) {
	if k := strings.TrimSpace(getenv(EnvVar)); k != "" {
		return k, nil
	}
	data, err := readFile(Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrNoKey
		}
		return "", fmt.Errorf("%w: reading %s: %w", ErrNoKey, Path, err)
	}
	if k := strings.TrimSpace(string(data)); k != "" {
		return k, nil
	}
	return "", ErrNoKey
}

// Loader returns a function that calls Load against the real environment and
// filesystem on every invocation, so a rotated key is picked up without a
// restart.
func Loader() func() (string, error) {
	return func() (string, error) { return Load(os.Getenv, os.ReadFile) }
}
