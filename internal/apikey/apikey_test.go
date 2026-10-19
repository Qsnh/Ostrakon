package apikey

import (
	"errors"
	"io/fs"
	"testing"
)

func TestLoad(t *testing.T) {
	permErr := &fs.PathError{Op: "open", Path: Path, Err: fs.ErrPermission}

	tests := []struct {
		name     string
		env      string
		file     string
		fileErr  error
		want     string
		wantErr  error // matched with errors.Is
		extraErr error // also expected in the chain
		wantRead bool
	}{
		{name: "env wins and is trimmed", env: "  k1 \n", file: "ignored\n", want: "k1"},
		{name: "env empty falls back to file", env: "", file: "k2\n", want: "k2", wantRead: true},
		{name: "env whitespace only falls back to file", env: " \t\n", file: "k3\n", want: "k3", wantRead: true},
		{name: "file is trimmed", env: "", file: " \n k4 \r\n\n", want: "k4", wantRead: true},
		{name: "both empty", env: "", file: "", wantErr: ErrNoKey, wantRead: true},
		{name: "file whitespace only", env: "", file: " \n\t\n", wantErr: ErrNoKey, wantRead: true},
		{name: "file missing", env: "", fileErr: fs.ErrNotExist, wantErr: ErrNoKey, wantRead: true},
		{name: "file unreadable still means no key", env: "", fileErr: permErr, wantErr: ErrNoKey, extraErr: fs.ErrPermission, wantRead: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var readPath string
			reads := 0
			getenv := func(k string) string {
				if k != EnvVar {
					t.Errorf("getenv(%q), want only %q", k, EnvVar)
				}
				return tt.env
			}
			readFile := func(p string) ([]byte, error) {
				reads++
				readPath = p
				if tt.fileErr != nil {
					return nil, tt.fileErr
				}
				return []byte(tt.file), nil
			}

			got, err := Load(getenv, readFile)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want errors.Is %v", err, tt.wantErr)
				}
				if tt.extraErr != nil && !errors.Is(err, tt.extraErr) {
					t.Errorf("err = %v, want it to also wrap %v", err, tt.extraErr)
				}
				if got != "" {
					t.Errorf("key = %q, want empty on error", got)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("key = %q, want %q", got, tt.want)
				}
			}

			if tt.wantRead {
				if reads != 1 || readPath != Path {
					t.Errorf("readFile calls = %d (path %q), want exactly one read of %q", reads, readPath, Path)
				}
			} else if reads != 0 {
				t.Errorf("readFile called %d times, want 0 when the env var is set", reads)
			}
		})
	}
}

func TestLoaderReadsEnvEachCall(t *testing.T) {
	load := Loader()

	t.Setenv(EnvVar, "  first \n")
	got, err := load()
	if err != nil || got != "first" {
		t.Fatalf("first load = %q, %v; want %q, nil", got, err, "first")
	}

	// Keys may be rotated without restarting the process.
	t.Setenv(EnvVar, "second")
	got, err = load()
	if err != nil || got != "second" {
		t.Fatalf("second load = %q, %v; want %q, nil", got, err, "second")
	}
}
