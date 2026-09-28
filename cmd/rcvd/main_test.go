// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rcvd-dns/rcvd/internal/allowlist"
	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/logger"
)

// registerFlags mirrors the flag registrations at the top of main() onto a fresh
// FlagSet, so tests can enumerate the real flag surface without invoking main().
// Keep this in lockstep with main()'s flag block — the drift tests below exist to
// make an omission here (or in help/manpage) fail loudly rather than ship silently.
func registerFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("rcvd", flag.ContinueOnError)
	fs.String("config", "rcvd.toml", "")
	fs.Bool("version", false, "")
	fs.Bool("help", false, "")
	fs.Bool("stats", false, "")
	fs.Bool("audit", false, "")
	fs.Bool("blocklist-reload", false, "")
	fs.Bool("allowlist-reload", false, "")
	fs.Bool("verify-upstream", false, "")
	fs.Bool("verify-pin", false, "")
	fs.Int("show-pin", -1, "")
	fs.Bool("verify-self", false, "")
	fs.String("server-name", "", "")
	return fs
}

// TestHelpListsEveryFlag guards against the classic drift where a flag is added to
// main() but the hardcoded printHelp() text is not updated (help is a static string,
// not generated from the flagset). Every registered flag name must appear in help.
func TestHelpListsEveryFlag(t *testing.T) {
	help := captureHelp(t)
	registerFlags().VisitAll(func(f *flag.Flag) {
		if !strings.Contains(help, "-"+f.Name) {
			t.Errorf("printHelp() output is missing flag -%s", f.Name)
		}
	})
}

// TestManpageDocumentsActionFlags guards the manpage (man/rcvd.1.md) against the same
// drift for the operator-facing action flags. The .md is the source of truth the roff
// is generated from, so asserting against it catches an un-regenerated manpage too.
func TestManpageDocumentsActionFlags(t *testing.T) {
	md, err := os.ReadFile("../../man/rcvd.1.md")
	if err != nil {
		t.Fatalf("read manpage: %v", err)
	}
	page := string(md)
	for _, name := range []string{
		"-stats", "-audit", "-blocklist-reload", "-verify-upstream", "-verify-pin", "-show-pin",
		"-verify-self", "-server-name", "-version", "-help",
	} {
		if !strings.Contains(page, "**"+name+"**") {
			t.Errorf("man/rcvd.1.md is missing an entry for %s", name)
		}
	}
}

// captureHelp runs printHelp() with stdout redirected and returns what it printed.
func captureHelp(t *testing.T) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	printHelp()
	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read help: %v", err)
	}
	return buf.String()
}

func TestConfigHintPath(t *testing.T) {
	cases := []struct {
		name       string
		extra      string // the stray positional argument
		configPath string // the active -config value
		want       string
	}{
		{
			name:       "toml positional is echoed back (user meant it as the config)",
			extra:      "/etc/rcvd/rcvd.toml",
			configPath: "rcvd.toml",
			want:       "/etc/rcvd/rcvd.toml",
		},
		{
			name:       "non-toml positional falls back to the active -config value",
			extra:      "foo",
			configPath: "rcvd.toml",
			want:       "rcvd.toml",
		},
		{
			name:       "non-toml positional with a custom -config preserves the custom value",
			extra:      "garbage",
			configPath: "/etc/rcvd/custom.toml",
			want:       "/etc/rcvd/custom.toml",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := configHintPath(tc.extra, tc.configPath); got != tc.want {
				t.Errorf("configHintPath(%q, %q) = %q, want %q", tc.extra, tc.configPath, got, tc.want)
			}
		})
	}
}

// TestStartupAllowlistMissingFileFails exercises the fail-closed promise at
// startup via the testable helper loadAllowlistAtStartup: an enabled allowlist
// that points at a file which does not exist must surface an error so the
// caller can os.Exit(1). Without the synchronous-load step the daemon would
// silently fall through to a default-deny world that may or may not match the
// operator's intent — fail-closed is the only safe choice.
func TestStartupAllowlistMissingFileFails(t *testing.T) {
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "does-not-exist.txt")

	cfg := &config.Config{
		Allowlist: config.AllowlistConfig{
			Enabled: true,
			Mode:    "default-deny",
			Files:   []string{allowPath},
		},
	}
	discardLog := logger.New("info", io.Discard)
	al, err := loadAllowlistAtStartup(cfg, discardLog)
	if err == nil {
		t.Fatal("expected error for missing allowlist file, got nil")
	}
	if al != nil {
		t.Errorf("allowlist handle must be nil on failure, got %v", al)
	}
}

// TestStartupAllowlistEmptyFileFails covers the comments-only / whitespace-only
// case: an enabled allowlist that loads ZERO entries is just as dangerous as a
// missing file (it would silently deny the whole host's egress) and must fail
// at startup with an error wrapping allowlist.ErrEmptyAllowlist.
func TestStartupAllowlistEmptyFileFails(t *testing.T) {
	cases := map[string]string{
		"completely empty":  "",
		"only comments":     "# header\n# body\n",
		"only blank lines":  "\n\n   \n",
		"comments + blanks": "# header\n\n   \n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "allow.txt")
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			cfg := &config.Config{
				Allowlist: config.AllowlistConfig{
					Enabled: true,
					Mode:    "default-deny",
					Files:   []string{path},
				},
			}
			discardLog := logger.New("info", io.Discard)
			al, err := loadAllowlistAtStartup(cfg, discardLog)
			if err == nil {
				t.Fatal("expected error for empty allowlist, got nil")
			}
			if !errors.Is(err, allowlist.ErrEmptyAllowlist) {
				t.Errorf("error must wrap allowlist.ErrEmptyAllowlist, got: %v", err)
			}
			if al != nil {
				t.Errorf("allowlist handle must be nil on failure, got %v", al)
			}
		})
	}
}

// TestStartupAllowlistSuccess covers the happy path: enabled, valid file,
// non-empty result. Helper returns a non-nil allowlist handle whose Size
// matches the number of entries the file contained.
func TestStartupAllowlistSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	body := "example.com\nexample.net\n*.sub.example.org\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := &config.Config{
		Allowlist: config.AllowlistConfig{
			Enabled: true,
			Mode:    "default-deny",
			Files:   []string{path},
		},
	}
	discardLog := logger.New("info", io.Discard)
	al, err := loadAllowlistAtStartup(cfg, discardLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if al == nil {
		t.Fatal("allowlist handle must be non-nil on success")
	}
	if al.Size() != 3 {
		t.Errorf("Size: expected 3 entries (2 apex + 1 wildcard), got %d", al.Size())
	}
}

// TestStartupAllowlistDisabledReturnsNil verifies the disabled-off path: when
// the [allowlist] block is absent or enabled=false, the helper returns
// (nil, nil) so callers skip the SetPolicy step. This is the unchanged
// pre-feature behavior and must keep working byte-identically.
func TestStartupAllowlistDisabledReturnsNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rcvd-noallow.toml")
	body := `
[resolver]
enabled = true
listen = "127.0.0.1:5300"
[[upstreams]]
name = "T"
host = "1.1.1.1"
port = 853
doq = true
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.LoadForDiagnostics(path)
	if err != nil {
		t.Fatalf("config load: %v", err)
	}
	discardLog := logger.New("info", io.Discard)
	al, err := loadAllowlistAtStartup(cfg, discardLog)
	if err != nil {
		t.Errorf("disabled allowlist: expected no error, got: %v", err)
	}
	if al != nil {
		t.Errorf("disabled allowlist: expected nil handle, got: %v", al)
	}
}

// TestStartupAllowlistMode2OnlyAccepted covers the same startup path from the
// config side: a Mode-2-only deployment with allowlist enabled must validate
// (the shared policy wires allowlist enforcement into Mode 2; the earlier
// "Mode 2 not enforced yet" guard is no longer needed).
func TestStartupAllowlistMode2OnlyAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rcvd-mode2only.toml")
	body := `
[resolver]
enabled = false
[upstream_service]
enabled = true
listen_doq = "127.0.0.1:8853"
tls_cert_autogen = true
[[upstreams]]
name = "T"
host = "1.1.1.1"
port = 853
doq = true
[allowlist]
enabled = true
mode = "default-deny"
files = ["` + filepath.Join(dir, "allow.txt") + `"]
`
	if err := os.WriteFile(filepath.Join(dir, "allow.txt"), []byte("example.com\n"), 0644); err != nil {
		t.Fatalf("write allow file: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := config.LoadForDiagnostics(path); err != nil {
		t.Errorf("mode-2-only + allowlist should validate now, got: %v", err)
	}
}
