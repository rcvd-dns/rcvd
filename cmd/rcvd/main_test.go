// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
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
