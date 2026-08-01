// SPDX-License-Identifier: MIT
package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestNoDeadTOMLFields guards against "advertised config that does nothing" — a
// toml:-tagged field that is declared in config.go but wired up NOWHERE else. Such
// fields are a credibility footgun (an operator sets a key that silently has no
// effect), and this project has been burned by them before (pinned_pubkey was a dead
// stub; quic_0rtt was a dead privacy knob — both resolved). This test fails if any
// toml field is referenced only inside config.go, so dead wiring cannot recreep.
//
// Intentionally-inert fields are RESERVED forward declarations paired with deferred
// features; list them in reservedFields with the reason. Adding a field here is a
// deliberate act (it must also carry a `// RESERVED — …` comment on the struct field),
// NOT a way to silence the test for a genuinely dead knob — wire it or delete it.
func TestNoDeadTOMLFields(t *testing.T) {
	// RESERVED fields: declared now, honestly no-op until their parent feature lands.
	// key = toml tag name.
	reservedFields := map[string]string{
		"prefetch":                 "cache prefetch not yet implemented (no-op)",
		"update_interval":          "periodic/SIGHUP blocklist reload deferred",
		"phase2_slow_threshold_ms": "StateSLOW threshold not yet wired into NewFallbackResolver",
		"phase1_timeout_ms":        "NewFallbackResolver takes phase1_duration_s, not a phase-1 timeout",
		"metrics":                  "Prometheus endpoint deferred (internal/metrics not built)",
	}

	fset := token.NewFileSet()
	configFile, err := parser.ParseFile(fset, "config.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}

	// Collect every Go field name that carries a toml:"..." tag (skipping "-").
	type tomlField struct {
		goName  string // Go identifier, e.g. "QUIC0RTT"
		tomlTag string // toml key, e.g. "quic_0rtt"
	}
	var fields []tomlField
	ast.Inspect(configFile, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		for _, f := range st.Fields.List {
			if f.Tag == nil || len(f.Names) == 0 {
				continue
			}
			tag, err := strconv.Unquote(f.Tag.Value)
			if err != nil {
				continue
			}
			tomlTag := reflect.StructTag(tag).Get("toml")
			tomlTag = strings.Split(tomlTag, ",")[0] // drop ",omitempty" etc.
			if tomlTag == "" || tomlTag == "-" {
				continue
			}
			fields = append(fields, tomlField{goName: f.Names[0].Name, tomlTag: tomlTag})
		}
		return true
	})
	if len(fields) == 0 {
		t.Fatal("found no toml-tagged fields in config.go — parser regression?")
	}

	// Gather the text of every non-test .go file in the WHOLE module (INCLUDING
	// config.go), to count where each field's Go name appears. A field is "wired"
	// if it is referenced ANYWHERE beyond its single declaration site — which
	// includes config-package logic itself (e.g. the dns_api_token_* fields are
	// materialized by resolveDNSAPIToken inside config.go — real work, not dead).
	// So the rule is: a toml field whose Go name occurs exactly ONCE across the
	// module (only the struct declaration) is dead. Fields read via a selector in
	// another package (cfg.Resolver, up.Host) trivially exceed one occurrence.
	moduleSrc, err := moduleSource(t)
	if err != nil {
		t.Fatalf("read module source: %v", err)
	}

	for _, f := range fields {
		occurrences := countIdent(moduleSrc, f.goName)
		if _, reserved := reservedFields[f.tomlTag]; reserved {
			// A RESERVED field is allowed to be declaration-only, but it MUST carry
			// an honest "// RESERVED — …" marker on its struct field so a reader
			// knows it is inert. And if it turns out to be wired after all, drop it
			// from the allowlist (keeps the list honest).
			if !fieldHasReservedComment(configSource(t), f.goName) {
				t.Errorf("field %q (Go: %s) is in reservedFields but lacks a `// RESERVED — …` comment on its struct field",
					f.tomlTag, f.goName)
			}
			continue
		}
		if occurrences <= 1 {
			t.Errorf("dead config field: %q (Go: %s) is toml-tagged but referenced NOWHERE beyond its declaration — "+
				"wire it up, delete it, or add it to reservedFields with a `// RESERVED — …` comment", f.tomlTag, f.goName)
		}
	}
}

// countIdent counts occurrences of ident as a whole-word identifier in src.
func countIdent(src, ident string) int {
	n := 0
	for i := 0; ; {
		j := strings.Index(src[i:], ident)
		if j < 0 {
			break
		}
		pos := i + j
		before := pos == 0 || !isIdentByte(src[pos-1])
		afterPos := pos + len(ident)
		after := afterPos >= len(src) || !isIdentByte(src[afterPos])
		if before && after {
			n++
		}
		i = pos + len(ident)
	}
	return n
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// fieldHasReservedComment reports whether the struct-field line declaring goName
// carries a "RESERVED" marker comment.
func fieldHasReservedComment(configSrc, goName string) bool {
	for _, line := range strings.Split(configSrc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), goName+" ") && strings.Contains(line, "RESERVED") {
			return true
		}
	}
	return false
}

// moduleSource walks the module tree (rooted two levels up from internal/config)
// and concatenates every non-test .go file. Vendored/hidden dirs are skipped. This
// gives the full set of sites where a config field could be referenced, INCLUDING
// config.go itself (config-package logic can legitimately consume a field).
func moduleSource(t *testing.T) (string, error) {
	t.Helper()
	// internal/config → module root is two levels up.
	root := filepath.Join("..", "..")

	var b strings.Builder
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil // never skip the walk root (its base name may be "..")
			}
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		if !strings.HasSuffix(base, ".go") || strings.HasSuffix(base, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func configSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	return string(data)
}
