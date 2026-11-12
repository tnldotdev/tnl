package daemon

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

type dependencyMatch struct {
	path    string
	subtree bool
}

func dependencyExact(path string) dependencyMatch { return dependencyMatch{path: path} }
func dependencyTree(path string) dependencyMatch {
	return dependencyMatch{path: path, subtree: true}
}

func (m dependencyMatch) matches(pkg string) bool {
	return pkg == m.path || m.subtree && strings.HasPrefix(pkg, m.path+"/")
}

type dependencyRule struct {
	owner     dependencyMatch
	forbidden []dependencyMatch
	reason    string
}

var dependencyRules = []dependencyRule{
	{
		owner:     dependencyTree("internal/client"),
		forbidden: []dependencyMatch{dependencyTree("internal/publisher"), dependencyTree("internal/connector"), dependencyTree("internal/installed"), dependencyTree("internal/daemon")},
		reason:    "client facilities must not depend on process owners",
	},
	{
		owner:     dependencyTree("internal/control/state"),
		forbidden: []dependencyMatch{dependencyTree("cmd"), dependencyTree("internal/control/api"), dependencyExact("internal/control/certificates"), dependencyExact("internal/control/dns"), dependencyExact("internal/control/email"), dependencyTree("internal/ingress"), dependencyTree("internal/relay"), dependencyTree("internal/daemon")},
		reason:    "control state must not depend on HTTP handlers, work executors, or process owners",
	},
	{
		owner:     dependencyTree("internal/ingress"),
		forbidden: []dependencyMatch{dependencyTree("internal/control/state"), dependencyTree("internal/control/api"), dependencyTree("internal/daemon")},
		reason:    "ingress must use control contracts, not control state, handlers, or daemon composition",
	},
	{
		owner:     dependencyTree("internal/relay"),
		forbidden: []dependencyMatch{dependencyTree("internal/control/state"), dependencyTree("internal/control/api"), dependencyTree("internal/daemon")},
		reason:    "relay must use control contracts, not control state, handlers, or daemon composition",
	},
	{
		owner:     dependencyTree("internal/transport"),
		forbidden: []dependencyMatch{dependencyTree("cmd"), dependencyTree("internal/publisher"), dependencyTree("internal/connector"), dependencyTree("internal/installed"), dependencyTree("internal/control"), dependencyTree("internal/ingress"), dependencyTree("internal/relay"), dependencyTree("internal/daemon")},
		reason:    "transport mechanics must not depend on command or process owners",
	},
	{
		owner:     dependencyTree("internal/publisher/service"),
		forbidden: []dependencyMatch{dependencyExact("internal/publisher")},
		reason:    "service owners must not call back into publisher orchestration",
	},
	{
		owner:     dependencyTree("internal/publisher/service/stream"),
		forbidden: []dependencyMatch{dependencyExact("internal/publisher/service")},
		reason:    "service stream mechanics must not call back into service orchestration",
	},
	{
		owner:     dependencyTree("internal/publisher/httpaccess"),
		forbidden: []dependencyMatch{dependencyExact("internal/publisher"), dependencyExact("internal/publisher/service"), dependencyTree("cmd"), dependencyTree("internal/installed"), dependencyTree("internal/daemon")},
		reason:    "shared visitor HTTP mechanics must not depend on run or process orchestration",
	},
	{
		owner:     dependencyTree("internal/publisher/requestlimit"),
		forbidden: []dependencyMatch{dependencyExact("internal/publisher"), dependencyExact("internal/publisher/service"), dependencyTree("cmd"), dependencyTree("internal/installed"), dependencyTree("internal/daemon")},
		reason:    "shared request budgets must not depend on run or process orchestration",
	},
	{
		owner:     dependencyTree("internal/publisher/localapi"),
		forbidden: []dependencyMatch{dependencyExact("internal/publisher/local")},
		reason:    "the local API must not call back into its process owner",
	},
	{
		owner:     dependencyTree("internal/connector/stream"),
		forbidden: []dependencyMatch{dependencyExact("internal/connector")},
		reason:    "connector stream mechanics must not call back into connector operations",
	},
	{
		owner:     dependencyTree("internal/connector/runtime"),
		forbidden: []dependencyMatch{dependencyExact("internal/connector")},
		reason:    "connector runtime must not call back into connector operations",
	},
}

func forbiddenDependency(owner, imported string) *dependencyRule {
	for i := range dependencyRules {
		rule := &dependencyRules[i]
		if !rule.owner.matches(owner) {
			continue
		}
		for _, forbidden := range rule.forbidden {
			if forbidden.matches(imported) {
				return rule
			}
		}
	}
	return nil
}

func TestDependencyMatch(t *testing.T) {
	for _, test := range []struct {
		name    string
		match   dependencyMatch
		pkg     string
		matches bool
	}{
		{"exact package", dependencyExact("internal/connector"), "internal/connector", true},
		{"exact excludes children", dependencyExact("internal/connector"), "internal/connector/runtime", false},
		{"tree includes root", dependencyTree("internal/client"), "internal/client", true},
		{"tree includes descendants", dependencyTree("internal/client"), "internal/client/project/resolve", true},
		{"tree excludes siblings", dependencyTree("internal/client"), "internal/clientextra", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.match.matches(test.pkg); got != test.matches {
				t.Fatalf("matches(%q) = %v, want %v", test.pkg, got, test.matches)
			}
		})
	}
}

func TestPackageDependencyRules(t *testing.T) {
	for _, test := range []struct {
		owner, imported string
		forbidden       bool
	}{
		{"internal/client", "internal/publisher", true},
		{"internal/client/auth", "internal/publisher/identity", true},
		{"internal/client/project", "internal/installed", true},
		{"internal/client/project", "internal/connector/runtime", true},
		{"internal/client/project", "internal/daemon/config", true},
		{"internal/client/auth", "internal/security/certificateidentity", false},
		{"internal/installed", "internal/publisher", false},
		{"internal/control/state", "cmd/tnld", true},
		{"internal/control/state/controlstatedb", "internal/control/api/public", true},
		{"internal/control/state", "internal/control/certificates", true},
		{"internal/control/state", "internal/control/dns", true},
		{"internal/control/state", "internal/control/email", true},
		{"internal/control/state", "internal/control/certificates/visitor", false},
		{"internal/control/state", "internal/ingress", true},
		{"internal/control/state", "internal/relay", true},
		{"internal/control/state", "internal/daemon", true},
		{"internal/control/state", "internal/naming/ingresspool", false},
		{"internal/ingress", "internal/control/state/controlstatedb", true},
		{"internal/relay", "internal/control/api/private/relay", true},
		{"internal/relay", "internal/control/state/controlstatedb", true},
		{"internal/relay", "pkg/api/control/private/relay", false},
		{"internal/transport/muxsession", "internal/publisher/target", true},
		{"internal/transport/muxsession", "cmd/tnl", true},
		{"internal/transport", "internal/control/proxy", true},
		{"internal/transport", "internal/ingress", true},
		{"internal/transport", "internal/relay", true},
		{"internal/transport/muxsession", "internal/security", false},
		{"internal/publisher/service", "internal/publisher", true},
		{"internal/publisher/service", "internal/publisher/target", false},
		{"internal/publisher/service/stream", "internal/publisher", true},
		{"internal/publisher/service/stream", "internal/publisher/service", true},
		{"internal/publisher/service/stream", "internal/publisher/target/kubernetes", false},
		{"internal/publisher/httpaccess", "internal/publisher", true},
		{"internal/publisher/httpaccess", "internal/publisher/service", true},
		{"internal/publisher/httpaccess", "internal/publisher/proxy", false},
		{"internal/publisher/httpaccess", "internal/policy/visitorlease", false},
		{"internal/publisher/requestlimit", "internal/publisher", true},
		{"internal/publisher/requestlimit", "internal/publisher/service", true},
		{"internal/publisher/requestlimit", "internal/installed", true},
		{"internal/publisher/requestlimit", "internal/daemon", true},
		{"internal/publisher/requestlimit", "cmd/tnl", true},
		{"internal/publisher/requestlimit", "internal/policy/applicationlimits", false},
		{"internal/publisher/localapi", "internal/publisher/local", true},
		{"internal/publisher/localapi", "internal/publisher/app", false},
		{"internal/connector/stream", "internal/connector", true},
		{"internal/connector/stream", "internal/connector/runtime", false},
		{"internal/connector/runtime", "internal/connector", true},
		{"internal/connector/runtime", "internal/connector/stream", false},
		{"internal/clientextra", "internal/publisher", false},
		{"internal/client", "internal/publisherextra", false},
	} {
		t.Run(test.owner+"->"+test.imported, func(t *testing.T) {
			if got := forbiddenDependency(test.owner, test.imported) != nil; got != test.forbidden {
				t.Fatalf("forbidden = %v, want %v", got, test.forbidden)
			}
		})
	}
}

// scan source rather than host-compiled imports so platform and build tags cannot
// hide a production dependency. generated code has the same ownership rules.
func scanPackageDependencies(source fs.FS) ([]string, error) {
	var violations []string
	err := fs.WalkDir(source, ".", func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if filename != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || entry.IsDir() && name == "testdata") {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if filename != "." && !strings.Contains(filename, "/") && filename != "cmd" && filename != "internal" && filename != "pkg" {
				return fs.SkipDir
			}
			return nil
		}
		// tests and their testdata may compose owners without becoming dependencies
		// of the production package.
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(source, filename)
		if err != nil {
			return err
		}
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, filename, data, parser.ImportsOnly)
		if err != nil {
			return err
		}
		owner := path.Dir(filename)
		for _, spec := range file.Imports {
			value, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: invalid import: %w", filename, err)
			}
			imported, local := strings.CutPrefix(value, "github.com/tnldotdev/tnl/")
			if local {
				if rule := forbiddenDependency(owner, imported); rule != nil {
					violations = append(violations, fmt.Sprintf("%s: %s imports %s; %s", positions.Position(spec.Pos()), owner, imported, rule.reason))
				}
			}
		}
		return nil
	})
	return violations, err
}

func TestPackageDependencyScanner(t *testing.T) {
	source := fstest.MapFS{
		"internal/client/allowed.go":       {Data: []byte("package client\nimport _ \"github.com/tnldotdev/tnl/internal/security\"\n")},
		"internal/client/linux_linux.go":   {Data: []byte("//go:build linux\n\npackage client\nimport _ \"github.com/tnldotdev/tnl/internal/publisher\"\n")},
		"internal/client/windows.go":       {Data: []byte("//go:build windows && custom\n\npackage client\nimport _ \"github.com/tnldotdev/tnl/internal/connector\"\n")},
		"internal/client/model.gen.go":     {Data: []byte("// Code generated by fixture. DO NOT EDIT.\npackage client\nimport _ \"github.com/tnldotdev/tnl/internal/installed\"\n")},
		"internal/client/compose_test.go":  {Data: []byte("package client_test\nimport _ \"github.com/tnldotdev/tnl/internal/publisher\"\n")},
		"internal/client/local_test.go":    {Data: []byte("package client\nimport _ \"github.com/tnldotdev/tnl/internal/publisher\"\n")},
		"internal/client/external.go":      {Data: []byte("package client\nimport _ \"example.com/tnl/internal/publisher\"\nimport _ \"github.com/tnldotdev/tnl-extra/internal/publisher\"\n")},
		"internal/client/_ignored.go":      {Data: []byte("not go source")},
		"internal/client/.ignored.go":      {Data: []byte("not go source")},
		"internal/client/testdata/main.go": {Data: []byte("not go source")},
		"internal/installed/compose.go":    {Data: []byte("package installed\nimport _ \"github.com/tnldotdev/tnl/internal/publisher\"\n")},
		"cmd/tnl/main.go":                  {Data: []byte("package main\nimport _ \"github.com/tnldotdev/tnl/internal/publisher\"\n")},
		"tools/fixture/main.go":            {Data: []byte("not go source")},
	}
	violations, err := scanPackageDependencies(source)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/client/linux_linux.go:4:8: internal/client imports internal/publisher; client facilities must not depend on process owners",
		"internal/client/model.gen.go:3:8: internal/client imports internal/installed; client facilities must not depend on process owners",
		"internal/client/windows.go:4:8: internal/client imports internal/connector; client facilities must not depend on process owners",
	}
	if strings.Join(violations, "\n") != strings.Join(want, "\n") {
		t.Fatalf("violations:\n%s\nwant:\n%s", strings.Join(violations, "\n"), strings.Join(want, "\n"))
	}
}

func TestPackageDependencyScannerInvalidSource(t *testing.T) {
	_, err := scanPackageDependencies(fstest.MapFS{
		"internal/client/broken.go": {Data: []byte("package client\nimport \"unfinished")},
	})
	if err == nil || !strings.Contains(err.Error(), "internal/client/broken.go") {
		t.Fatalf("expected parse error with source path, got %v", err)
	}
}

func TestPackageDependencies(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	violations, err := scanPackageDependencies(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, violation := range violations {
		t.Error(violation)
	}
}
