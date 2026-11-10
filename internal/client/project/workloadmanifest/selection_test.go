package workloadmanifest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"

	"golang.org/x/sys/unix"
)

func selectionFixture(t *testing.T) (string, Manifest, func(Manifest)) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(directory, ".tnl", "generated")
	if err := os.MkdirAll(generated, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Schema: 1, Server: "https://control.example.test", Team: "team", ProjectKey: "project", SourceFingerprint: strings.Repeat("a", 64), ProjectLabel: "app", Services: map[string]string{"api": "http"}, Workloads: map[string]Workload{"job": {Provider: "github", Grants: config.ServiceVisitGrants("api"), MaxDurationSeconds: 3600, Acquisition: Acquisition{Method: "github-actions", Audience: "https://control.example.test"}}}}
	write := func(m Manifest) {
		t.Helper()
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(generated, Filename), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(manifest)
	return directory, manifest, write
}

func TestSelectionUsesOnlyOneGeneratedWorkload(t *testing.T) {
	directory, manifest, write := selectionFixture(t)
	for _, tc := range []struct {
		name       string
		configured string
		runtime    Runtime
		service    string
		want       error
	}{
		{"automatic", "", Runtime{GitHubActions: "true"}, "api", nil},
		{"configured", "job", Runtime{}, "api", nil},
		{"explicit", "", Runtime{Workload: new("job"), Vercel: "1", GitHubActions: "true"}, "api", nil},
		{"empty explicit", "job", Runtime{Workload: new("")}, "api", ErrRequired},
		{"no runtime", "", Runtime{}, "api", ErrRequired},
		{"ambiguous runtime", "", Runtime{GitHubActions: "true", Vercel: "1"}, "api", ErrRequired},
		{"different runtime", "", Runtime{Vercel: "1"}, "api", ErrRequired},
		{"configuration conflict", "job", Runtime{Workload: new("other")}, "api", ErrRequired},
		{"missing workload", "missing", Runtime{}, "api", ErrRequired},
		{"invalid workload", "../job", Runtime{}, "api", ErrRequired},
		{"unselected service", "job", Runtime{}, "other", ErrDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := Select(directory, tc.configured, tc.service, tc.runtime)
			if !errors.Is(err, tc.want) {
				t.Fatal("wrong selection result", err)
			}
			if err == nil && (selected.Name != "job" || selected.Directory != directory || selected.Path != filepath.Join(directory, ".tnl", "generated", Filename) || !fingerprint.MatchString(selected.Policy)) {
				t.Fatal("incomplete native selection")
			}
		})
	}
	first, err := Select(directory, "job", "api", Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	manifest.Workloads["other"] = manifest.Workloads["job"]
	write(manifest)
	if _, err := Select(directory, "", "api", Runtime{GitHubActions: "true"}); !errors.Is(err, ErrRequired) {
		t.Fatal("ambiguous workloads accepted", err)
	}
	next, err := Select(directory, "job", "api", Runtime{})
	if err != nil || next.Policy == first.Policy {
		t.Fatal("changed manifest was cached", err)
	}
	// invalid configuration and repository metadata are irrelevant at runtime.
	if err := os.WriteFile(filepath.Join(directory, "tnl.yml"), []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Select(directory, "job", "api", Runtime{}); err != nil {
		t.Fatal("selection consulted project configuration", err)
	}
}

func TestSelectionRejectsManifestSubstitutionAndBlockingFiles(t *testing.T) {
	directory, _, _ := selectionFixture(t)
	file := filepath.Join(directory, ".tnl", "generated", Filename)
	real := file + ".real"
	if err := os.Rename(file, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, file); err != nil {
		t.Fatal(err)
	}
	if _, err := Select(directory, "job", "api", Runtime{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("symlinked manifest accepted", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(file, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Select(directory, "job", "api", Runtime{}); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalid) {
			t.Fatal("FIFO manifest accepted", err)
		}
	case <-time.After(time.Second):
		fd, err := unix.Open(file, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		<-done
		t.Fatal("manifest selection blocked on FIFO")
	}
}

func TestManifestRejectsSDKInvalidShapes(t *testing.T) {
	for name, change := range map[string]func(*Manifest){
		"unknown service protocol": func(m *Manifest) { m.Services["extra"] = "unknown" },
		"invalid service name":     func(m *Manifest) { m.Services["../extra"] = "http" },
		"duplicate service": func(m *Manifest) {
			w := m.Workloads["job"]
			w.Grants = config.ServiceVisitGrants("api", "api")
			m.Workloads["job"] = w
		},
		"missing service": func(m *Manifest) { delete(m.Services, "api") },
		"wrong GitHub audience": func(m *Manifest) {
			w := m.Workloads["job"]
			w.Acquisition.Audience = "https://other.example"
			m.Workloads["job"] = w
		},
		"wrong Fly audience": func(m *Manifest) {
			w := m.Workloads["job"]
			w.Provider = "fly"
			w.Acquisition = Acquisition{Method: "fly-machine-api", Audience: "https://other.example/org"}
			m.Workloads["job"] = w
		},
		"unknown acquisition": func(m *Manifest) { w := m.Workloads["job"]; w.Acquisition.Method = "other"; m.Workloads["job"] = w },
	} {
		t.Run(name, func(t *testing.T) {
			directory, manifest, write := selectionFixture(t)
			change(&manifest)
			write(manifest)
			if _, err := Select(directory, "job", "api", Runtime{}); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid artifact accepted", err)
			}
		})
	}
}

func TestManifestProviderAcquisitionOwnership(t *testing.T) {
	for _, tc := range []struct {
		provider    string
		acquisition Acquisition
		valid       bool
	}{
		{"github", Acquisition{Method: "github-actions", Audience: "https://control.example.test"}, true},
		{"github", Acquisition{Method: "github-actions", Audience: "https://control.example.test", TokenFile: "token"}, false},
		{"github", Acquisition{Method: "token-file", Audience: "https://control.example.test", TokenFile: "token"}, true},
		{"github", Acquisition{Method: "token-env", Audience: "https://control.example.test", TokenEnv: "JOB_TOKEN"}, true},
		{"github", Acquisition{Method: "token-env", Audience: "wrong", TokenEnv: "JOB_TOKEN"}, false},
		{"vercel", Acquisition{Method: "vercel-oidc"}, true},
		{"vercel", Acquisition{Method: "vercel-oidc", Audience: "unexpected"}, false},
		{"vercel", Acquisition{Method: "vercel-oidc", TokenFile: "token"}, false},
		{"oidc", Acquisition{Method: "token-file", Audience: "audience", TokenFile: "token"}, true},
		{"oidc", Acquisition{Method: "token-file", Audience: "audience"}, false},
		{"oidc", Acquisition{Method: "callback", Audience: "audience"}, true},
		{"oidc", Acquisition{Method: "callback", Audience: "audience", TokenFile: "token"}, false},
		{"oidc", Acquisition{Method: "token-env", Audience: "audience", TokenEnv: "JOB_TOKEN"}, true},
		{"oidc", Acquisition{Method: "token-env", Audience: "audience", TokenEnv: "JOB=TOKEN"}, false},
		{"oidc", Acquisition{Method: "token-env", Audience: "audience", TokenEnv: "JOB_TOKEN", TokenFile: "token"}, false},
		{"oidc", Acquisition{Method: "token-file", TokenFile: "token"}, false},
	} {
		directory, m, write := selectionFixture(t)
		w := m.Workloads["job"]
		w.Provider, w.Acquisition = tc.provider, tc.acquisition
		m.Workloads["job"] = w
		write(m)
		_, err := Select(directory, "job", "api", Runtime{})
		if (err == nil) != tc.valid {
			t.Fatalf("%s/%s acquisition: %v", tc.provider, tc.acquisition.Method, err)
		}
	}
}
