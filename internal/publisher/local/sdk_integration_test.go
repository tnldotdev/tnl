package local

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationSDKApplicationPublicationTraffic(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, mode := range []string{"prepare", "publish", "fetch", "python-prepare", "python-publish"} {
		t.Run(mode, func(t *testing.T) {
			if !testutil.IsolatedPublishingTest(t) {
				return
			}
			release := make(chan struct{})
			prepared := strings.HasSuffix(mode, "prepare")
			ready := sync.OnceFunc(func() { close(release) })
			defer ready()
			var joined atomic.Int32
			a, _, _, fixture, document, saved := applicationInvocation(t, testutil.PublishingHooks{
				Ready: func(ctx context.Context, _ controlv1.PublishRunSetup) error {
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				},
				Close: func(controlv1.PublishRunSetup) error { joined.Add(1); return nil },
			})
			a.workers.HTTPTransport = fixture
			_, source, _, _ := runtime.Caller(0)
			repo := filepath.Clean(filepath.Join(filepath.Dir(source), "../../.."))
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			credential := filepath.Join(root, "application.json")
			if err := credentialfile.Write(credential, document); err != nil {
				t.Fatal(err)
			}
			launcher, err := os.ReadFile(filepath.Join(repo, "packages/ts/test/fixtures/publication-native.ts"))
			if err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(root, "native.ts")
			if err := os.WriteFile(binary, launcher, 0700); err != nil {
				t.Fatal(err)
			}
			endpoint, err := json.Marshal(a.capabilities.Owner())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(binary+".json", endpoint, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"type":"module"}`), 0600); err != nil {
				t.Fatal(err)
			}
			manifest, err := os.ReadFile(filepath.Join(repo, "packages/ts/package.json"))
			if err != nil {
				t.Fatal(err)
			}
			var sdk struct {
				Version string `json:"version"`
			}
			if err := json.Unmarshal(manifest, &sdk); err != nil {
				t.Fatal(err)
			}
			arch := runtime.GOARCH
			if arch == "amd64" {
				arch = "x64"
			}
			name := fmt.Sprintf("tnl-%s-%s", runtime.GOOS, arch)
			artifact := filepath.Join(root, "node_modules", "@tnldotdev", name)
			if err := os.MkdirAll(filepath.Join(artifact, "bin"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(artifact, "package.json"), fmt.Appendf(nil, `{"name":"@tnldotdev/%s","version":%q}`, name, sdk.Version), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(binary, filepath.Join(artifact, "bin", "tnl")); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), "node", filepath.Join(repo, "packages/ts/test/fixtures/publication-runtime.ts"), credential, saved.Id, mode, binary)
			if strings.HasPrefix(mode, "python-") {
				command = exec.CommandContext(t.Context(), filepath.Join(repo, "packages/py/.venv/bin/python"), filepath.Join(repo, "packages/py/tests/application_publication_native.py"), credential, saved.Id, binary, mode)
			}
			command.Dir = root
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "TNL_") && !strings.HasPrefix(entry, "NODE_PATH=") && !strings.HasPrefix(entry, "PYTHONPATH=") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, "NODE_PATH="+filepath.Join(root, "node_modules"), "PYTHONPATH="+filepath.Join(repo, "packages/py/src"), "TNL_PUBLISHER_CREDENTIAL_FILE=/private/must-not-read.json")
			var diagnostics bytes.Buffer
			command.Stderr = &diagnostics
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			input, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			waited := false
			t.Cleanup(func() {
				_ = input.Close()
				if !waited {
					_ = command.Process.Kill()
					<-done
				}
				if t.Failed() {
					t.Logf("SDK diagnostics: %s", diagnostics.String())
				}
			})
			lines := make(chan string, 16)
			go func() {
				defer func() { close(lines); done <- command.Wait() }()
				scanner := bufio.NewScanner(output)
				for scanner.Scan() {
					select {
					case lines <- scanner.Text():
					case <-t.Context().Done():
						return
					}
				}
			}()
			expect := func(want string) {
				t.Helper()
				select {
				case got := <-lines:
					if got != want {
						t.Fatalf("SDK phase=%q, want %q", got, want)
					}
				case <-time.After(20 * time.Second):
					t.Fatalf("SDK did not reach %s", want)
				}
			}
			send := func(value string) {
				t.Helper()
				if _, err := fmt.Fprintln(input, value); err != nil {
					t.Fatal(err)
				}
			}
			before := fixture.Enrollments.Load()
			address := "https://" + saved.CanonicalHostname
			if prepared {
				expect("prepared " + address)
				if fixture.Runs.Load() != 0 {
					t.Fatal("unbound SDK preparation started a publish run")
				}
				send("bind")
			}
			expect("starting")
			waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
				for _, service := range snapshot.Services {
					if service.Registered {
						return !service.Routable && service.Target != ""
					}
				}
				return false
			})
			if prepared {
				expect("bound")
			}
			ready()
			if prepared {
				send("ready")
			}
			expect("ready " + address)
			visit := func(want string) {
				t.Helper()
				status, body, err := fixture.Visit(t.Context(), address)
				if err != nil || status != http.StatusOK || string(body) != want {
					t.Fatalf("SDK visitor bytes: status=%d body=%q err=%v", status, body, err)
				}
			}
			visit("first SDK listener")
			send("visit")
			if prepared {
				expect("replaced")
				visit("replacement SDK listener")
				send("visit")
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, address+"/held", nil)
			if err != nil {
				t.Fatal(err)
			}
			held, err := fixture.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Body.Close()
			prefix := make([]byte, len("held prefix"))
			if _, err := io.ReadFull(held.Body, prefix); err != nil || string(prefix) != "held prefix" {
				t.Fatal("SDK did not stream visitor response prefix", err)
			}
			send("close")
			expect("closing")
			waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
				for _, service := range snapshot.Services {
					if service.Registered {
						return false
					}
				}
				return true
			})
			send("release")
			suffix, err := io.ReadAll(held.Body)
			if err != nil || string(suffix) != " held suffix" {
				t.Fatal("SDK cleanup did not drain original response", err)
			}
			if err := held.Body.Close(); err != nil {
				t.Fatal(err)
			}
			expect("closed")
			if err := <-done; err != nil {
				waited = true
				t.Fatal("SDK publication failed", err)
			}
			waited = true
			for _, service := range a.manager.Snapshot().Services {
				if service.Registered {
					t.Fatal("SDK cleanup retained a registered publication")
				}
			}
			wantRuns := int32(1)
			if prepared {
				wantRuns = 2
			}
			if fixture.Runs.Load() != wantRuns || joined.Load() != wantRuns || fixture.Allocations.Load() != 0 || fixture.Deletions.Load() != 0 || fixture.Enrollments.Load() != before {
				t.Fatalf("SDK changed saved URL lifecycle: runs=%d joined=%d allocated=%d deleted=%d enrolled=%d", fixture.Runs.Load(), joined.Load(), fixture.Allocations.Load(), fixture.Deletions.Load(), fixture.Enrollments.Load()-before)
			}
		})
	}
}
