package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherlocal "github.com/tnldotdev/tnl/internal/publisher/local"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// only socket addressing and fixture trust are attached in process. all SDK
// calls cross real private IPC; control authorizes the registered signing key.
func TestIntegrationDeploymentSDKPublication(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	testutil.UseClientKeychain(t)
	f := newSplitPublishFixture(t, "sdk-publication")
	repo, directory := integrationRepositoryRoot(t), t.TempDir()
	binary := filepath.Join(directory, "tnl")
	buildIntegrationBinary(t, repo, binary, "./cmd/tnl")
	installPublicationSDKs(t, repo, directory, binary)
	if err := os.WriteFile(filepath.Join(directory, "tnl.config.ts"), []byte(`throw new Error("remote publication evaluated configuration")`), 0600); err != nil {
		t.Fatal(err)
	}
	mode, restricted, protocol := controlv1.Anonymous, controlv1.Restricted, controlv1.ServiceProtocol("http")
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "sdk-publication", controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, Source: &testProjectSource, Deployment: "production",
		ServiceDeclarations: controlv1.ProjectServiceDeclarations{"web": protocol, "restricted": protocol},
		Configuration: controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{
			"web":        {Target: "app", Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}}},
			"restricted": {Target: "app", Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &restricted}}},
		}},
	})
	if err != nil || applied.Deployments == nil {
		t.Fatal("apply SDK publication", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := controlv1.RegisterDeploymentCredentialRequest{
		Name: "sdk-publication", PublicKey: base64.RawURLEncoding.EncodeToString(public),
		ExpiresIn: 600, DeploymentIds: new([]string{(*applied.Deployments)[0].Id}),
	}
	request.Permissions.Publish = &controlv1.DeploymentPublishSelection{
		Services: new(controlv1.DeploymentCredentialServiceSelection{"web", "restricted"}), Temporary: new(controlv1.TemporaryPublicationAnonymous),
	}
	approval, err := f.identity.routes.RegisterDeploymentCredential(t.Context(), f.identity.teamID, "sdk-publication", "sdk-publication", request)
	if err != nil {
		t.Fatal(err)
	}
	token, err := (auth.DeploymentCredential{Version: 1, ControlURL: f.controlConfig.ControlOrigin(), Team: "acme", Approval: approval, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(directory, "state")
	state, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = sdkControlTransport{origin: f.controlConfig.ControlOrigin(), selected: f.controlHTTP.Transport, other: original}
	t.Cleanup(func() { http.DefaultTransport = original })
	ready := make(chan string, 1)
	var recovering atomic.Bool
	options := publisherlocal.Options{Directory: directory, StateDir: stateDir, Publications: true, AttachPublication: func(_ context.Context, _ publisherapp.Service, cfg *publisherservice.RunConfig) error {
		quic, tcp := f.connectors()
		cfg.TransportTLS = f.roots.Clone()
		cfg.DrainTime = time.Second
		cfg.RelayQUIC, cfg.RelayWebSocket = quic, tcp
		var preparation controlv1.ServiceRunPreparation
		prepared, onReady := cfg.Prepared, cfg.Ready
		cfg.Prepared = func(run controlv1.ServiceRunPreparation) error {
			preparation = run
			if prepared != nil {
				return prepared(run)
			}
			return nil
		}
		cfg.Ready = func() error {
			if onReady != nil {
				if err := onReady(); err != nil {
					return err
				}
			}
			if recovering.Load() {
				select {
				case ready <- serviceHTTPAddress(preparation):
				default:
				}
			}
			return nil
		}
		return nil
	}}
	project, root, err := publisherlocal.ResolveProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx, stopOwner := context.WithCancel(t.Context())
	ownerDone := make(chan struct{})
	var ownerErr error
	go func() {
		defer close(ownerDone)
		ownerErr = publisherlocal.Serve(ownerCtx, options)
	}()
	t.Cleanup(func() {
		stopOwner()
		select {
		case <-ownerDone:
			if ownerErr != nil {
				t.Error(ownerErr)
			}
		case <-time.After(20 * time.Second):
			t.Error("native publication owner did not join")
		}
	})
	path, err := publisherprotocol.DescriptorPath(root, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if endpoint, err := publisherprotocol.ReadEndpoint(path); err == nil && publisherlocal.Available(t.Context(), endpoint) {
			break
		}
		select {
		case <-ownerDone:
			t.Fatal("native owner stopped before readiness", ownerErr)
		case <-deadline.C:
			t.Fatal("native owner did not start")
		case <-tick.C:
		}
	}
	// check discovery separately so an SDK's intentionally bounded public error
	// cannot hide a fixture startup or credential-protection failure.
	discovery := exec.CommandContext(t.Context(), binary, "--no-telemetry", "runtime", "endpoint",
		"--directory", directory, "--state-dir", stateDir, "--publications",
		"--invocation-id", "ivk_0123456789ABCDEFGHIJKL")
	discovery.Dir = directory
	discovery.Env = append(os.Environ(), "TNL_STATE_DIR="+stateDir, "TNL_NO_TELEMETRY=1")
	var discoveryError bytes.Buffer
	discovery.Stderr = &discoveryError
	if _, err := discovery.Output(); err != nil {
		t.Fatal("native SDK fixture discovery failed", err, discoveryError.String())
	}
	var savedID, savedURL string
	for _, variant := range []string{
		"node", "node-restart", "node-restricted", "bun", "fetch", "python", "python-restricted",
		"lost-reply", "python-lost-reply", "node-lost-unregister", "fetch-lost-unregister", "python-lost-unregister",
	} {
		t.Run(variant, func(t *testing.T) {
			var evidence func() sdkLostReplyEvidence
			lostRegistration := strings.HasSuffix(variant, "lost-reply")
			lostUnregister := strings.HasSuffix(variant, "lost-unregister")
			if lostRegistration || lostUnregister {
				owner, err := publisherprotocol.ReadEndpoint(path)
				if err != nil {
					t.Fatal(err)
				}
				recovering.Store(true)
				operation := "/v1/publications/register"
				if lostUnregister {
					operation = "/v1/unregister"
				}
				proxy, inspect := newSDKLostReplyProxy(t, owner, ready, f.visitor, operation)
				evidence = inspect
				forwarded := owner
				forwarded.Url = proxy.URL
				if err := publisherprotocol.WriteEndpoint(path, forwarded); err != nil {
					t.Fatal(err)
				}
				defer func() {
					recovering.Store(false)
					if err := publisherprotocol.WriteEndpoint(path, owner); err != nil {
						t.Error(err)
					}
				}()
			}
			environment := append(os.Environ(), "TNL_TOKEN="+token, "TNL_STATE_DIR="+stateDir, "TNL_NO_TELEMETRY=1", "PYTHONPATH="+filepath.Join(directory, "python"))
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			var command *exec.Cmd
			if strings.HasPrefix(variant, "python") {
				command = exec.CommandContext(ctx, "uv", "run", "--frozen", "--project", filepath.Join(repo, "packages/py"), "python", filepath.Join(directory, "publication.py"), variant)
			} else {
				executable := "node"
				if variant == "bun" {
					executable = "bun"
				}
				command = exec.CommandContext(ctx, executable, filepath.Join(directory, "publication.ts"), variant)
			}
			command.Dir, command.Env = directory, environment
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr synchronizedBuffer
			command.Stderr = &stderr
			stopDescendants := isolateIntegrationCommand(t, command)
			process, err := startOwnedCommand(command, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				defer stopDescendants()
				_ = stdin.Close()
				if err := process.shutdown(3*time.Second, 3*time.Second); err != nil {
					t.Error("SDK subprocess cleanup", err)
				}
			}()
			lines := make(chan string, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				if scanner.Scan() {
					lines <- scanner.Text()
				} else {
					lines <- ""
				}
			}()
			var line string
			select {
			case line = <-lines:
			case <-ctx.Done():
				t.Fatal("SDK did not become routable", stderr.String())
			}
			var result struct {
				URL       string `json:"url"`
				Recovered bool   `json:"recovered"`
			}
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				t.Fatal("SDK failed before readiness", stderr.String())
			}
			if lostRegistration {
				proof := evidence()
				if !result.Recovered || proof.err != nil || proof.status != 200 || proof.body != "SDK publication" ||
					len(proof.requests) != 2 || !bytes.Equal(proof.requests[0], proof.requests[1]) {
					t.Fatal("lost acknowledgment did not recover and clean the exact allocation", proof.err)
				}
				result.URL = proof.url
			} else if strings.HasSuffix(variant, "-restricted") {
				address := result.URL + "/settings?tab=profile"
				response, _, err := f.visitor.requestURL(http.MethodGet, address, nil)
				if err != nil || response.StatusCode != http.StatusForbidden || response.Header.Get("Location") != "" {
					t.Fatal("restricted API request started browser sign-in", response, err)
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header = http.Header{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}, "Accept": {"text/html"}}
				browser := *f.visitor.client
				browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				response, err = browser.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/__tnl/team/login?return=%2Fsettings%3Ftab%3Dprofile" {
					t.Fatal("restricted browser navigation did not start sign-in", response.StatusCode, response.Header)
				}
				cookies := response.Cookies()
				if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
					t.Fatal("browser sign-in did not set its secure attempt cookie", cookies)
				}
			} else {
				if variant == "node-restart" {
					// sdk readiness confirms the new run at control, not that
					// ingress has replaced its cached snapshot of the old run.
					var runID string
					if err := f.inspect.QueryRowContext(ctx, `
						SELECT id FROM control.service_runs
						WHERE service_id=$1 AND state='ready' AND closed_at IS NULL
						ORDER BY run_number DESC LIMIT 1
					`, savedID).Scan(&runID); err != nil {
						t.Fatal("could not identify the ready replacement run", err)
					}
					waitForAppliedServiceRouting(t, f.inspect, runID, f.ingress.metricsAddress)
				}
				response, body, err := f.visitor.requestURL(http.MethodGet, result.URL, nil)
				if err != nil || response.StatusCode != 200 || string(body) != "SDK publication" {
					t.Fatal("SDK visitor traffic failed", err)
				}
			}
			var id string
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT service_id FROM control.service_endpoints WHERE hostname=$1`, strings.TrimPrefix(result.URL, "https://")).Scan(&id); err != nil {
				t.Fatal(err)
			}
			if variant == "bun" || variant == "fetch" || variant == "python" {
				declaration, _, err := f.identity.routes.GetServiceConfiguration(t.Context(), id)
				if err != nil {
					t.Fatal(err)
				}
				if declaration == nil || declaration.Http == nil {
					t.Fatal("SDK request limits were not saved in its service declaration")
				}
				limits := declaration.Http.Limits
				if limits == nil || limits.Total == nil || *limits.Total != 10 ||
					limits.Concurrency == nil || *limits.Concurrency != 2 ||
					limits.Rate == nil || limits.Rate.Count != 100 || limits.Rate.Per != "1s" {
					t.Fatal("SDK request limits did not reach native service preparation", limits)
				}
			}
			if variant == "node" {
				savedID, savedURL = id, result.URL
			}
			if variant == "node-restart" && (id != savedID || result.URL != savedURL) {
				t.Fatal("named restart changed saved URL")
			}
			if !lostRegistration {
				_, _ = stdin.Write([]byte("close\n"))
			}
			_ = stdin.Close()
			select {
			case <-process.done:
				if err := process.result(); err != nil {
					t.Fatal("SDK cleanup failed", stderr.String())
				}
			case <-ctx.Done():
				t.Fatal("SDK cleanup did not join", stderr.String())
			}
			if lostUnregister {
				proof := evidence()
				if len(proof.cleanupRequests) != 2 ||
					!bytes.Equal(proof.cleanupRequests[0], proof.cleanupRequests[1]) ||
					len(proof.cleanupStatuses) != 2 ||
					proof.cleanupStatuses[0] != http.StatusNoContent ||
					proof.cleanupStatuses[1] != http.StatusNoContent {
					t.Fatal("lost unregister reply did not recover the exact native outcome", proof.cleanupStatuses)
				}
			}
			var enabled, deleted bool
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT enabled, deleted_at IS NOT NULL FROM control.services WHERE id=$1`, id).Scan(&enabled, &deleted); err != nil {
				t.Fatal(err)
			}
			named := variant == "node" || variant == "node-restart" || variant == "node-restricted"
			if named && (!enabled || deleted) || !named && !deleted {
				t.Fatal("SDK cleanup changed wrong service lifetime", enabled, deleted)
			}
		})
	}
}

type sdkLostReplyEvidence struct {
	url, body       string
	status          int
	err             error
	requests        [][]byte
	cleanupRequests [][]byte
	cleanupStatuses []int
}

// drop one successful native acknowledgment only after a real visitor has used
// its allocation. the SDK must recover the same invocation before deleting it.
func newSDKLostReplyProxy(t *testing.T, owner publisherprotocol.Endpoint, ready <-chan string, visitor *integrationVisitor, operation string) (*httptest.Server, func() sdkLostReplyEvidence) {
	t.Helper()
	var mu sync.Mutex
	var evidence sdkLostReplyEvidence
	var dropped atomic.Bool
	client := &http.Client{Transport: http.DefaultTransport, Timeout: 80 * time.Second}
	var proxy *httptest.Server
	proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, publisherprotocol.MaxBytes+1))
		if err != nil {
			http.Error(w, "read private request", http.StatusBadGateway)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, owner.Url+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			http.Error(w, "build private request", http.StatusBadGateway)
			return
		}
		request.Header = r.Header.Clone()
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "forward private request", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			http.Error(w, "read private response", http.StatusBadGateway)
			return
		}
		if r.URL.Path == "/v1/capabilities" && response.StatusCode == 200 {
			var endpoint publisherprotocol.Endpoint
			if err := json.Unmarshal(data, &endpoint); err != nil {
				http.Error(w, "decode private endpoint", http.StatusBadGateway)
				return
			}
			endpoint.Url = proxy.URL
			data, err = json.Marshal(endpoint)
			if err != nil {
				http.Error(w, "encode private endpoint", http.StatusBadGateway)
				return
			}
		}
		if r.URL.Path == "/v1/publications/register" {
			mu.Lock()
			evidence.requests = append(evidence.requests, body)
			mu.Unlock()
			if operation == r.URL.Path && response.StatusCode == 200 && !dropped.Swap(true) {
				var proof sdkLostReplyEvidence
				var registration publisherprotocol.Registration
				proof.err = json.Unmarshal(data, &registration)
				tick := time.NewTicker(publisherapp.LeaseDuration / 4)
			awaitVisitor:
				for proof.err == nil {
					// the proxy owns this artificial acknowledgment delay. keep
					// the accepted registration alive until the SDK can recover it.
					renewCtx, cancel := context.WithTimeout(r.Context(), publisherapp.LeaseDuration/4)
					proof.err = publisherprotocol.Call(renewCtx, owner, http.MethodPost, "/v1/renew", registration, nil)
					cancel()
					if proof.err != nil {
						break
					}
					select {
					case proof.url = <-ready:
						visitCtx, cancel := context.WithTimeout(r.Context(), publisherapp.LeaseDuration/2)
						visited, content, visitErr := visitor.requestURLContext(visitCtx, http.MethodGet, proof.url, nil)
						cancel()
						proof.body, proof.err = string(content), visitErr
						if visited != nil {
							proof.status = visited.StatusCode
						}
						break awaitVisitor
					case <-tick.C:
					case <-r.Context().Done():
						proof.err = r.Context().Err()
					}
				}
				tick.Stop()
				mu.Lock()
				evidence.url, evidence.body, evidence.status, evidence.err = proof.url, proof.body, proof.status, proof.err
				mu.Unlock()
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = connection.Close()
				}
				return
			}
		}
		if r.URL.Path == "/v1/unregister" {
			mu.Lock()
			evidence.cleanupRequests = append(evidence.cleanupRequests, body)
			evidence.cleanupStatuses = append(evidence.cleanupStatuses, response.StatusCode)
			mu.Unlock()
			if operation == r.URL.Path && response.StatusCode == http.StatusNoContent && !dropped.Swap(true) {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = connection.Close()
				}
				return
			}
		}
		for key, values := range response.Header {
			if !strings.EqualFold(key, "Content-Length") {
				w.Header()[key] = values
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(data)
	}))
	t.Cleanup(proxy.Close)
	return proxy, func() sdkLostReplyEvidence {
		mu.Lock()
		defer mu.Unlock()
		return evidence
	}
}

type sdkControlTransport struct {
	origin          string
	selected, other http.RoundTripper
}

func (s sdkControlTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host == s.origin {
		return s.selected.RoundTrip(r)
	}
	return s.other.RoundTrip(r)
}

func installPublicationSDKs(t *testing.T, repo, directory, binary string) {
	t.Helper()
	packageRoot := filepath.Join(directory, "node_modules/@tnldotdev/tnl")
	if err := os.MkdirAll(packageRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(packageRoot, "dist"), os.DirFS(filepath.Join(repo, "packages/ts/dist"))); err != nil {
		t.Fatal("build the SDK before runtime qualification", err)
	}
	manifest, err := os.ReadFile(filepath.Join(repo, "packages/ts/package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageRoot, "package.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Version      string            `json:"version"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(manifest, &metadata); err != nil {
		t.Fatal(err)
	}
	for dependency := range metadata.Dependencies {
		destination := filepath.Join(directory, "node_modules", dependency)
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(repo, "packages/ts/node_modules", dependency), destination); err != nil {
			t.Fatal(err)
		}
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	native := filepath.Join(directory, "node_modules/@tnldotdev", "tnl-"+runtime.GOOS+"-"+arch)
	if err := os.MkdirAll(filepath.Join(native, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "package.json"), []byte(fmt.Sprintf(`{"version":%q}`, metadata.Version)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, filepath.Join(native, "bin/tnl")); err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(directory, "python/tnl")
	if err := os.CopyFS(python, os.DirFS(filepath.Join(repo, "packages/py/src/tnl"))); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(python, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, filepath.Join(python, "bin/tnl")); err != nil {
		t.Fatal(err)
	}
	for source, name := range map[string]string{
		"packages/ts/test/fixtures/deployment-publication.ts": "publication.ts",
		"packages/py/tests/deployment_publication_fixture.py": "publication.py",
		"packages/ts/test/fixtures/enrolled-publisher.ts":     "enrolled-publisher.ts",
		"packages/py/tests/enrolled_publisher_fixture.py":     "enrolled-publisher.py",
	} {
		data, err := os.ReadFile(filepath.Join(repo, source))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
