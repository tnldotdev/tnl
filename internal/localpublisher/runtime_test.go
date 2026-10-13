package localpublisher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func testAppRuntime(t *testing.T) (*appRuntime, string, <-chan uint64) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	project, _ := filepath.EvalSymlinks(t.TempDir())
	state, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	a := &appRuntime{project: projectConfiguration{Project: projectconfig.Project{Root: project, Config: config.TNL{Services: config.Services{"api": {}, "web": {}}}, RelativeServiceDirectories: map[string]string{"api": ".", "web": "."}}}, prepared: map[string]appPreparation{}}
	var run atomic.Uint64
	started := make(chan uint64, 4)
	manager, err := clientruntime.New(t.Context(), project, state, configuredRuntimeServices(a.project), func(ctx context.Context, _ clientruntime.Service, observe func(uint64, bool) error) error {
		number := run.Add(1)
		if err := observe(number, true); err != nil {
			return err
		}
		started <- number
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	a.manager = manager
	t.Cleanup(manager.Close)
	key, err := runtimeKey(project, state)
	if err != nil {
		t.Fatal(err)
	}
	services := configuredRuntimeServices(a.project)
	tcpServer, _, err := startRuntimeTCP(key, a.handler(), services...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stopRuntimeTCP(context.Background(), tcpServer, key); err != nil {
			t.Error(err)
		}
	})
	return a, state, started
}

func TestAppScopedCredentialCannotManagePublisherLogin(t *testing.T) {
	a, state, _ := testAppRuntime(t)
	key, err := runtimeKey(a.project.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := readLocalPublisherDescriptor(runtimeAppEndpointPath(key, "api"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/auth/status", "/v1/auth/login/start", "/v1/auth/login/token", "/v1/auth/logout"} {
		method := http.MethodPost
		if path == "/v1/auth/status" {
			method = http.MethodGet
		}
		request, err := http.NewRequestWithContext(t.Context(), method, endpoint.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("app credential accessed %s: %d", path, response.StatusCode)
		}
	}
}

func TestPublisherOwnerReadsItsOwnControlSessionStatus(t *testing.T) {
	a, state, _ := testAppRuntime(t)
	database, err := clientstate.Open(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	a.state = database
	server := "https://control.example.test"
	a.project.Config.Server = &server
	key, err := runtimeKey(a.project.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint.URL+"/v1/auth/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var status clientauth.StatusResult
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil || response.StatusCode != http.StatusOK || status.Server != server || status.Source != "none" {
		t.Fatalf("publisher-owned session status = %+v, HTTP %d, %v", status, response.StatusCode, err)
	}
}

func TestLocalPublisherCredentialsRestrictAppAndAdHocOperations(t *testing.T) {
	a, state, started := testAppRuntime(t)
	key, err := runtimeKey(a.project.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	credential := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var scoped localPublisherEndpoint
		if err := json.Unmarshal(data, &scoped); err != nil || scoped.Credential == "" || scoped.Credential == endpoint.Credential || scoped.URL != endpoint.URL {
			t.Fatalf("scoped endpoint = %+v, %v", scoped, err)
		}
		return scoped.Credential
	}
	apiToken := credential(runtimeAppEndpointPath(key, "api"))
	webToken := credential(runtimeAppEndpointPath(key, "web"))
	adHocToken := credential(runtimeAdHocEndpointPath(key))
	if apiToken == webToken || apiToken == adHocToken || webToken == adHocToken {
		t.Fatal("service-scoped credentials were reused")
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	call := func(method, path, token string, value any) *http.Response {
		t.Helper()
		var body io.Reader
		if value != nil {
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(data)
		}
		request, err := http.NewRequestWithContext(t.Context(), method, endpoint.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		if value != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	for _, test := range []struct {
		token, service string
	}{
		{apiToken, "api"}, {webToken, "web"}, {adHocToken, ""},
	} {
		response := call(http.MethodGet, "/v1/status", test.token, nil)
		var snapshot localpublisherv1.ProjectSnapshot
		if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK || test.service == "" && len(snapshot.Services) != 0 ||
			test.service != "" && (len(snapshot.Services) != 1 || snapshot.Services[0].Service != test.service) {
			t.Fatalf("credential %q could inspect %+v", test.service, snapshot.Services)
		}
	}
	for _, test := range []struct{ token, path string }{
		{webToken, "/v1/publications"},
		{webToken, "/v1/scopes/app/api"},
		{webToken, "/v1/ad-hoc/register"},
		{adHocToken, "/v1/prepare"},
		{adHocToken, "/v1/publications"},
	} {
		response := call(http.MethodPost, test.path, test.token, nil)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("credential reached %s with status %d", test.path, response.StatusCode)
		}
	}
	probeResponse := call(http.MethodGet, "/v1/status?probe=api", webToken, nil)
	probeResponse.Body.Close()
	if probeResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("app credential requested a private target probe: HTTP %d", probeResponse.StatusCode)
	}
	owner := "0123456789abcdef0123456789abcdef"
	id, err := a.manager.Reserve("api", owner, os.Getpid(), "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{assignment: privateprotocol.Assignment{Service: "api"}}
	a.mu.Unlock()
	registration := privateprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner, Target: "http://127.0.0.1:3000"}
	response := call(http.MethodPost, "/v1/register", webToken, registration)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || a.manager.Current("api", id, registration.Target, 0) {
		t.Fatal("web credential claimed the api listener")
	}
	response = call(http.MethodPost, "/v1/register", apiToken, registration)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("api registration = %d", response.StatusCode)
	}
	<-started
}

func TestRunningPublisherIssuesCredentialForNewConfiguredApp(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	a, state, _ := testAppRuntime(t)
	configData := []byte(`{"version":1,"tnl":{"services":{"api":{"target":{"type":"app"}},"web":{"target":{"type":"app"}},"new":{"target":{"type":"app"}}}}}`)
	if err := os.WriteFile(filepath.Join(a.project.Root, "tnl.json"), configData, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runRuntimeEndpoint(t.Context(), runtimeOptions{Directory: a.project.Root, StateDir: state, App: true, Service: "new"}, &output); err != nil {
		t.Fatal(err)
	}
	var located struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(output.Bytes(), &located); err != nil || located.Path == "" {
		t.Fatalf("new app endpoint = %q, %v", output.String(), err)
	}
	info, err := os.Stat(located.Path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("new app credential file = %v, %v", info, err)
	}
	newEndpoint, err := readLocalPublisherDescriptor(located.Path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := runtimeKey(a.project.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := readRuntimeTCPEndpoint(key)
	if err != nil || newEndpoint.Credential == owner.Credential {
		t.Fatalf("app credential was not scoped to the new service: %v", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, newEndpoint.URL+"/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+newEndpoint.Credential)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("new app credential status = %d", response.StatusCode)
	}
}

func TestRuntimeEndpointWorksWithoutProjectConfiguration(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	directory := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	var output bytes.Buffer
	if err := runRuntimeEndpoint(t.Context(), runtimeOptions{Directory: directory, StateDir: state}, &output); err != nil {
		t.Fatal(err)
	}
	var endpoint struct {
		Version int    `json:"version"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(output.Bytes(), &endpoint); err != nil || endpoint.Version != 1 || endpoint.Path == "" {
		t.Fatalf("unconfigured runtime endpoint = %#v, %v", endpoint, err)
	}
	if _, err := os.Stat(endpoint.Path); !os.IsNotExist(err) {
		t.Fatalf("unconfigured endpoint lookup started the local publisher: %v", err)
	}
}

func TestExternalPublisherMapsOnlyReachableAppListeners(t *testing.T) {
	compose := &config.ComposeSelection{File: "compose.yaml", Project: "shop-k7n2p9", Service: "publisher"}
	a := &appRuntime{project: projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Publisher: &config.ProjectPublisher{
		Type: "docker", DockerSelection: config.DockerSelection{Compose: compose},
	}}}}}
	ctx := context.WithValue(t.Context(), localScopeContextKey{}, localPublisherScope{kind: localScopeApp, service: "web"})
	if target, err := a.registeredAppTarget(ctx, "web", "http://127.0.0.1:49152", "0.0.0.0"); err != nil || target != "http://web:49152" {
		t.Fatalf("docker app target = %q, %v", target, err)
	}
	for _, test := range []struct {
		scope         localPublisherScope
		target, bound string
	}{
		{localPublisherScope{kind: localScopeOwner}, "http://127.0.0.1:49152", "0.0.0.0"},
		{localPublisherScope{kind: localScopeApp, service: "web"}, "http://127.0.0.1:49152", "127.0.0.1"},
		{localPublisherScope{kind: localScopeApp, service: "web"}, "http://another:49152", "0.0.0.0"},
	} {
		ctx := context.WithValue(t.Context(), localScopeContextKey{}, test.scope)
		if _, err := a.registeredAppTarget(ctx, "web", test.target, test.bound); err == nil {
			t.Fatalf("accepted unreachable or unscoped app target %+v", test)
		}
	}
	if _, err := a.registeredAppTarget(ctx, "web", "http://web.internal:49152", "0.0.0.0"); err == nil {
		t.Fatal("docker publisher accepted an app-selected private hostname")
	}
}

func TestExternalPublisherUsesMountedHostWorktreeLabel(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	t.Setenv("TNL_PUBLISHER_EXTERNAL", "1")
	root := t.TempDir()
	configData := []byte(`{"version":1,"tnl":{"publisher":{"type":"docker","compose":{"file":"compose.yaml","project":"shop-k7n2p9","service":"publisher"},"container_port":8765},"services":{"web":{"target":{"type":"app"}}}}}`)
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), configData, 0600); err != nil {
		t.Fatal(err)
	}
	metadata := projectmeta.Metadata{Version: projectmeta.Version, Namespace: "shop.example.test",
		Services: map[string]projectmeta.Service{}, ServiceDirectories: map[string]string{},
		Worktree: &projectmeta.Worktree{Label: projectconfig.WorktreeLabel{Project: "shop", ID: "k7n2p9", FullLabel: "shop-k7n2p9"}},
	}
	if err := projectmeta.Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	project, _, err := runtimeProject(t.Context(), runtimeOptions{Directory: root, StateDir: state})
	if err != nil || project.Worktree.Label.FullLabel != "shop-k7n2p9" || projectconfig.ServiceWorktreeLabel("web", project.Worktree) != "web-shop-k7n2p9" {
		t.Fatalf("mounted publisher worktree = %+v, %v", project.Worktree.Label, err)
	}
}

func TestDockerPublisherGeneratesOwnerCredentialInPrivateClientState(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	t.Setenv("TNL_PUBLISHER_EXTERNAL", "1")
	root := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	configData := []byte(fmt.Sprintf(`{"version":1,"tnl":{"publisher":{"type":"docker","compose":{"file":"compose.yaml","project":"shop-k7n2p9","service":"publisher"},"container_port":%d},"services":{"orders":{"protocol":"postgres","target":{"type":"address","address":"127.0.0.1:5432"}}}}}`, port))
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), configData, 0600); err != nil {
		t.Fatal(err)
	}
	metadata := projectmeta.Metadata{Version: projectmeta.Version, Namespace: "shop.example.test",
		Services: map[string]projectmeta.Service{}, ServiceDirectories: map[string]string{},
		Worktree: &projectmeta.Worktree{Label: projectconfig.WorktreeLabel{Project: "shop", ID: "k7n2p9", FullLabel: "shop-k7n2p9"}},
	}
	if err := projectmeta.Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runRuntimeServe(ctx, runtimeOptions{Directory: root, StateDir: state}) }()
	project, canonicalState, err := runtimeProject(t.Context(), runtimeOptions{Directory: root, StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	key, err := runtimeKey(project.Root, canonicalState)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var endpoint localPublisherEndpoint
	for time.Now().Before(deadline) {
		endpoint, err = readRuntimeTCPEndpoint(key)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil || endpoint.Credential == "" {
		t.Fatalf("Docker publisher owner credential was not generated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".tnl", "publisher-owner")); !os.IsNotExist(err) {
		t.Fatalf("owner credential was saved in the shared checkout: %v", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint.URL+"/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("external publisher status = %d", response.StatusCode)
	}
	// external publishers have no app parent or local idle owner to keep them
	// running while the CLI has no active publication.
	time.Sleep(clientruntime.CleanupGrace + time.Second)
	request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint.URL+"/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	response, err = (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatalf("idle external publisher stopped: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("idle external publisher status = %d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("external publisher did not stop with its owner")
	}
}

func TestAdHocTCPRegistrationWaitsForTheSameReadyRun(t *testing.T) {
	a, state, _ := testAppRuntime(t)
	started := make(chan struct{})
	a.adhoc = clientruntime.NewAdHocManager(t.Context(), func(ctx context.Context, request privateprotocol.AdHocRegister, update func(privateprotocol.AdHocStatus)) error {
		update(privateprotocol.AdHocStatus{Version: 1, RegistrationID: request.RegistrationID, State: "publishing",
			PublicURLID: "url_allocated", PublicURL: "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test"})
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}, func(int) bool { return true }, a.manager.BeginPreparation)
	t.Cleanup(a.adhoc.Close)
	key, err := runtimeKey(a.project.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	token, _, _, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	owner := "0123456789abcdef0123456789abcdef"
	call := func(operation string, payload any) (*http.Response, error) {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint.URL+"/v1/ad-hoc/"+operation, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
		return client.Do(request)
	}
	response, err := call("register", privateprotocol.AdHocRegister{Version: 1, RegistrationID: id, Owner: owner,
		PID: os.Getpid(), Target: "http://127.0.0.1:3000", Credential: token.String()})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("register = %v, %v", response, err)
	}
	response.Body.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("ad-hoc registration did not start its worker")
	}
	registration := privateprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner}
	response, err = call("status", registration)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("status = %v, %v", response, err)
	}
	var status privateprotocol.AdHocStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if status.State != "publishing" || status.PublicURLID != "url_allocated" || status.PublishRunNumber != 0 {
		t.Fatalf("register acknowledgement incorrectly reported readiness: %#v", status)
	}
	response, err = call("unregister", registration)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("unregister = %v, %v", response, err)
	}
	response.Body.Close()
}

func TestNamedPublicationLocalAPIReportsCurrentLeaseAndEvents(t *testing.T) {
	a, state, started := testAppRuntime(t)
	protocol := "postgres"
	target := config.Target("127.0.0.1:5432")
	a.project.Config.Services["orders"] = config.Service{Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &target}}
	a.project.RelativeServiceDirectories["orders"] = "."
	if err := a.manager.Configure(configuredRuntimeServices(a.project)); err != nil {
		t.Fatal(err)
	}
	before := a.manager.Snapshot().Cursor
	owner := "0123456789abcdef0123456789abcdef"
	id, err := a.manager.Reserve("orders", owner, os.Getpid(), "orders.example:15432")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RegisterNamed(id, owner, string(target)); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := a.manager.Started(id, "tun_named"); err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RecordPublication(id, clientruntime.PublicationEvent{Type: "ready", PublicURL: "orders.example:15432", PublishRunNumber: 1}); err != nil {
		t.Fatal(err)
	}
	key, err := runtimeKey(a.project.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	call := func(method, path, identity string) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), method, endpoint.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
		if identity != "" {
			request.Header.Set("X-Publication-Owner", identity)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := call(http.MethodGet, "/v1/status", "")
	var snapshot localpublisherv1.ProjectSnapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(snapshot.Services) != 3 || snapshot.Services[1].Service != "orders" || snapshot.Services[1].TunnelId == nil || *snapshot.Services[1].TunnelId != "tun_named" || snapshot.Services[1].State != localpublisherv1.Routable {
		t.Fatalf("named status = %+v", snapshot)
	}
	response = call(http.MethodGet, "/v1/events?after="+before, "")
	var page localpublisherv1.ProjectEventPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(page.Events) < 2 {
		t.Fatalf("named events = %+v, HTTP %d", page, response.StatusCode)
	}
	last := page.Events[len(page.Events)-1]
	if response.StatusCode != http.StatusOK || page.Cursor != snapshot.Cursor || last.Publication == nil ||
		last.Publication.PublicUrl == nil || *last.Publication.PublicUrl != "orders.example:15432" || last.Status.TunnelId == nil {
		t.Fatalf("named events = %+v, HTTP %d", page, response.StatusCode)
	}
	response = call(http.MethodPost, "/v1/publications/"+id+"/renew", "ffffffffffffffffffffffffffffffff")
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("unowned renewal status = %d", response.StatusCode)
	}
	response = call(http.MethodPost, "/v1/publications/"+id+"/renew", owner)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("owned renewal status = %d", response.StatusCode)
	}
	response = call(http.MethodDelete, "/v1/publications/"+id, owner)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || a.manager.Current("orders", id, string(target), 1) {
		t.Fatalf("owned stop status = %d", response.StatusCode)
	}
}
