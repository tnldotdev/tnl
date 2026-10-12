package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func TestPublisherOwnerCredentialMustBePrivateAndIsNeverInErrors(t *testing.T) {
	root := t.TempDir()
	if _, err := readPublisherOwnerCredential(root, ".tnl/publisher-owner"); err == nil {
		t.Fatal("missing publisher owner credential was accepted")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.PublisherOwnerCredentialMissing {
		t.Fatalf("missing credential did not suggest the creation command: %v", err)
	}
	secret, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "owner-token")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPublisherOwnerCredential(root, "owner-token"); err != nil || got != secret {
		t.Fatalf("owner credential = %q, %v", got, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublisherOwnerCredential(root, "owner-token"); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("publicly readable owner credential accepted or exposed: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "owner-link")
	if err := os.Symlink(path, other); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublisherOwnerCredential(root, "owner-link"); err == nil {
		t.Fatal("followed symlink to owner credential")
	}
}

func TestExternalPublisherIssuesOnlyScopedCredentialForSelectedProject(t *testing.T) {
	root := t.TempDir()
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	app, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "owner-token"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	issued := 0
	servedProject := root
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+owner {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/status":
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectSnapshot{Project: servedProject, Cursor: "1", Services: []localpublisherv1.ServiceStatus{}})
		case "/v1/scopes/app/web":
			issued++
			privateprotocol.Write(w, http.StatusOK, localPublisherEndpoint{Version: 1, URL: "http://0.0.0.0:8765", Credential: app})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	file := "owner-token"
	address := server.URL
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Config: config.TNL{Publisher: &config.ProjectPublisher{
		Type: "url", URL: &address, OwnerCredentialFile: &file,
	}}}}
	endpoint, err := remotePublisherScope(t.Context(), project, true, false, "web")
	if err != nil || issued != 1 || endpoint.URL != server.URL || endpoint.Credential != app {
		t.Fatalf("scoped external endpoint = %+v, issued=%d, %v", endpoint, issued, err)
	}
	servedProject = filepath.Join(root, "different")
	_, err = remotePublisherScope(t.Context(), project, true, false, "web")
	if reason, _, ok := failure.Describe(err); err == nil || !ok || reason != failure.ProjectConfigInvalid {
		t.Fatalf("different project publisher was accepted: %v", err)
	}
	server.Close()
	if _, err := remotePublisherScope(t.Context(), project, false, false, ""); err == nil {
		t.Fatal("stopped external publisher was accepted")
	}
}

func TestPublisherClientDoesNotForwardOwnerCredentialThroughRedirect(t *testing.T) {
	var redirected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirected.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	credential, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	client := namedPublisherClient{endpoint: localPublisherEndpoint{URL: server.URL, Credential: credential}, http: publisherHTTPClient(time.Second)}
	var snapshot localpublisherv1.ProjectSnapshot
	if err := client.request(t.Context(), http.MethodGet, "/v1/status", "", nil, &snapshot); err == nil || redirected.Load() {
		t.Fatalf("publisher followed an authenticated redirect: %v", err)
	}
}

func TestRemoteStatusChecksPrivateTCPReachabilityAtThePublisher(t *testing.T) {
	root := t.TempDir()
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "owner-token"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	privateTarget := "database:5432"
	publicURL := "orders.example:15432"
	publicationID := "reg_0123456789abcdef0123456789abcdef"
	tunnelID := "tun_0123456789abcdefghijkl"
	version := int64(1)
	var checked atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+owner {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		state := localpublisherv1.Routable
		if r.URL.Query().Get("probe") == "orders" {
			checked.Store(true)
			state = localpublisherv1.Ready
		}
		privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectSnapshot{Project: root, Cursor: "7", Services: []localpublisherv1.ServiceStatus{{
			Service: "orders", Protocol: localpublisherv1.ServiceStatusProtocolPostgres, State: state,
			Target: &privateTarget, PublicUrl: &publicURL, PublicationId: &publicationID, TunnelId: &tunnelID,
			PublishRunNumber: &version,
		}}})
	}))
	defer server.Close()
	credentialFile := "owner-token"
	url := server.URL
	protocol := "postgres"
	project := projectConfiguration{Project: projectconfig.Project{Root: root,
		Config: config.TNL{Publisher: &config.ProjectPublisher{Type: "url", URL: &url, OwnerCredentialFile: &credentialFile},
			Services: config.Services{"orders": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address"}}}},
		RelativeServiceDirectories: map[string]string{"orders": "."},
	}}
	snapshot, err := readRemoteAppSnapshot(t.Context(), project)
	if err != nil || len(snapshot.Services) != 1 || !snapshot.Services[0].Routable || snapshot.Services[0].Target != privateTarget || snapshot.Services[0].PublicURL != publicURL || snapshot.Services[0].TunnelID != tunnelID {
		t.Fatalf("remote publication = %+v, %v", snapshot, err)
	}
	if !probeRemoteTarget(t.Context(), project, "orders") || !checked.Load() {
		t.Fatal("visitor readiness did not check the publisher's private network")
	}
}

func TestDockerPublisherAttachmentUsesWorktreeComposeBinding(t *testing.T) {
	root := t.TempDir()
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "owner-token"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" || r.Header.Get("Authorization") != "Bearer "+owner {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectSnapshot{Project: root, Cursor: "0", Services: []localpublisherv1.ServiceStatus{}})
	}))
	defer server.Close()
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := address.Port()
	commands := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = inspect ]; then printf '%s\\n' '[{\"Name\":\"/publisher\",\"State\":{\"Running\":true},\"Config\":{\"Labels\":{\"tnl.worktree\":\"shop-perf-k7n2p9\"}},\"NetworkSettings\":{\"Ports\":{\"8765/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"" + port + "\"}]},\"Networks\":{\"bridge\":{}}}}]'; fi\n"
	if err := os.WriteFile(filepath.Join(commands, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", commands+string(os.PathListSeparator)+os.Getenv("PATH"))
	service, file := "publisher", "owner-token"
	privatePort := 8765
	project := projectConfiguration{Project: projectconfig.Project{Root: root,
		Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "shop-perf-k7n2p9"}},
		Config:   config.TNL{Publisher: &config.ProjectPublisher{Type: "docker", DockerSelection: config.DockerSelection{Container: &service, ContainerPort: &privatePort}, OwnerCredentialFile: &file}},
	}}
	client, stop, err := localPublisherForCLI(t.Context(), publishCommand{projectRoot: root, project: project})
	if err != nil || client.endpoint.URL != server.URL {
		t.Fatalf("Docker owner attachment = %+v, %v", client.endpoint, err)
	}
	stop()
}

type cancelWatchWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelWatchWriter) Write(data []byte) (int, error) {
	n, err := w.Buffer.Write(data)
	w.cancel()
	return n, err
}

func TestExternalPublisherWatchFollowsPublisherEvents(t *testing.T) {
	root := t.TempDir()
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "owner-token"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	publication := "reg_0123456789abcdef0123456789abcdef"
	at := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	servedProject := root
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+owner {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/status" {
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectSnapshot{Project: servedProject, Cursor: "1", Services: []localpublisherv1.ServiceStatus{}})
			return
		}
		if r.URL.Path != "/v1/events" || r.URL.Query().Get("after") != "1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectEventPage{Cursor: "2", Events: []localpublisherv1.ProjectEvent{{
			Cursor: "2", Type: "service.publication", Service: "orders", At: at, Status: &localpublisherv1.ServiceStatus{
				Service: "orders", Protocol: localpublisherv1.ServiceStatusProtocolPostgres,
				State: localpublisherv1.Routable, PublicationId: &publication,
			},
		}}})
	}))
	defer server.Close()
	credentialFile, endpoint, protocol := "owner-token", server.URL, "postgres"
	project := projectConfiguration{Project: projectconfig.Project{Root: root,
		Config: config.TNL{Publisher: &config.ProjectPublisher{Type: "url", URL: &endpoint, OwnerCredentialFile: &credentialFile},
			Services: config.Services{"orders": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address"}}}},
		RelativeServiceDirectories: map[string]string{"orders": "."},
	}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	output := &cancelWatchWriter{cancel: cancel}
	if err := runRemoteAppWatch(ctx, project, watchCommand{After: "1", Output: "ndjson"}, output); err != nil {
		t.Fatal(err)
	}
	var event clientruntime.Event
	if err := json.Unmarshal(output.Bytes(), &event); err != nil || event.Cursor != "2" || event.Service == nil || event.Service.Name != "orders" || !event.Service.Routable || !event.At.Equal(at) {
		t.Fatalf("external publisher watch event = %s, %v", output.String(), err)
	}
	servedProject = filepath.Join(root, "other")
	if err := runRemoteAppWatch(t.Context(), project, watchCommand{After: "1", Output: "ndjson"}, &bytes.Buffer{}); err == nil {
		t.Fatal("resumed another project's event stream")
	}
}

func TestExternalPublisherWaitRecordsHTTPReadinessOnTheSelectedOwner(t *testing.T) {
	root := t.TempDir()
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "owner-token"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	publication := "reg_0123456789abcdef0123456789abcdef"
	tunnel := "tun_0123456789abcdefghijkl"
	number := int64(3)
	var observed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+owner {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/status":
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectSnapshot{Project: root, Cursor: "2", Services: []localpublisherv1.ServiceStatus{{
				Service: "web", Protocol: localpublisherv1.ServiceStatusProtocolHttp, State: localpublisherv1.Routable,
				PublicationId: &publication, TunnelId: &tunnel, PublishRunNumber: &number,
			}}})
		case "/v1/observe":
			var observation clientruntime.Observation
			if json.NewDecoder(r.Body).Decode(&observation) != nil || observation.RegistrationID != publication || observation.PublishRunNumber != uint64(number) || !observation.Ready {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			observed.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	credentialFile, endpoint := "owner-token", server.URL
	project := projectConfiguration{Project: projectconfig.Project{Root: root,
		Config: config.TNL{Publisher: &config.ProjectPublisher{Type: "url", URL: &endpoint, OwnerCredentialFile: &credentialFile},
			Services: config.Services{"web": {Target: &config.ServiceTarget{Type: "app"}}}},
		RelativeServiceDirectories: map[string]string{"web": "."},
	}}
	var output bytes.Buffer
	state := filepath.Join(t.TempDir(), "state")
	err = runAppWaitWithProbe(t.Context(), project, state, waitCommand{Timeout: time.Second, Output: "json"}, &output,
		func(_ context.Context, service clientruntime.Service) clientruntime.Observation {
			return clientruntime.Observation{RegistrationID: service.RegistrationID, PublishRunNumber: service.PublishRunNumber,
				Readiness: service.Readiness, Ready: true, CheckedAt: time.Now()}
		})
	if err != nil || !observed.Load() {
		t.Fatalf("remote HTTP readiness was not recorded: %v, output=%s", err, output.String())
	}
}
