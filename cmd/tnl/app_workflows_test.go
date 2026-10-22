package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestAppWorkflowRejectsStaleOwnerAfterOneAppRestart(t *testing.T) {
	a, endpoint := testAppRuntime(t)
	a.project.Config.Services = config.Services{
		"web": {Tunnel: &config.Tunnel{}},
		"api": {Tunnel: &config.Tunnel{Access: &config.Access{Mode: "anonymous"}}},
	}
	for _, name := range []string{"web", "api"} {
		id, err := a.manager.Reserve(name, name, os.Getpid(), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := a.manager.Register(id, name, "http://127.0.0.1:3000", "node"); err != nil {
			t.Fatal(err)
		}
		if name == "web" {
			t.Cleanup(func() { _ = a.manager.Unregister(id, name) })
		}
		if name == "api" {
			if err := a.manager.Unregister(id, name); err != nil {
				t.Fatal(err)
			}
		}
	}
	path, err := privateprotocol.DescriptorPath(a.state.Root(), a.project.Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateprotocol.WriteEndpoint(path, endpoint); err != nil {
		t.Fatal(err)
	}
	changed := a.project
	changed.Config.Services = config.Services{"web": {Tunnel: &config.Tunnel{}}, "api": {Tunnel: &config.Tunnel{Access: &config.Access{Mode: "restricted"}}}}
	if _, err := ensureRuntimeOwner(t.Context(), changed, a.state.Root()); err == nil {
		t.Fatal("restarted app silently reused the old owner's policy")
	}
}

func TestAppWorkflowWaitSelectsLocalServices(t *testing.T) {
	a, endpoint := testAppRuntimeWorkers(t, false, true)
	a.project.Config.Services = config.Services{"web": {}, "remote": {Publisher: new("production")}}
	if err := a.manager.Configure(configuredRuntimeServices(a.project)); err != nil {
		t.Fatal(err)
	}
	id, err := a.manager.Reserve("web", "owner", os.Getpid(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(s clientruntime.Snapshot) bool { return s.Services[0].Routable })
	a.workers.Configure = nil
	// the owner reports a fresh check; the CLI must count only local services.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request privateprotocol.Check
		_ = json.NewDecoder(r.Body).Decode(&request)
		s := a.manager.Snapshot()
		s.Services[0].Ready = true
		_ = json.NewEncoder(w).Encode(s)
	}))
	defer server.Close()
	endpoint.Url = server.URL
	path, _ := privateprotocol.DescriptorPath(a.state.Root(), a.project.Root)
	if err := privateprotocol.WriteEndpoint(path, endpoint); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAppWait(t.Context(), a.project, a.state.Root(), waitCommand{Timeout: 3 * time.Second, Output: "json"}, &output); err != nil {
		t.Fatalf("mixed local/remote wait failed: %v\n%s", err, &output)
	}
}

func TestAppWorkflowCrashInvalidatesPrivateReadiness(t *testing.T) {
	a, _ := testAppRuntime(t)
	s := a.manager.Snapshot()
	s.Services[0].Registered, s.Services[0].Routable, s.Services[0].Ready = true, true, true
	s.Services[0].RegistrationID, s.Services[0].PublishRunNumber = "old", 7
	if err := clientruntime.CommitSnapshot(t.Context(), a.state, &s, "service.readiness", nil); err != nil {
		t.Fatal(err)
	}
	got, err := readAppSnapshotFrom(t.Context(), a.project, a.state)
	if err != nil {
		t.Fatal(err)
	}
	if got.Services[0].Registered || got.Services[0].Routable || got.Services[0].Ready {
		t.Fatalf("private readiness survived an absent owner: %+v", got.Services[0])
	}
}

func TestAppWorkflowLocalRealizationSurvivesGitChanges(t *testing.T) {
	var identities []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body controlv1.RealizeLocalProjectServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		identities = append(identities, r.URL.Path+":"+body.SourceFingerprint+":"+body.WorktreeKey)
		_ = json.NewEncoder(w).Encode(controlv1.LocalProjectService{Service: "web", ServiceId: "svc_test", ServiceKind: "private_service", WorktreeKey: body.WorktreeKey})
	}))
	defer server.Close()
	control, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken("session"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configuration := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(configuration, []byte(`{"version":1,"tnl":{"services":{"web":{}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for step := range 4 {
		if step == 1 {
			command := exec.Command("git", "init", "--quiet", root)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("git init: %v %s", err, out)
			}
		}
		if step >= 2 {
			args := []string{"-C", root, "remote", "add", "origin", "https://example.test/first.git"}
			if step == 3 {
				args = []string{"-C", root, "remote", "set-url", "origin", "https://elsewhere.test/second.git"}
			}
			if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
				t.Fatalf("git remote: %v %s", err, out)
			}
		}
		p, err := projectconfig.Resolve(t.Context(), projectconfig.Selection{Path: configuration}, root, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = realizeLocalService(t.Context(), control, projectConfiguration{Project: p}, teamContext{team: authorityv1.Team{Id: "team"}}, "web", "")
		if err != nil {
			t.Fatalf("step %d local app requires Git identity: %v", step, err)
		}
		if len(identities) > 1 && identities[step] != identities[0] {
			t.Fatalf("local identity changed: %v", identities)
		}
		if step < 2 {
			if _, err := p.SourceIdentity(t.Context()); err == nil {
				t.Fatal("portable apply accepted missing origin")
			}
		}
	}
}

func TestAppWorkflowAuthoredNamedAction(t *testing.T) {
	_, err := namedInvocation(publishCommand{namedOverrides: true})
	_, definition, ok := failure.Describe(err)
	if !ok || !strings.Contains(definition.Action, "configuration") || strings.Contains(definition.Action, "--allow-ip") {
		t.Fatalf("named action lost: %+v, %v", definition, err)
	}
	_, definition, _ = failure.Describe(publisherCLIError("internal cause must not be displayed"))
	if strings.Contains(definition.Action, "--allow-ip") || strings.Contains(definition.Message, "internal cause") {
		t.Fatalf("unsafe or obsolete action: %+v", definition)
	}
}
