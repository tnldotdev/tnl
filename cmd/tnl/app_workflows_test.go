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

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAppWorkflowWaitSelectsLocalServices(t *testing.T) {
	project, state, manager, endpoint := observationFixture(t, true)
	project.Config.Services = config.Services{"web": {}, "remote": {PublisherGroup: new("production")}}
	if err := manager.Configure(configuredRuntimeServices(project)); err != nil {
		t.Fatal(err)
	}
	id, err := manager.Reserve("web", "owner", os.Getpid(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	waitObservationFixture(t, manager, func(s clientruntime.Snapshot) bool { return s.Services[0].Routable })
	// the owner reports a fresh check; the CLI must count only local services.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request publisherprotocol.Check
		_ = json.NewDecoder(r.Body).Decode(&request)
		s := manager.Snapshot()
		s.Services[0].Ready = true
		_ = json.NewEncoder(w).Encode(s)
	}))
	defer server.Close()
	endpoint.Url = server.URL
	path, _ := publisherprotocol.DescriptorPath(state.Root(), project.Root)
	if err := publisherprotocol.WriteEndpoint(path, endpoint); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAppWait(t.Context(), project, state.Root(), waitCommand{Timeout: 3 * time.Second, Output: "json"}, &output); err != nil {
		t.Fatalf("mixed local/remote wait failed: %v\n%s", err, &output)
	}
}

func TestAppWorkflowCrashInvalidatesPrivateReadiness(t *testing.T) {
	project, state, manager, _ := observationFixture(t, false)
	s := manager.Snapshot()
	s.Services[0].Registered, s.Services[0].Routable, s.Services[0].Ready = true, true, true
	s.Services[0].RegistrationID, s.Services[0].RunNumber = "old", 7
	if err := clientruntime.CommitSnapshot(t.Context(), state, &s, "service.readiness", nil); err != nil {
		t.Fatal(err)
	}
	got, err := readAppSnapshotFrom(t.Context(), project, state)
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
		_ = json.NewEncoder(w).Encode(controlv1.LocalProjectService{Service: "web", ServiceId: "svc_test", ServiceKind: "service", WorktreeKey: body.WorktreeKey})
	}))
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("session"))
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
		p, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: configuration}, root, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = invocation.RealizeLocalService(t.Context(), control, invocation.LocalService{Project: p, Team: invocation.NewTeamSelection(authorityv1.Team{Id: "team"}, authorityv1.Membership{}, nil, ""), Name: "web"})
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
