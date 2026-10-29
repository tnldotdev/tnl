package main

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationCLIGroupDetachedHistoricalIdentity(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "detached group rename", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	team, control := session.Identity().PersonalTeamId, session.Authenticated().Control
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "detached replica") }))
	defer target.Close()
	applied, err := control.ApplyProjectConfiguration(t.Context(), "detached", controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{PublisherGroups: map[string]controlv1.ProjectPublisherGroup{"production": {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: new("production"), Target: target.URL, Access: &controlv1.ProjectServiceAccess{Team: true}}}}})
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "old.json")
	cliCall(t, t.Context(), []string{"--no-config", "publisher", "provision", "--server", f.url, "--team", team, "--group", "production", "--project-key", "detached", "--instance", "replica-1", "--output-file", identity, "--state-dir", person})
	if _, err := control.RenamePublisherGroup(t.Context(), "detached", "production", controlv1.RenamePublisherGroupRequest{TeamId: team, Name: "live", ExpectedRevision: applied.Revision}); err != nil {
		t.Fatal(err)
	}
	binary := workflowExecutable(t)
	task := f.state(t, "detached-task")
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"live", "production"} {
		command := exec.CommandContext(t.Context(), binary, "--no-config", "--no-telemetry", "publisher", "serve", "--detach", "--group", selector, "--instance", "replica-1", "--identity-file", identity, "--state-dir", task)
		command.Env = append(os.Environ(), "SSL_CERT_FILE="+caFile, "GODEBUG=x509usefallbackroots=0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("detached OLD identity with %s selector: %v %s", selector, err, output)
		}
		entries, err := os.ReadDir(detachedDir(task))
		if err != nil {
			t.Fatal(err)
		}
		var id string
		for _, entry := range entries {
			if validDetachedID(entry.Name()) {
				id = entry.Name()
			}
		}
		if id == "" {
			t.Fatal("detached child did not own its control socket")
		}
		t.Cleanup(func() { _, _ = detachedRequest(task, id, "stop") })
		workflowWait(t, 25*time.Second, func() bool {
			status, err := control.GetProjectConfiguration(t.Context(), team, "detached")
			return err == nil && len(status.Members) == 1 && status.Members[0].Healthy && status.Members[0].GroupName == "live"
		})
		service, err := control.GetService(t.Context(), *applied.Services[0].ServiceId)
		if err != nil {
			t.Fatal(err)
		}
		listener := workflowListen(t)
		address := listener.Addr().String()
		_ = listener.Close()
		ctx, cancel := context.WithCancel(t.Context())
		_, joined := f.command(t, ctx, cancel, []string{"--no-config", "connect", service.Id, "--team", team, "--server", f.url, "--state-dir", person, "--listen", address})
		client := workflowNativeHTTPClient(t, f, service.Endpoint.Hostname)
		workflowWait(t, 10*time.Second, func() bool {
			response, err := client.Get("https://" + address + "/detached")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			data, _ := io.ReadAll(response.Body)
			return string(data) == "detached replica"
		})
		cancel()
		<-joined
		if _, err := detachedRequest(task, id, "stop"); err != nil {
			t.Fatal(err)
		}
		workflowWait(t, 20*time.Second, func() bool { _, err := os.Lstat(filepath.Join(detachedDir(task), id)); return os.IsNotExist(err) })
	}
	if f.groupEnrollmentRequests.Load() != 2 {
		t.Fatal("detached replacement enrolled another replica")
	}
}
