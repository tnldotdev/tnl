package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/background"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationCLIDeploymentBackgroundHistoricalIdentity(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "background deployment rename", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	team, control := session.Identity().PersonalTeamId, session.Authenticated().Control
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "deployment replica") }))
	defer target.Close()
	applied, err := control.ApplyProjectConfiguration(t.Context(), "background", controlv1.ApplyProjectConfigurationRequest{Deployment: "production", ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": "http"}, TeamId: team, Source: &controlv1.GitProjectSource{GitOrigin: "https://example.test/example.git", ConfigurationPath: "tnl.yml"}, Configuration: controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Target: target.URL, Access: &controlv1.ProjectServiceAccess{Team: true}}}}})
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "old.json")
	cliCall(t, t.Context(), []string{"--no-config", "publisher", "provision", "--server", f.url, "--team", team, "--deployment", "production", "--service", "api", "--project-key", "background", "--instance", "replica-1", "--output-file", identity, "--state-dir", person})
	renamed, err := control.RenameDeployment(t.Context(), "background", "production", controlv1.RenameDeploymentRequest{TeamId: team, Name: "live", ExpectedRevision: applied.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Revision <= applied.Revision {
		t.Fatal("selector rename did not advance the project revision")
	}
	command := workflowBackgroundCLI(t, f)
	task := f.state(t, "publisher-task")
	t.Cleanup(func() { cleanupBackgroundJobs(t, task) })
	var previousJobID string
	for _, selector := range []string{"live", "production"} {
		result := command(t.Context(), "publisher", "serve", "--bg", "--output=json", "--deployment", selector, "--instance", "replica-1", "--identity-file", identity, "--state-dir", task)
		if result.err != nil || len(result.stderr) != 0 {
			t.Fatalf("background publisher with %s selector: %v %s", selector, result.err, result.stderr)
		}
		var receipt struct {
			SchemaVersion int    `json:"schema_version"`
			JobID         string `json:"job_id"`
			Mode          string `json:"mode"`
			Target        string `json:"target"`
		}
		if err := json.Unmarshal(result.stdout, &receipt); err != nil || receipt.SchemaVersion != 1 || receipt.Mode != "background" ||
			!opaqueid.Valid(receipt.JobID, opaqueid.JobPrefix) || receipt.JobID == previousJobID || receipt.Target != "live/replica-1" {
			t.Fatalf("invalid receipt for %s selector: %s (%v)", selector, result.stdout, err)
		}
		previousJobID = receipt.JobID
		job, err := background.Status(t.Context(), task, receipt.JobID)
		if err != nil || job.State != background.StateReady || job.Kind != background.KindPublisher || job.Target != receipt.Target {
			t.Fatalf("receipt does not identify the ready deployment publisher: %+v (%v)", job, err)
		}
		workflowWait(t, 25*time.Second, func() bool {
			status, err := control.GetProjectConfiguration(t.Context(), team, "background", "live")
			return err == nil && len(status.Members) == 1 && status.Members[0].Healthy && status.Members[0].DeploymentName == "live" && status.Members[0].ObservedRevision == applied.Revision && status.Members[0].CurrentRevision == applied.Revision
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
			response, err := client.Get("https://" + address + "/deployment")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			data, _ := io.ReadAll(response.Body)
			return string(data) == "deployment replica"
		})
		cancel()
		<-joined
		if _, err := background.Stop(t.Context(), task, receipt.JobID); err != nil {
			t.Fatal(err)
		}
		waitBackgroundJobExit(t, t.Context(), task, receipt.JobID)
	}
	if f.deploymentEnrollmentRequests.Load() != 2 {
		t.Fatal("background replacement enrolled another replica")
	}
}
