package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestFeedbackCommandsUseOnlyLocalContentAndDeleteWholeThread(t *testing.T) {
	const preview = "pv_0123456789abcdefghijkl"
	const service = "svc_0123456789abcdefghijkl"
	const runID = "srun_0123456789abcdefghijkl"
	const identity = "ident_0123456789abcdefghijkl"
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	decisions := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("lost signed-in CLI authority")
			w.WriteHeader(401)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated", Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: "device_code"}}})
		case "GET /v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{PersonalTeamId: statusTestTeamOne, Memberships: []authorityv1.Membership{{TeamId: statusTestTeamOne, Role: "owner"}}})
		case "GET /v1/teams/" + statusTestTeamOne:
			_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: statusTestTeamOne, DisplayName: "personal", Kind: "personal"})
		case "POST /v1/feedback/authorization":
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 || strings.Contains(string(raw), "private") {
				t.Error("CLI sent feedback content to control")
			}
			var body controlv1.AuthorizeImplementerFeedbackRequest
			if json.Unmarshal(raw, &body) != nil || body.PreviewId != preview || body.ServiceId != service {
				t.Error("CLI lost exact local scope")
			}
			decisions++
			_ = json.NewEncoder(w).Encode(controlv1.FeedbackAuthorization{PreviewId: preview, ServiceId: service, Operation: body.Operation, Actor: "implementer", ExpiresAt: time.Now().Add(4 * time.Second), Author: controlv1.FeedbackAuthor{IdentityId: new(identity), DisplayName: "CLI author", Verified: true}})
		default:
			t.Errorf("CLI used a retired content endpoint: %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	transport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = transport }()
	t.Setenv("TNL_ACCESS_TOKEN", access.String())
	state := statusTestDatabase(t)
	profile, err := state.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	project := projectConfiguration{Project: clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")}, Config: config.TNL{Services: config.Services{"web": {}}}}}
	project.Project, err = project.Project.BindLocalIdentity(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err = profile.SavePreviewID(t.Context(), statusTestTeamOne, project.LocalWorktreeKey(), preview); err != nil {
		t.Fatal(err)
	}
	local, err := profile.Feedback(t.Context(), project.LocalPublicationIdentity().Fingerprint, preview, func(_ context.Context, selected, operation string) (controlv1.FeedbackAuthorization, error) {
		return controlv1.FeedbackAuthorization{PreviewId: preview, ServiceId: selected, ServiceRunId: runID, RunNumber: 1, Operation: controlv1.FeedbackOperation(operation), Actor: "reviewer", ExpiresAt: time.Now().Add(4 * time.Second), Author: controlv1.FeedbackAuthor{IdentityId: new(identity), DisplayName: "Reviewer", Verified: true}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	body := controlv1.CreateFeedbackReportRequest{PreviewId: preview, RunNumber: 1, Service: "web", PagePath: "/", Evidence: controlv1.FeedbackEvidence{SchemaVersion: 1}, SourceAtReport: controlv1.SourceState{SchemaVersion: 1, ChangedFiles: []controlv1.SourceFileState{}}}
	body.Report.Text = "private local report"
	thread, err := local.Create(t.Context(), service, runID, "report", body)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	project.Worktree, err = clientproject.ResolveWorktree(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	project.Project, err = project.Project.BindLocalIdentity(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	flags := scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: server.URL, StateDir: state.Root(), AccessToken: access.String()}}
	var output bytes.Buffer
	if err = runFeedbackList(t.Context(), feedbackListCommand{scopedTeamFlags: flags, Output: feedbackJSON}, project, &output, io.Discard); err != nil || !strings.Contains(output.String(), body.Report.Text) {
		t.Fatal("CLI did not read local feedback", output.String(), err)
	}
	output.Reset()
	if err = runFeedbackMutation(t.Context(), feedbackMutationCommand{scopedTeamFlags: flags, FeedbackID: thread.Id, Message: "private local reply", Output: feedbackJSON}, project, "reply", &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err = runFeedbackInspect(t.Context(), feedbackInspectCommand{scopedTeamFlags: flags, FeedbackID: thread.Id, Output: feedbackJSON}, project, &output, io.Discard); err != nil || !strings.Contains(output.String(), "private local reply") {
		t.Fatal("CLI did not read complete local history", output.String(), err)
	}
	output.Reset()
	if err = runFeedbackDelete(t.Context(), feedbackDeleteCommand{scopedTeamFlags: flags, FeedbackID: thread.Id}, project, &output, io.Discard); err != nil || !strings.Contains(output.String(), "deleted") {
		t.Fatal("CLI deletion failed", output.String(), err)
	}
	output.Reset()
	err = runFeedbackInspect(t.Context(), feedbackInspectCommand{scopedTeamFlags: flags, FeedbackID: thread.Id, Output: feedbackJSON}, project, &output, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResourceNotFound || output.Len() != 0 {
		t.Fatal("deleted thread remained readable", output.String(), err)
	}
	if decisions < 4 {
		t.Fatal("CLI reused feedback authorization")
	}
}
