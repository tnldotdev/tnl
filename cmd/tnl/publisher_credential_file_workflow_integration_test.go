package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationCLINamedPublisherCredentialFileWithoutPersonSession(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real CLI state protection is qualified in Linux")
	}
	if !*cliWorkflowChild {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestIntegrationCLINamedPublisherCredentialFileWithoutPersonSession$", "-test.v", "-test.timeout=90s", "-tnl-test-tier=integration", "-tnl-test-postgres-url="+flag.Lookup("tnl-test-postgres-url").Value.String(), "-tnl-cli-workflow-child")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("publisher-file CLI workflow: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "publisher-file workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	team := session.Identity().PersonalTeamId
	root := t.TempDir()
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/cli/publisher-file.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture Git setup: %v %s", err, output)
		}
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "scoped named publisher") }))
	defer target.Close()
	configuration := filepath.Join(root, "selected.json")
	data, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{"services": map[string]any{"api": map[string]any{"name": "portable", "target": map[string]any{"type": "address", "address": target.URL}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	document, err := config.LoadDocument(configuration)
	if err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{Project: clientproject.Project{Selection: clientproject.Selection{Path: configuration, Explicit: true}, Config: *document.TNL, Root: root, Worktree: clientproject.Worktree{Root: root, IsGit: true, Label: clientproject.WorktreeLabel{FullLabel: "portable-worktree"}}}}
	current, err := session.Current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	realized, err := invocation.RealizeLocalService(t.Context(), session.Authenticated().Control, invocation.LocalService{Project: project.Project, Team: invocation.FromTeamContext(current), Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := session.Authenticated().Control.GetService(t.Context(), realized.ServiceId)
	if err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(root, "publisher.json")
	cliCall(t, t.Context(), []string{"--no-config", "publisher", "provision", "--service", saved.Id, "--output-file", credential, "--server", f.url, "--team", team, "--state-dir", person})
	identity, err := credentialfile.Read(credential)
	if err != nil {
		t.Fatal(err)
	}
	assertWorkflowPublisherRuntime(t, session.Authenticated().Control, team, identity.PublisherIdentityID, 0, false)
	publisherState := f.state(t, "file-only-publisher")
	ctx, stop := context.WithCancel(t.Context())
	ready, joined := f.command(t, ctx, stop, []string{"--config", configuration, "publish", "api", "--foreground", "--publisher-credential-file", credential, "--state-dir", publisherState})
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("named scoped publisher did not become ready")
	}
	runtime := assertWorkflowPublisherRuntime(t, session.Authenticated().Control, team, identity.PublisherIdentityID, 1, true)
	listener := workflowListen(t)
	address := listener.Addr().String()
	_ = listener.Close()
	connectCtx, stopConnect := context.WithCancel(t.Context())
	_, connectorJoined := f.command(t, connectCtx, stopConnect, []string{"--no-config", "connect", saved.Id, "--listen", address, "--server", f.url, "--state-dir", person})
	client := workflowNativeHTTPClient(t, f, saved.Endpoint.Hostname)
	workflowWait(t, 15*time.Second, func() bool {
		response, err := client.Get("https://" + address + "/private-api")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode == http.StatusOK && string(body) == "scoped named publisher"
	})
	state, err := clientstate.Open(t.Context(), publisherState)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	profile, err := state.Server(t.Context(), f.url)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
		t.Fatalf("scoped named publication fell back to a person session: found=%t err=%v", found, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".tnl", "local", "project.json")); !os.IsNotExist(err) {
		t.Fatalf("credential-owned named publication entered browser preparation: %v", err)
	}
	stopConnect()
	select {
	case <-connectorJoined:
	case <-time.After(20 * time.Second):
		t.Fatal("foreground connector did not join before publisher shutdown")
	}
	stop()
	select {
	case <-joined:
	case <-time.After(20 * time.Second):
		t.Fatal("foreground publisher did not join")
	}
	stopped := assertWorkflowPublisherRuntime(t, session.Authenticated().Control, team, identity.PublisherIdentityID, 1, false)
	if stopped.ProcessRunId != runtime.ProcessRunId {
		t.Fatal("foreground stop replaced runtime ownership")
	}
	t.Log("real CLI named private HTTP used only --publisher-credential-file, carried visitor bytes, and created no person session or browser metadata")
}
