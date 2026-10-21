package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationCLIGroupIdentitySurvivesTaskStateDeletion(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	identityDir := filepath.Join(t.TempDir(), "identities")
	person := f.state(t, "person")
	t.Setenv("TNL_GROUP_ENROLL_KEY", "")
	t.Setenv("TNL_GROUP_IDENTITY", "")
	if err := os.Unsetenv("TNL_GROUP_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "portable group workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	team, control := session.identity.PersonalTeamId, session.authenticated.Control
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/cli/portable.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture Git setup: %v %s", err, output)
		}
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "portable group worker") }))
	defer target.Close()
	if err := os.WriteFile(filepath.Join(root, "target.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(root, "tnl.json")
	data, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{"server": f.url, "team": team, "publishers": map[string]any{"production": map[string]any{}}, "services": map[string]any{
		"api": map[string]any{"publisher": "production", "target": map[string]any{"type": "address", "address": target.URL, "tls": map[string]any{"server_name": "example.com", "ca_file": "target.pem"}}, "access": map[string]any{"team": true}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	var applied controlv1.AppliedProjectConfiguration
	if err := json.Unmarshal(cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--state-dir", person, "--output", "json"}), &applied); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(t.TempDir(), "replica.json")
	provision := []string{"--config", configuration, "publisher", "provision", "--group", "production", "--instance", "replica-1", "--output-file", credential, "--state-dir", person}
	output := cliCall(t, t.Context(), provision)
	value, err := credentialfile.ReadGroup(credential)
	if err != nil {
		t.Fatal(err)
	}
	if value.ControlURL != f.url || value.Member.ProjectKey != applied.ProjectKey || value.Member.TeamId != team || value.Instance != "replica-1" || bytes.Contains(output, []byte(value.PrivateKey)) {
		t.Fatal("provision lost its resolved project/team/server or exposed the signing key")
	}
	if info, err := os.Lstat(credential); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("provision did not produce a private file")
	}
	if f.groupEnrollmentRequests.Load() != 2 {
		t.Fatalf("provision should issue and redeem once; enrollment requests=%d", f.groupEnrollmentRequests.Load())
	}
	if err := run(t.Context(), provision, io.Discard, io.Discard); err == nil {
		t.Fatal("provision overwrote its private output file")
	}
	if f.groupEnrollmentRequests.Load() != 2 {
		t.Fatal("no-clobber retry mutated remote enrollment state")
	}
	// another output path for the same replica exports the protected identity.
	provision[len(provision)-3] = filepath.Join(t.TempDir(), "same-replica.json")
	cliCall(t, t.Context(), provision)
	retried, err := credentialfile.ReadGroup(provision[len(provision)-3])
	if err != nil || retried != value || f.groupEnrollmentRequests.Load() != 2 {
		t.Fatal("provision retry enrolled another member or changed the signing identity", err)
	}
	assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, 0, false)
	encoded, err := os.ReadFile(credential)
	if err != nil {
		t.Fatal(err)
	}
	forged := testPublisherGroupIdentity(t)
	forged.ControlURL, forged.Instance, forged.Member = value.ControlURL, value.Instance, value.Member
	wrongCredential := filepath.Join(t.TempDir(), "wrong-key.json")
	if err := credentialfile.WriteGroup(wrongCredential, forged); err != nil {
		t.Fatal(err)
	}
	task := f.state(t, "task")
	// an unrelated saved server must not override the file's bound control URL.
	state, err := clientstate.Open(t.Context(), task)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SaveServer(t.Context(), "https://unrelated.example"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	listener := workflowListen(t)
	address := listener.Addr().String()
	_ = listener.Close()
	connectCtx, stopConnect := context.WithCancel(t.Context())
	if len(applied.Services) != 1 || applied.Services[0].ServiceId == nil {
		t.Fatal("missing private service binding")
	}
	service, err := control.GetPrivateService(t.Context(), *applied.Services[0].ServiceId)
	if err != nil || service.ManagedTls == nil {
		t.Fatal("missing managed service endpoint", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: service.ManagedTls.Hostname}}, Timeout: 2 * time.Second}
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(t.Context())
	f.certificateWorkPaused.Store(true)
	var firstIssuance string
	for replacement := range 4 {
		selector := "production"
		if replacement == 1 || replacement == 3 {
			selector = "live"
		}
		args := []string{"--no-config", "publisher", "serve", "--server", f.url, "--group", selector, "--project-key", applied.ProjectKey, "--instance", "replica-1", "--state-dir", task, "--identity-dir", identityDir}
		if replacement == 0 {
			args = append(args, "--identity-file", credential)
		} else if replacement == 1 {
			if err := os.Setenv("TNL_GROUP_IDENTITY", string(encoded)); err != nil {
				t.Fatal(err)
			}
		} else if replacement == 3 {
			args = append(args, "--identity-file", credential)
		}
		ctx, stop := context.WithCancel(t.Context())
		ready, joined := f.command(t, ctx, stop, args)
		if replacement == 0 {
			workflowWait(t, 15*time.Second, func() bool {
				return inspect.QueryRow(t.Context(), `SELECT issuance.id FROM control.acme_orders issuance JOIN control.private_service_runs run ON run.id=issuance.private_run_id WHERE run.publisher_identity_id=$1 ORDER BY issuance.created_revision LIMIT 1`, value.Member.PublisherIdentityId).Scan(&firstIssuance) == nil
			})
			runtime := assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, 1, true)
			var oldRun string
			var oldLease []byte
			if err := inspect.QueryRow(t.Context(), `SELECT id FROM control.private_service_runs WHERE publisher_identity_id=$1 AND closed_at IS NULL`, value.Member.PublisherIdentityId).Scan(&oldRun); err != nil {
				t.Fatal(err)
			}
			// an OLD task keeps polling while a manager renames and re-exports its
			// exact member. verification must not replace that task's lease/run.
			cliCall(t, t.Context(), []string{"--config", configuration, "publisher", "rename", "production", "live", "--state-dir", person})
			applied, err = control.GetProjectConfiguration(t.Context(), team, applied.ProjectKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := inspect.QueryRow(t.Context(), `SELECT token_digest FROM control.publisher_group_leases WHERE publisher_identity_id=$1`, value.Member.PublisherIdentityId).Scan(&oldLease); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"live", "production"} {
				exported := filepath.Join(t.TempDir(), "renamed.json")
				cliCall(t, t.Context(), []string{"--no-config", "publisher", "provision", "--server", f.url, "--team", team, "--project-key", applied.ProjectKey, "--group", name, "--instance", "replica-1", "--output-file", exported, "--state-dir", person})
				repeated, err := credentialfile.ReadGroup(exported)
				if err != nil || repeated.PrivateKey != value.PrivateKey || !credentialfile.SameGroupIdentity(repeated.Member, value.Member) || repeated.Member.GroupName != "live" {
					t.Fatal("renamed provision replaced identity", err)
				}
			}
			workflowWait(t, 12*time.Second, func() bool {
				status, err := control.GetProjectConfiguration(t.Context(), team, applied.ProjectKey)
				return err == nil && len(status.Members) == 1 && status.Members[0].ObservedRevision == applied.Revision
			})
			var keptRun string
			var keptLease []byte
			if err := inspect.QueryRow(t.Context(), `SELECT id FROM control.private_service_runs WHERE publisher_identity_id=$1 AND closed_at IS NULL`, value.Member.PublisherIdentityId).Scan(&keptRun); err != nil || keptRun != oldRun {
				t.Fatal("selector rename restarted publication", err)
			}
			if err := inspect.QueryRow(t.Context(), `SELECT token_digest FROM control.publisher_group_leases WHERE publisher_identity_id=$1`, value.Member.PublisherIdentityId).Scan(&keptLease); err != nil || !bytes.Equal(oldLease, keptLease) {
				t.Fatal("provision rotated running task lease", err)
			}
			if kept := assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, 1, true); kept.ProcessRunId != runtime.ProcessRunId {
				t.Fatal("provision replaced running task observation")
			}
			statusOutput := cliCall(t, t.Context(), []string{"--config", configuration, "status", "--scope", "server", "--state-dir", person})
			if !strings.Contains(string(statusOutput), "live") {
				t.Fatal("status retained the old selector")
			}
			stop()
			select {
			case <-joined:
			case <-time.After(20 * time.Second):
				t.Fatal("pending issuer did not join before state deletion")
			}
			missing := f.state(t, "missing-certificate-state")
			missingErr := run(t.Context(), []string{"--no-config", "publisher", "serve", "--group", "production", "--project-key", applied.ProjectKey, "--instance", "replica-1", "--identity-file", credential, "--state-dir", missing}, io.Discard, io.Discard)
			if reason, _ := failure.ReasonOf(missingErr); reason != failure.PublisherCertificateStateMissing {
				t.Fatal("identity-only replacement silently generated fresh certificate keys", missingErr)
			}
			if err := run(t.Context(), []string{"--no-config", "publisher", "serve", "--group", "production", "--project-key", applied.ProjectKey, "--instance", "replica-1", "--identity-file", wrongCredential, "--state-dir", task}, io.Discard, io.Discard); err == nil {
				t.Fatal("invalid signing key fell back to the saved group identity")
			}
			assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, 1, false)
			if err := os.RemoveAll(task); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if replacement == 1 {
			workflowWait(t, 15*time.Second, func() bool {
				var requests int
				err := inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.private_certificate_requests request JOIN control.private_service_runs run ON run.id=request.private_run_id WHERE request.issuance_id=$1 AND run.publisher_identity_id=$2`, firstIssuance, value.Member.PublisherIdentityId).Scan(&requests)
				return err == nil && requests >= 2
			})
			f.certificateWorkPaused.Store(false)
		}
		select {
		case <-ready:
		case <-time.After(25 * time.Second):
			t.Fatal("restored identity did not run its assigned private publisher")
		}
		assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, int64(replacement+1), true)
		if replacement == 1 {
			// connector readiness now verifies managed TLS. start only after the
			// recovered publisher has installed the paused certificate, then keep
			// this same connector through the later publisher replacements.
			connectReady, _ := f.command(t, connectCtx, stopConnect, []string{"--no-config", "connect", "api", "--team", team, "--listen", address, "--server", f.url, "--state-dir", person})
			select {
			case <-connectReady:
			case <-time.After(25 * time.Second):
				t.Fatal("connector did not verify the recovered publisher")
			}
		}
		if _, supplied := os.LookupEnv("TNL_GROUP_IDENTITY"); supplied {
			t.Fatal("injected identity remains in the worker environment")
		}
		workflowWait(t, 10*time.Second, func() bool {
			response, err := client.Get("https://" + address + "/replacement")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			return response.StatusCode == http.StatusOK && string(body) == "portable group worker"
		})
		status, err := control.GetProjectConfiguration(t.Context(), team, applied.ProjectKey)
		if err != nil || len(status.Members) != 1 || status.Members[0].PublisherIdentityId != value.Member.PublisherIdentityId || !status.Members[0].Healthy || status.Members[0].ObservedRevision != applied.Revision {
			t.Fatal("replacement changed membership or did not acknowledge its assignment", err)
		}
		state, err := clientstate.Open(t.Context(), task)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := state.Server(t.Context(), f.url)
		if err != nil {
			t.Fatal(err)
		}
		saved, found, err := profile.SelectedPublisherIdentity(t.Context(), "project", credentialfile.GroupSelection(applied.ProjectKey, value.Member.GroupId, "replica-1"))
		if err != nil || !found || saved.ID != value.Member.PublisherIdentityId {
			t.Fatal("CLI did not save the restored signing identity", err)
		}
		if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
			t.Fatal("group import created a person session", err)
		}
		var installed string
		if err := inspect.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.private_service_runs WHERE publisher_identity_id=$1 AND closed_at IS NULL ORDER BY run_number DESC LIMIT 1`, value.Member.PublisherIdentityId).Scan(&installed); err != nil || installed != firstIssuance {
			t.Fatal("task-local state deletion changed the installed certificate issuance", err)
		}
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
		if f.groupEnrollmentRequests.Load() != 2 {
			t.Fatal("replacement attempted enrollment")
		}
		if replacement == 3 {
			oldHostname := service.ManagedTls.Hostname
			cliCall(t, t.Context(), []string{"--config", configuration, "publisher", "namespace", "rename", "production", "new-dns", "--expected-revision", strconv.FormatInt(applied.Revision, 10), "--request-id", "dns-move", "--state-dir", person})
			project, err := loadProjectConfiguration(t.Context(), cli{ConfigPath: configuration}, person)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := selectConnectService(t.Context(), control, project, "api", team)
			if err != nil {
				t.Fatal(err)
			}
			native, err := serviceConnectionProfile(selected, "127.0.0.1:25443")
			if err != nil || native.Hostname == oldHostname || native.ServiceID != service.Id {
				t.Fatal("source-bound native profile kept old hostname or changed identity", err)
			}
			newClient := workflowNativeHTTPClient(t, f, native.Hostname)
			workflowWait(t, 25*time.Second, func() bool {
				response, err := newClient.Get("https://" + address + "/renamed-dns")
				if err != nil {
					return false
				}
				defer response.Body.Close()
				body, _ := io.ReadAll(response.Body)
				return response.StatusCode == http.StatusOK && string(body) == "portable group worker"
			})
			if response, err := client.Get("https://" + address + "/old-name"); err == nil {
				_ = response.Body.Close()
				t.Fatal("old hostname still authenticated the new namespace")
			}
			updated, err := control.GetPrivateService(t.Context(), service.Id)
			if err != nil || updated.ManagedTls.Hostname != native.Hostname || updated.ManagedTls.Port != service.ManagedTls.Port {
				t.Fatal("namespace change lost port or service", err)
			}
		}
		stop()
		select {
		case <-joined:
		case <-time.After(20 * time.Second):
			t.Fatal("group worker did not join before task-state deletion")
		}
		assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, int64(replacement+1), false)
		if err := os.RemoveAll(task); err != nil {
			t.Fatal(err)
		}
	}
	// installed jobs keep immutable membership even when their captured selector
	// predates a rename. run the actual user supervisor against its saved job.
	supervisorRoot := filepath.Join(t.TempDir(), "supervisor")
	registry, err := publisherjob.Open(t.Context(), publisherjob.OpenOptions{Root: supervisorRoot, User: true})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	private, err := value.Validate(f.url, applied.ProjectKey, "production", "replica-1")
	if err != nil {
		t.Fatal(err)
	}
	job := publisherjob.Job{Kind: publisherjob.KindGroup, ID: publisherjob.JobKey(f.url, "group", value.Member.GroupId+":replica-1"), Name: "production-replica-1", Server: f.url, PublisherID: value.Member.PublisherIdentityId, GroupMember: &value.Member, GroupInstance: "replica-1", IdentityDir: identityDir}
	if err := registry.InstallGroup(t.Context(), job, value.Member, private); err != nil {
		t.Fatal(err)
	}
	supervisorCtx, stopSupervisor := context.WithCancel(t.Context())
	supervisorDone := make(chan error, 1)
	go func() {
		supervisorDone <- runServiceServe(supervisorCtx, serviceServeCommand{systemStateFlags: systemStateFlags{SystemStateDir: supervisorRoot, User: true}})
	}()
	t.Cleanup(func() {
		stopSupervisor()
		select {
		case <-supervisorDone:
		case <-time.After(20 * time.Second):
			t.Error("installed supervisor did not join")
		}
	})
	workflowWait(t, 25*time.Second, func() bool {
		jobs, err := registry.List(t.Context())
		return err == nil && len(jobs) == 1 && jobs[0].Status.State == "ready"
	})
	assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, 5, true)
	var installedStatus bytes.Buffer
	if err := writeSystemJobs(t.Context(), registry, &installedStatus, "tnl service status", job.ID); err != nil || !strings.Contains(installedStatus.String(), "live") {
		t.Fatal("installed status retained old selector", err)
	}
	if f.groupEnrollmentRequests.Load() != 2 {
		t.Fatal("installed supervisor enrolled a replacement identity")
	}
	stopSupervisor()
	if err := <-supervisorDone; err != nil {
		t.Fatal(err)
	}
	close(supervisorDone)
	assertWorkflowPublisherRuntime(t, control, team, value.Member.PublisherIdentityId, 5, false)
	if err := control.RevokePublisherGroupMember(t.Context(), team, applied.ProjectKey, "production", value.Member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), []string{"--no-config", "publisher", "serve", "--group", "production", "--project-key", applied.ProjectKey, "--instance", "replica-1", "--identity-file", credential, "--state-dir", person}, io.Discard, io.Discard); err == nil {
		t.Fatal("revoked identity fell back to another publisher")
	}
	if f.groupEnrollmentRequests.Load() != 2 {
		t.Fatal("revoked identity fell back to enrollment")
	}
	t.Log("CLI provision -> pending CSR -> delete runtime SQLite -> recover the same issuance and visitor bytes -> delete runtime state and omit bootstrap -> same filesystem identity, certificate and traffic without enrollment")
}
