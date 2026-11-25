package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/background"
	"github.com/tnldotdev/tnl/internal/failure"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

const testExactJobID = "job_0123456789abcdefghijkl"

func TestJobCommandsAcceptOnlyExactJobIDs(t *testing.T) {
	for _, selector := range []string{"orders", "svc_0123456789abcdefghijkl", "job_0123456789", "../" + testExactJobID, testExactJobID + " "} {
		for _, command := range [][]string{{"stop"}, {"service", "start"}, {"service", "remove"}} {
			var flags cli
			if _, err := commandForTest(&flags, io.Discard)(append(command, selector)); err == nil {
				t.Errorf("%q accepted %q as a job ID", command, selector)
			}
		}
	}
	for _, retired := range [][]string{{"service", "list"}, {"service", "status"}, {"service", "stop"}, {"connect", "list"}, {"connect", "stop"}, {"connect", "remove"}} {
		var flags cli
		root := (&commandApp{flags: &flags, out: io.Discard, errOut: io.Discard}).root()
		parent, _, err := root.Find(retired[:1])
		if err != nil {
			t.Fatal(err)
		}
		for _, child := range parent.Commands() {
			if child.Name() == retired[1] {
				t.Errorf("retired command remains: %v", retired)
			}
		}
	}
}

func TestJobStatusMissingSupervisorIsEmptyAndDoesNotCreateState(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state, supervisor := filepath.Join(root, "client"), filepath.Join(root, "supervisor")
	var output bytes.Buffer
	if err := run(t.Context(), []string{"status", "--bg", "--state-dir", state, "--system-state-dir", supervisor, "--output=json"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if output.String() != "{\"schema_version\":1,\"jobs\":[]}\n" {
		t.Fatalf("empty list: %s", &output)
	}
	for _, path := range []string{state, supervisor} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("status changed %s: %v", path, err)
		}
	}
}

func TestJobCommandsUseBackgroundAndInstalledStateWithoutProject(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state, supervisor := filepath.Join(root, "client"), filepath.Join(root, "supervisor")
	flags := []string{"--state-dir", state, "--system-state-dir", supervisor, "--output=json"}
	invoke := func(commands ...string) (string, error) {
		var out bytes.Buffer
		args := append([]string{"--config", filepath.Join(root, "missing-config.yml")}, commands...)
		err := run(t.Context(), append(args, flags...), &out, io.Discard)
		return out.String(), err
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var child background.Entry
	if err := background.Launch(t.Context(), background.LaunchOptions{StateDir: state, Binary: binary, Kind: background.KindPublish,
		Args: []string{"-test.run=^TestJobStatusChild$", "-tnl-job-status-fixture"}}, func(_ context.Context, entry background.Entry) error {
		child = entry
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := background.Stop(ctx, state, child.JobID); err != nil && !errors.Is(err, background.ErrNotFound) {
			t.Error(err)
		}
	})
	assertList := func(want map[string]string) {
		t.Helper()
		text, err := invoke("status", "--bg")
		if err != nil {
			t.Fatal(err)
		}
		var list struct {
			SchemaVersion int         `json:"schema_version"`
			Jobs          []jobStatus `json:"jobs"`
		}
		if err := json.Unmarshal([]byte(text), &list); err != nil || list.SchemaVersion != 1 || len(list.Jobs) != len(want) {
			t.Fatalf("unexpected list: %s (%v)", text, err)
		}
		for _, job := range list.Jobs {
			if want[job.JobID] != job.Mode || job.Scope != "user" {
				t.Fatalf("unexpected job: %+v", job)
			}
		}
	}
	assertList(map[string]string{child.JobID: "background"})

	registry, err := installedjobs.Open(t.Context(), installedjobs.OpenOptions{Root: supervisor, User: true})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	job := installStatusFixture(t, registry)
	assertList(map[string]string{child.JobID: "background", job.ID: "installed"})
	for id, want := range map[string]jobStatus{
		child.JobID: {Mode: "background", Address: "https://bg.example", ServiceID: "svc_0123456789abcdefghijkl", State: "ready"},
		job.ID:      {Mode: "installed", ServiceID: job.ServiceID, State: "starting"},
	} {
		text, err := invoke("status", id)
		var got jobStatus
		if err != nil || json.Unmarshal([]byte(text), &got) != nil || got.JobID != id || got.Mode != want.Mode ||
			got.State != want.State || got.ServiceID != want.ServiceID || got.Address != want.Address {
			t.Fatalf("wrong selected job %s: %s (%v)", id, text, err)
		}
	}
	for id, want := range map[string]string{child.JobID: "stopped", job.ID: "stopping"} {
		text, err := invoke("stop", id)
		var got jobStatus
		if err != nil || json.Unmarshal([]byte(text), &got) != nil || got.JobID != id || got.State != want {
			t.Fatalf("stop %s: %s (%v)", id, text, err)
		}
	}
	saved, err := registry.ResolveJob(t.Context(), job.ID)
	if err != nil || saved.Enabled || saved.GrantID != job.GrantID {
		t.Fatalf("installed publisher was removed instead of disabled: %+v (%v)", saved, err)
	}
	if _, err := registry.Credential(t.Context(), saved); err != nil {
		t.Fatalf("stop removed the installed credential: %v", err)
	}
	text, err := invoke("status", child.JobID)
	if reason, _ := failure.ReasonOf(err); reason != failure.ServerResourceNotFound || text != "" {
		t.Fatalf("stopped background job still appeared: %s (%v)", text, err)
	}
}

func installStatusFixture(t *testing.T, registry *installedjobs.Registry) installedjobs.Job {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job := installedjobs.Job{Kind: installedjobs.KindService, Name: "orders", Server: "https://control.example", ServiceID: "svc_0123456789abcdefghijkl",
		PublisherIdentityID: "pub_0123456789abcdefghijkl", GrantID: "pgrant_0123456789abcdefghijkl", TrustRevision: 1, Protocol: "http", Target: "http://127.0.0.1:3000"}
	identity := authorityv1.PublisherEnrollmentResult{Kind: authorityv1.Service, ClientId: job.PublisherIdentityID, GrantId: job.GrantID,
		ServiceId: &job.ServiceID, KeyId: "pkey_0123456789abcdefghijkl", TeamId: "team"}
	job, err = registry.Install(t.Context(), job, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

var jobStatusFixture = flag.Bool("tnl-job-status-fixture", false, "run the background job status test child")

func TestJobStatusChild(t *testing.T) {
	if !*jobStatusFixture {
		return
	}
	if err := background.RunChild(t.Context(), func(ctx context.Context, _ background.Bootstrap) error {
		if err := background.Ready(ctx, background.Readiness{Address: "https://bg.example", ServiceID: "svc_0123456789abcdefghijkl"}); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
