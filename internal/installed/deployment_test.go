package installed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestInstalledDeploymentTasksKeepIndependentProtectedKeys(t *testing.T) {
	options := testOptions(t)
	options.User = true
	registry, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	newID := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	deploymentID := newID("dpl_")
	team := newID(opaqueid.TeamPrefix)
	var jobs []Job
	var keys []ed25519.PrivateKey
	for _, name := range []string{"one", "two"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		member := controlv1.DeploymentPublisherIdentity{TeamId: team, ProjectKey: "project-one", DeploymentName: "cluster", DeploymentId: deploymentID, PublisherIdentityId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix)}
		job := Job{Kind: KindDeployment, ID: JobKey("https://control.example", "deployment", deploymentID+":"+name), Name: "cluster-" + name, Server: "https://control.example", PublisherIdentityID: member.PublisherIdentityId, DeploymentMember: &member, DeploymentInstance: name}
		if err := registry.InstallDeployment(t.Context(), job, member, key); err != nil {
			t.Fatal(err)
		}
		jobs = append(jobs, job)
		keys = append(keys, key)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err = Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	for index, job := range jobs {
		member, key, _, err := registry.DeploymentIdentity(t.Context(), job)
		if err != nil || member != *job.DeploymentMember || !bytes.Equal(key, keys[index]) || bytes.Equal(key, keys[1-index]) {
			t.Fatalf("installed task key was shared or changed: %v", err)
		}
		if job.Project != nil || job.StateDir != "" {
			t.Fatal("installed deployment task depends on a person's project or state directory")
		}
		if err := registry.InstallDeployment(t.Context(), job, member, keys[1-index]); !errors.Is(err, ErrScope) {
			t.Fatalf("installed deployment task replaced its key: %v", err)
		}
	}
}

func TestInstalledDeploymentIdentitySurvivesRuntimeDatabaseDeletion(t *testing.T) {
	options := testOptions(t)
	options.User = true
	registry, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	job, _, private := kindFixture(t, KindDeployment)
	job.IdentityDir = filepath.Join(t.TempDir(), "identity")
	if err := registry.InstallDeployment(t.Context(), job, *job.DeploymentMember, private); err != nil {
		t.Fatal(err)
	}
	profile, err := registry.Profile(t.Context(), job.Server)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := profile.SelectedPublisherIdentity(t.Context(), "job", "job:"+job.ID); err != nil || found {
		t.Fatal("installed deployment still depends on a SQLite signing key", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(options.Root); err != nil {
		t.Fatal(err)
	}
	registry, err = Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	member, restored, profile, err := registry.DeploymentIdentity(t.Context(), job)
	canonical, pathErr := filepath.EvalSymlinks(job.IdentityDir)
	if err != nil || pathErr != nil || member != *job.DeploymentMember || !bytes.Equal(restored, private) || profile.IdentityDirectory() != canonical {
		t.Fatal("fresh runtime lost its installed filesystem identity", err)
	}
	if err := registry.InstallDeployment(t.Context(), job, member, private); err != nil {
		t.Fatal("reinstall could not reuse the durable key", err)
	}
	oldJob := job
	member.DeploymentName = "renamed"
	job.DeploymentMember = &member
	job.Name = "renamed-" + job.DeploymentInstance
	if err := registry.InstallDeployment(t.Context(), job, member, private); err != nil {
		t.Fatal("selector rename replaced installed identity", err)
	}
	current, key, _, err := registry.DeploymentIdentity(t.Context(), oldJob)
	if err != nil || current != member || !bytes.Equal(key, private) {
		t.Fatal("old installed job lost renamed identity", err)
	}
}
