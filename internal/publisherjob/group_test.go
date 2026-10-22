package publisherjob

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestInstalledGroupTasksKeepIndependentProtectedKeys(t *testing.T) {
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
	groupID := newID("pgrp_")
	team := newID(opaqueid.TeamPrefix)
	var jobs []Job
	var keys []ed25519.PrivateKey
	for _, name := range []string{"one", "two"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		member := controlv1.PublisherGroupMember{TeamId: team, ProjectKey: "project-one", GroupName: "cluster", GroupId: groupID, PublisherIdentityId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix)}
		job := Job{Kind: KindGroup, ID: JobKey("https://control.example", "group", groupID+":"+name), Name: "cluster-" + name, Server: "https://control.example", PublisherID: member.PublisherIdentityId, GroupMember: &member, GroupInstance: name}
		if err := registry.InstallGroup(t.Context(), job, member, key); err != nil {
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
		member, key, _, err := registry.GroupIdentity(t.Context(), job)
		if err != nil || member != *job.GroupMember || !bytes.Equal(key, keys[index]) || bytes.Equal(key, keys[1-index]) {
			t.Fatalf("installed task key was shared or changed: %v", err)
		}
		if job.Project != nil || job.StateDir != "" {
			t.Fatal("installed group task depends on a person's project or state directory")
		}
		if err := registry.InstallGroup(t.Context(), job, member, keys[1-index]); !errors.Is(err, ErrScope) {
			t.Fatalf("installed group task replaced its key: %v", err)
		}
	}
}

func TestInstalledGroupIdentitySurvivesRuntimeDatabaseDeletion(t *testing.T) {
	options := testOptions(t)
	options.User = true
	registry, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	job, _, private := kindFixture(t, KindGroup)
	job.IdentityDir = filepath.Join(t.TempDir(), "identity")
	if err := registry.InstallGroup(t.Context(), job, *job.GroupMember, private); err != nil {
		t.Fatal(err)
	}
	profile, err := registry.Profile(t.Context(), job.Server)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := profile.SelectedPublisherIdentity(t.Context(), "job", "job:"+job.ID); err != nil || found {
		t.Fatal("installed group still depends on a SQLite signing key", err)
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
	member, restored, profile, err := registry.GroupIdentity(t.Context(), job)
	canonical, pathErr := filepath.EvalSymlinks(job.IdentityDir)
	if err != nil || pathErr != nil || member != *job.GroupMember || !bytes.Equal(restored, private) || profile.IdentityDirectory() != canonical {
		t.Fatal("fresh runtime lost its installed filesystem identity", err)
	}
	if err := registry.InstallGroup(t.Context(), job, member, private); err != nil {
		t.Fatal("reinstall could not reuse the durable key", err)
	}
	oldJob := job
	member.GroupName = "renamed"
	job.GroupMember = &member
	job.Name = "renamed-" + job.GroupInstance
	if err := registry.InstallGroup(t.Context(), job, member, private); err != nil {
		t.Fatal("selector rename replaced installed identity", err)
	}
	current, key, _, err := registry.GroupIdentity(t.Context(), oldJob)
	if err != nil || current != member || !bytes.Equal(key, private) {
		t.Fatal("old installed job lost renamed identity", err)
	}
}
