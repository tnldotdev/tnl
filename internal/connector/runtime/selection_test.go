package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

func TestBorrowedConnectionChecksCapturedProjectAndDeploymentBeforePreparation(t *testing.T) {
	scope := fixtureScope(t)
	scope.TeamID, scope.TeamName, scope.Deployment = "tm_selected", "acme", "production"
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fixtureBackend{deadline: time.Now().Add(time.Hour)}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer func() { cancel(); <-done }()
	go func() { done <- Serve(ctx, scope, directory, "/test/tnl", OwnerConfig{Backend: backend}, writer) }()
	var status Status
	if err := json.NewDecoder(reader).Decode(&status); err != nil {
		t.Fatal(err)
	}
	for _, selection := range []ProjectDeploymentSelection{
		{Project: "other/project-test", Name: "production"},
		{Project: "acme/other", Name: "production"},
		{Project: "acme/project-test", Name: "staging"},
		{Project: "acme/project-test", Name: ""},
		{Project: "project-test", Name: "production"},
	} {
		request := Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database", Selection: &selection}
		if err := Call(ctx, status.ConnectionHandle, "prepare", request, new(Prepared)); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("borrowed connection accepted another selection", err)
		}
	}
	if backend.credential.Load() != 0 {
		t.Fatal("a rejected selection started visitor work")
	}
	for _, project := range []string{"acme/project-test", "tm_selected/project-test"} {
		request := Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database", Selection: &ProjectDeploymentSelection{Project: project, Name: "production"}}
		if err := Call(ctx, status.ConnectionHandle, "prepare", request, new(Prepared)); err != nil {
			t.Fatal("matching borrowed selection was rejected", err)
		}
	}
}
