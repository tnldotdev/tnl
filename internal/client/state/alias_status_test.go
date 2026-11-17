package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestAliasStatusIgnoresStaleReadyRunsAndRetainsStoppedDefault(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	main, initial := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	selection, receiver, err := state.AliasCandidate(t.Context(), initial.ID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), scope.Server, selection.Hostname, "publisher", id, 1); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkAliasRunReady(t.Context(), AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "run", ServiceID: id, Number: 1}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.SnapshotProject(t.Context(), scope.ProjectKey)
	if err != nil || snapshot.SchemaVersion != 1 || len(snapshot.Aliases) != 1 || snapshot.Aliases[0].State != "ready" ||
		snapshot.Aliases[0].ServiceID != id || snapshot.Aliases[0].RunNumber != 1 {
		t.Fatalf("ready alias status = %v, %v", snapshot.Aliases, err)
	}
	if err := state.RecordAliasFailure(t.Context(), selection, failure.MemberHostnameDepthExceeded); err != nil {
		t.Fatal(err)
	}
	snapshot, err = state.SnapshotProject(t.Context(), scope.ProjectKey)
	if err != nil || snapshot.Aliases[0].Reason != failure.MemberHostnameDepthExceeded {
		t.Fatal("alias policy failure was not visible in status")
	}
	if err := main.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordAliasFailure(t.Context(), selection, ""); err != nil {
		t.Fatal(err)
	}
	snapshot, err = state.SnapshotProject(t.Context(), scope.ProjectKey)
	if err != nil || len(snapshot.Aliases) != 1 || snapshot.Aliases[0].SelectedProject != scope.ProjectKey || snapshot.Aliases[0].Reason != failure.AliasReceiverUnready {
		t.Fatal("stopped default alias disappeared or selected another worktree")
	}
}

func TestAliasReadyRunBindsServiceAndReceiverAtSameAddress(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	first, initial := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	selection, receiver, err := state.AliasCandidate(t.Context(), initial.ID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), scope.Server, selection.Hostname, "first", id, 1); err != nil {
		t.Fatal(err)
	}
	run := AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "first", ServiceID: id, Number: 1}
	if err := state.MarkAliasRunReady(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	if err := first.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	replacement, _ := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	_, current, err := state.AliasCandidate(t.Context(), initial.ID)
	if err != nil || current.ID != replacement.ID() || current.ServiceID == receiver.ServiceID || current.PublicURL != receiver.PublicURL {
		t.Fatalf("same-address replacement lost its identity: %+v, %v", current, err)
	}
	if err := state.MarkAliasRunReady(t.Context(), run); !errors.Is(err, ErrAliasSelectionStale) {
		t.Fatalf("old receiver refreshed alias readiness: %v", err)
	}
	snapshot, err := state.SnapshotProject(t.Context(), scope.ProjectKey)
	if err != nil || len(snapshot.Aliases) != 1 || snapshot.Aliases[0].State == "ready" {
		t.Fatalf("old alias run admitted a same-address replacement: %+v, %v", snapshot.Aliases, err)
	}
	nextID, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), scope.Server, selection.Hostname, "replacement", nextID, 1); err != nil {
		t.Fatal(err)
	}
	run.Receiver = current
	if err := state.MarkAliasRunReady(t.Context(), run); !errors.Is(err, ErrAliasSelectionStale) {
		t.Fatalf("old alias service reused replacement readiness: %v", err)
	}
	run.ServiceID, run.Owner = nextID, "replacement"
	if err := state.MarkAliasRunReady(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	if err := state.ClearAliasRun(t.Context(), selection.ID, "first"); err != nil {
		t.Fatal(err)
	}
	if err := state.ClearIntegrationURLReady(t.Context(), scope.Server, selection.Hostname, "first"); err != nil {
		t.Fatal(err)
	}
	snapshot, err = state.SnapshotProject(t.Context(), scope.ProjectKey)
	if err != nil || len(snapshot.Aliases) != 1 || snapshot.Aliases[0].State != "ready" || snapshot.Aliases[0].ServiceID != nextID {
		t.Fatalf("old owner cleared replacement readiness: %+v, %v", snapshot.Aliases, err)
	}
}
