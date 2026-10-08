package clientstate

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestAliasStatusFencesReadyRunsAndRetainsStoppedDefault(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	main, initial := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	selection, receiver, err := state.AliasCandidate(t.Context(), initial.ID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), scope.Server, selection.Hostname, "publisher"); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkAliasRunReady(t.Context(), AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "run", PublicURLID: id, Number: 1}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.SnapshotProject(t.Context(), scope.ProjectKey)
	if err != nil || snapshot.SchemaVersion != 3 || len(snapshot.Aliases) != 1 || snapshot.Aliases[0].State != "ready" {
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
