package clientstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func aliasTestScope(t *testing.T) AliasScope {
	t.Helper()
	return AliasScope{Server: "https://control.example.test", ProjectKey: filepath.Join(t.TempDir(), "main"),
		TeamID: "team_fixture", MembershipID: "membership_fixture", Namespace: "member.example.test", Name: "review"}
}

func aliasTestTunnel(t *testing.T, state *Database, scope AliasScope, project, label string, ready bool) (*Tunnel, AliasSelection) {
	t.Helper()
	tunnel, err := state.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: scope.Server, Project: project, Service: "api", Target: "3000",
		IntegrationGroup: scope.ProjectKey + "\x00" + scope.Namespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetPublicURL(t.Context(), id, label+"."+scope.Namespace); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if ready {
		if err := tunnel.SetReady(t.Context(), "https://"+label+"."+scope.Namespace, 1); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := state.RegisterAlias(t.Context(), AliasRegistration{Scope: scope, Hostname: "review." + scope.Namespace,
		Service: "api", TunnelID: tunnel.ID(), IntegrationGroup: scope.ProjectKey + "\x00" + scope.Namespace, Fingerprint: sha256.Sum256([]byte("review"))})
	if err != nil {
		t.Fatal(err)
	}
	return tunnel, selection
}

func aliasTestDatabase(t *testing.T) (*Database, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state, root
}

func TestAliasesDefaultToPrimaryAndReleaseRestoresIt(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	linkedProject := filepath.Join(filepath.Dir(scope.ProjectKey), "feature")
	_, initial := aliasTestTunnel(t, state, scope, linkedProject, "feature", true)
	if initial.Project != scope.ProjectKey || initial.Revision != 1 {
		t.Fatal("a linked worktree took default ownership")
	}
	if _, _, err := state.AliasCandidate(t.Context(), initial.ID); !errors.Is(err, ErrAliasReceiverUnavailable) {
		t.Fatal("stopped primary checkout fell back to a linked worktree")
	}
	main, _ := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	if _, err := state.SelectAlias(t.Context(), scope, linkedProject, false); !errors.Is(err, ErrAliasOwned) {
		t.Fatal("ordinary selection replaced the live primary checkout")
	}
	selected, err := state.SelectAlias(t.Context(), scope, linkedProject, true)
	if err != nil || selected.Project != linkedProject || selected.Revision != initial.Revision+1 {
		t.Fatalf("forced selection = %#v, %v", selected, err)
	}
	if _, err := state.ReleaseAlias(t.Context(), scope, scope.ProjectKey); !errors.Is(err, ErrAliasNotSelected) {
		t.Fatal("an unselected worktree released another's selection")
	}
	if err := main.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	released, err := state.ReleaseAlias(t.Context(), scope, linkedProject)
	if err != nil || released.Project != scope.ProjectKey || released.Revision != selected.Revision+1 {
		t.Fatalf("release did not restore the primary checkout: %#v, %v", released, err)
	}
	if _, _, err := state.AliasCandidate(t.Context(), initial.ID); !errors.Is(err, ErrAliasReceiverUnavailable) {
		t.Fatal("release assigned an available linked worktree instead of the primary")
	}
}

func TestAliasSelectionPersistsAcrossServiceRestart(t *testing.T) {
	state, root := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	project := filepath.Join(filepath.Dir(scope.ProjectKey), "feature")
	tunnel, initial := aliasTestTunnel(t, state, scope, project, "feature", true)
	selected, err := state.SelectAlias(t.Context(), scope, project, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	other, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	restarted, registration := aliasTestTunnel(t, other, scope, project, "restarted", false)
	if registration.Project != project || registration.Revision != selected.Revision {
		t.Fatal("restarting reset the persistent selection")
	}
	if _, _, err := other.AliasCandidate(t.Context(), initial.ID); !errors.Is(err, ErrAliasReceiverUnavailable) {
		t.Fatal("provisioning receiver was eligible")
	}
	if err := restarted.SetReady(t.Context(), "https://restarted."+scope.Namespace, 1); err != nil {
		t.Fatal(err)
	}
	current, receiver, err := other.AliasCandidate(t.Context(), initial.ID)
	if err != nil || current.Project != project || receiver.ID != restarted.ID() {
		t.Fatalf("restarted selected receiver = %q, %v", receiver.ID, err)
	}
}

func TestAliasRejectsConflictingLiveDeclarations(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	_, initial := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	linked, _ := aliasTestTunnel(t, state, scope, filepath.Join(filepath.Dir(scope.ProjectKey), "feature"), "feature", true)
	_, err := state.RegisterAlias(t.Context(), AliasRegistration{Scope: scope, Hostname: "review." + scope.Namespace,
		Service: "api", TunnelID: linked.ID(), IntegrationGroup: scope.ProjectKey + "\x00" + scope.Namespace, Fingerprint: sha256.Sum256([]byte("different"))})
	if !errors.Is(err, ErrAliasPolicyConflict) {
		t.Fatalf("conflicting declaration = %v", err)
	}
	unchanged, err := state.AliasSelection(t.Context(), scope)
	if err != nil || unchanged.Revision != initial.Revision || unchanged.Fingerprint != initial.Fingerprint {
		t.Fatal("rejected declaration mutated selection")
	}
}

func TestAliasConcurrentSelectionHasOneOwner(t *testing.T) {
	state, root := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	projects := []string{filepath.Join(filepath.Dir(scope.ProjectKey), "first"), filepath.Join(filepath.Dir(scope.ProjectKey), "second")}
	for index, project := range projects {
		aliasTestTunnel(t, state, scope, project, []string{"first", "second"}[index], true)
	}
	other, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for index, store := range []*Database{state, other} {
		workers.Go(func() { _, err := store.SelectAlias(t.Context(), scope, projects[index], false); results <- err })
	}
	workers.Wait()
	first, second := <-results, <-results
	if !((first == nil && errors.Is(second, ErrAliasOwned)) || (second == nil && errors.Is(first, ErrAliasOwned))) {
		t.Fatalf("competing selections = %v, %v", first, second)
	}
}

func TestAliasTakeoverRequiresReadyCallerAndPreservesProvisioningOwner(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	main, initial := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	project := filepath.Join(filepath.Dir(scope.ProjectKey), "feature")
	linked, _ := aliasTestTunnel(t, state, scope, project, "feature", false)
	if _, err := state.SelectAlias(t.Context(), scope, project, true); !errors.Is(err, ErrAliasReceiverUnavailable) {
		t.Fatal("force selected a provisioning caller")
	}
	if err := main.SetProvisioning(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if err := linked.SetReady(t.Context(), "https://feature."+scope.Namespace, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := state.SelectAlias(t.Context(), scope, project, false); !errors.Is(err, ErrAliasOwned) {
		t.Fatal("provisioning owner lost its live selection")
	}
	unchanged, err := state.AliasSelection(t.Context(), scope)
	if err != nil || unchanged.Project != scope.ProjectKey || unchanged.Revision != initial.Revision {
		t.Fatal("failed takeover changed selection")
	}
}
