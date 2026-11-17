package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestOAuthCallbackNamedBoundariesAndExactStateDigest(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	tunnel, initial := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	selection, receiver, err := state.AliasCandidate(t.Context(), initial.ID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), scope.Server, selection.Hostname, "alias", id, 7); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkAliasRunReady(t.Context(), AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "alias", ServiceID: id, Number: 7}); err != nil {
		t.Fatal(err)
	}
	input := SaveOAuthCallbackInput{
		Scope:       OAuthCallbackScope{Server: scope.Server, Hostname: "oauth." + scope.Namespace, IntegrationScope: IntegrationScope{PrimaryProjectRoot: scope.ProjectKey, Namespace: scope.Namespace}},
		Origin:      OAuthRedirectOrigin{Hostname: selection.Hostname, ServiceID: id, RunNumber: 7},
		Destination: OAuthCallbackDestination{TunnelID: tunnel.ID(), Path: "/callback", Query: "flow=github"}, State: "abc",
	}
	expected := input
	if err := state.SaveOAuthCallback(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveOAuthCallback(t.Context(), input); err == nil {
		t.Fatal("duplicate state replaced its initiating origin")
	}
	wantDigest, _ := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	var digest []byte
	var destinationID, originID string
	var destinationNumber, originNumber int64
	if err := state.db.QueryRowContext(t.Context(), `SELECT state_digest, service_id, run_number, origin_service_id, origin_run_number FROM oauth_pending_callbacks`).Scan(&digest, &destinationID, &destinationNumber, &originID, &originNumber); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, wantDigest) || destinationID != receiver.ServiceID || destinationNumber != int64(receiver.PublishRunNumber) || originID != id || originNumber != 7 || originID == destinationID {
		t.Fatal("state hashing or independent origin/destination binding changed")
	}
	input.Origin.Hostname, input.Destination.Path, input.State = "changed.example", "/changed", "changed"
	callback, origin, err := state.ConsumeOAuthCallback(t.Context(), expected.Scope.Server, expected.Scope.Hostname, expected.State, expected.Destination.Path)
	if err != nil || callback.TunnelID != expected.Destination.TunnelID || callback.Path != expected.Destination.Path || origin != expected.Origin {
		t.Fatal("callback did not return its exact redirect origin and local destination", err)
	}
	if _, _, err := state.ConsumeOAuthCallback(t.Context(), expected.Scope.Server, expected.Scope.Hostname, expected.State, expected.Destination.Path); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("consumed callback was replayed", err)
	}
	if err := state.db.QueryRowContext(t.Context(), `SELECT state_digest FROM oauth_callback_handoffs`).Scan(&digest); err != nil || !bytes.Equal(digest, wantDigest) {
		t.Fatal("alias handoff changed the exact state digest", err)
	}
	otherID, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AdmitOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, otherID, origin.RunNumber); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("another service at the alias address received a known callback", err)
	}
	if err := tunnel.SetIntegrationScope(t.Context(), IntegrationScope{PrimaryProjectRoot: scope.ProjectKey, Namespace: "other." + scope.Namespace}); err != nil {
		t.Fatal(err)
	}
	if err := state.AdmitOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, origin.ServiceID, origin.RunNumber); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("alias callback reached a reassigned receiver", err)
	}
	if err := tunnel.SetIntegrationScope(t.Context(), receiver.IntegrationScope); err != nil {
		t.Fatal(err)
	}
	if err := state.AdmitOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, origin.ServiceID, origin.RunNumber+1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("replacement alias run received a known callback", err)
	}
	if err := state.AdmitOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, origin.ServiceID, origin.RunNumber); err != nil {
		t.Fatal(err)
	}
	if err := state.AdmitOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, origin.ServiceID, origin.RunNumber); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("alias final-hop state was replayed", err)
	}
}

func TestOAuthOrdinaryFinalHopKeepsExactDestinationAndOneUse(t *testing.T) {
	for _, replacement := range []string{"none", "service", "run", "project", "namespace", "hostname", "stopped", "removed", "expired"} {
		t.Run(replacement, func(t *testing.T) {
			state, _ := aliasTestDatabase(t)
			scope := aliasTestScope(t)
			tunnel, selection := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
			_, receiver, err := state.AliasCandidate(t.Context(), selection.ID)
			if err != nil {
				t.Fatal(err)
			}
			input := SaveOAuthCallbackInput{
				Scope:       OAuthCallbackScope{Server: scope.Server, Hostname: "oauth." + scope.Namespace, IntegrationScope: receiver.IntegrationScope},
				Origin:      OAuthRedirectOrigin{Hostname: receiver.Hostname, ServiceID: receiver.ServiceID, RunNumber: receiver.PublishRunNumber},
				Destination: OAuthCallbackDestination{TunnelID: tunnel.ID(), Path: "/callback"}, State: "between-hops",
			}
			if err := state.SaveOAuthCallback(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			callback, origin, err := state.ConsumeOAuthCallback(t.Context(), input.Scope.Server, input.Scope.Hostname, input.State, input.Destination.Path)
			if err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "service":
				id, err := opaqueid.New(opaqueid.ServicePrefix)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := state.db.ExecContext(t.Context(), `UPDATE local_tunnels SET service_id=? WHERE id=?`, id, tunnel.ID()); err != nil {
					t.Fatal(err)
				}
				origin.ServiceID = id
			case "run":
				if err := tunnel.SetReady(t.Context(), receiver.PublicURL, receiver.PublishRunNumber+1); err != nil {
					t.Fatal(err)
				}
				origin.RunNumber++
			case "project", "namespace":
				next := receiver.IntegrationScope
				if replacement == "project" {
					next.PrimaryProjectRoot += "-other"
				} else {
					next.Namespace = "other." + next.Namespace
				}
				if err := tunnel.SetIntegrationScope(t.Context(), next); err != nil {
					t.Fatal(err)
				}
			case "hostname":
				if err := tunnel.SetReady(t.Context(), "https://other."+scope.Namespace, receiver.PublishRunNumber); err != nil {
					t.Fatal(err)
				}
			case "stopped":
				if err := tunnel.Finish(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			case "removed":
				if _, err := state.db.ExecContext(t.Context(), `DELETE FROM local_tunnels WHERE id=?`, tunnel.ID()); err != nil {
					t.Fatal(err)
				}
			case "expired":
				now := state.now()
				state.now = func() time.Time { return now.Add(11 * time.Minute) }
			}
			admit := func(value, path string) error {
				return state.AdmitOAuthReturn(t.Context(), scope.Server, origin.Hostname, value, path, origin.ServiceID, origin.RunNumber)
			}
			if err := admit("unknown-app-state", callback.Path); err != nil {
				t.Fatal("unknown state did not remain an app request", err)
			}
			if err := admit(input.State, "/unrelated"); err != nil {
				t.Fatal("unrelated path consumed callback state", err)
			}
			err = admit(input.State, callback.Path)
			if replacement != "none" {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("final hop reached a replaced or expired destination", err)
				}
				return
			}
			if err != nil {
				t.Fatal("current initiating run did not receive its callback", err)
			}
			if err := admit(input.State, callback.Path); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("final-hop state was replayed", err)
			}
		})
	}
}

func TestOAuthCallbackRejectsReplacedServiceRunAndScope(t *testing.T) {
	for _, replacement := range []string{"service", "run", "project", "namespace"} {
		t.Run(replacement, func(t *testing.T) {
			state, _ := aliasTestDatabase(t)
			scope := aliasTestScope(t)
			tunnel, selection := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
			_, receiver, err := state.AliasCandidate(t.Context(), selection.ID)
			if err != nil {
				t.Fatal(err)
			}
			input := SaveOAuthCallbackInput{
				Scope:       OAuthCallbackScope{Server: scope.Server, Hostname: "oauth." + scope.Namespace, IntegrationScope: receiver.IntegrationScope},
				Origin:      OAuthRedirectOrigin{Hostname: receiver.Hostname, ServiceID: receiver.ServiceID, RunNumber: receiver.PublishRunNumber},
				Destination: OAuthCallbackDestination{TunnelID: tunnel.ID(), Path: "/callback"}, State: "before-replacement",
			}
			if err := state.SaveOAuthCallback(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "service":
				id, err := opaqueid.New(opaqueid.ServicePrefix)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := state.db.ExecContext(t.Context(), `UPDATE local_tunnels SET service_id=? WHERE id=?`, id, tunnel.ID()); err != nil {
					t.Fatal(err)
				}
			case "run":
				if err := tunnel.SetReady(t.Context(), receiver.PublicURL, receiver.PublishRunNumber+1); err != nil {
					t.Fatal(err)
				}
			default:
				next := receiver.IntegrationScope
				if replacement == "project" {
					next.PrimaryProjectRoot += "-other"
				} else {
					next.Namespace = "other." + next.Namespace
				}
				if err := tunnel.SetIntegrationScope(t.Context(), next); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := state.ConsumeOAuthCallback(t.Context(), input.Scope.Server, input.Scope.Hostname, input.State, input.Destination.Path); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("callback reached a replaced service run or scope: %v", err)
			}
		})
	}
}

func TestOAuthCallbackConcurrentConsumptionHasOneWinner(t *testing.T) {
	state, root := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	tunnel, selection := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	_, receiver, err := state.AliasCandidate(t.Context(), selection.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := SaveOAuthCallbackInput{
		Scope:       OAuthCallbackScope{Server: scope.Server, Hostname: "oauth." + scope.Namespace, IntegrationScope: receiver.IntegrationScope},
		Origin:      OAuthRedirectOrigin{Hostname: receiver.Hostname, ServiceID: receiver.ServiceID, RunNumber: receiver.PublishRunNumber},
		Destination: OAuthCallbackDestination{TunnelID: tunnel.ID(), Path: "/callback"}, State: "one-winner",
	}
	if err := state.SaveOAuthCallback(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	other, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, database := range []*Database{state, other} {
		workers.Go(func() {
			<-start
			_, _, err := database.ConsumeOAuthCallback(t.Context(), input.Scope.Server, input.Scope.Hostname, input.State, input.Destination.Path)
			results <- err
		})
	}
	close(start)
	workers.Wait()
	first, second := <-results, <-results
	if !(first == nil && errors.Is(second, sql.ErrNoRows) || second == nil && errors.Is(first, sql.ErrNoRows)) {
		t.Fatalf("concurrent callback results: %v, %v", first, second)
	}
	start = make(chan struct{})
	prepared := make(chan struct{}, 2)
	for _, database := range []*Database{state, other} {
		workers.Go(func() {
			consume, err := database.PrepareOAuthReturn(t.Context(), scope.Server, input.Origin.Hostname, input.State,
				input.Destination.Path, input.Origin.ServiceID, input.Origin.RunNumber)
			prepared <- struct{}{}
			<-start
			if err != nil {
				results <- err
				return
			}
			if consume == nil {
				results <- errors.New("known return produced no claim")
				return
			}
			results <- consume(t.Context())
		})
	}
	<-prepared
	<-prepared
	close(start)
	workers.Wait()
	first, second = <-results, <-results
	if !(first == nil && errors.Is(second, sql.ErrNoRows) || second == nil && errors.Is(first, sql.ErrNoRows)) {
		t.Fatalf("concurrent final-hop results: %v, %v", first, second)
	}
}

func TestOAuthReturnClaimRechecksDestinationAndHandoffIdentity(t *testing.T) {
	for _, replacement := range []string{"none", "run", "scope", "stopped", "removed", "expired", "purged", "recreated"} {
		t.Run(replacement, func(t *testing.T) {
			state, _ := aliasTestDatabase(t)
			scope := aliasTestScope(t)
			tunnel, selection := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
			_, receiver, err := state.AliasCandidate(t.Context(), selection.ID)
			if err != nil {
				t.Fatal(err)
			}
			input := SaveOAuthCallbackInput{
				Scope:       OAuthCallbackScope{Server: scope.Server, Hostname: "oauth." + scope.Namespace, IntegrationScope: receiver.IntegrationScope},
				Origin:      OAuthRedirectOrigin{Hostname: receiver.Hostname, ServiceID: receiver.ServiceID, RunNumber: receiver.PublishRunNumber},
				Destination: OAuthCallbackDestination{TunnelID: tunnel.ID(), Path: "/callback"}, State: "prepared-return",
			}
			if err := state.SaveOAuthCallback(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			if _, _, err := state.ConsumeOAuthCallback(t.Context(), input.Scope.Server, input.Scope.Hostname, input.State, input.Destination.Path); err != nil {
				t.Fatal(err)
			}
			prepare := func(value, path string) (func(context.Context) error, error) {
				return state.PrepareOAuthReturn(t.Context(), scope.Server, receiver.Hostname, value, path, receiver.ServiceID, receiver.PublishRunNumber)
			}
			for _, request := range []struct{ state, path string }{{"unknown", "/callback"}, {input.State, "/unrelated"}} {
				if consume, err := prepare(request.state, request.path); err != nil || consume != nil {
					t.Fatal("unrelated app request acquired a claim", err)
				}
			}
			first, err := prepare(input.State, input.Destination.Path)
			if err != nil || first == nil {
				t.Fatal("valid return did not prepare", err)
			}
			second, err := prepare(input.State, input.Destination.Path)
			if err != nil || second == nil {
				t.Fatal("read-only preparation spent the return", err)
			}
			switch replacement {
			case "run":
				err = tunnel.SetReady(t.Context(), receiver.PublicURL, receiver.PublishRunNumber+1)
			case "scope":
				next := receiver.IntegrationScope
				next.Namespace = "other." + next.Namespace
				err = tunnel.SetIntegrationScope(t.Context(), next)
			case "stopped":
				err = tunnel.Finish(t.Context(), nil)
			case "removed":
				_, err = state.db.ExecContext(t.Context(), `DELETE FROM local_tunnels WHERE id=?`, tunnel.ID())
			case "expired":
				now := state.now()
				state.now = func() time.Time { return now.Add(11 * time.Minute) }
			case "purged":
				_, err = state.db.ExecContext(t.Context(), `DELETE FROM oauth_callback_handoffs`)
			case "recreated":
				_, err = state.db.ExecContext(t.Context(), `UPDATE oauth_callback_handoffs SET created_at=created_at+1, expires_at=expires_at+1`)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = first(t.Context())
			if replacement != "none" {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("prepared return reached a changed destination or handoff", err)
				}
				return
			}
			if err != nil {
				t.Fatal("current return could not commit", err)
			}
			for _, consume := range []func(context.Context) error{first, second} {
				if err := consume(t.Context()); !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("a prepared return committed twice", err)
				}
			}
		})
	}
}
