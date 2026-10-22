package clientstate

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestOAuthCallbackNamedBoundariesAndExactStateDigest(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	tunnel, initial := aliasTestTunnel(t, state, scope, scope.ProjectKey, "main", true)
	selection, receiver, err := state.AliasCandidate(t.Context(), initial.ID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), scope.Server, selection.Hostname, "alias"); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkAliasRunReady(t.Context(), AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "alias", PublicURLID: id, Number: 7}); err != nil {
		t.Fatal(err)
	}
	input := SaveOAuthCallbackInput{
		Scope:       OAuthCallbackScope{Server: scope.Server, Hostname: "oauth." + scope.Namespace, IntegrationGroup: scope.ProjectKey + "\x00" + scope.Namespace},
		Origin:      OAuthRedirectOrigin{Hostname: selection.Hostname, PublicURLID: id, PublishRunNumber: 7},
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
	if err := state.db.QueryRowContext(t.Context(), `SELECT state_digest, public_url_id, publish_run_number, origin_public_url_id, origin_publish_run_number FROM oauth_pending_callbacks`).Scan(&digest, &destinationID, &destinationNumber, &originID, &originNumber); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, wantDigest) || destinationID != receiver.PublicURLID || destinationNumber != int64(receiver.PublishRunNumber) || originID != id || originNumber != 7 || originID == destinationID {
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
	if err := state.db.QueryRowContext(t.Context(), `SELECT state_digest FROM oauth_alias_handoffs`).Scan(&digest); err != nil || !bytes.Equal(digest, wantDigest) {
		t.Fatal("alias handoff changed the exact state digest", err)
	}
	if err := state.AdmitAliasOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, origin.PublicURLID, origin.PublishRunNumber+1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("replacement alias run received a known callback", err)
	}
	if err := state.AdmitAliasOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, origin.PublicURLID, origin.PublishRunNumber); err != nil {
		t.Fatal(err)
	}
	if err := state.AdmitAliasOAuthReturn(t.Context(), scope.Server, origin.Hostname, expected.State, callback.Path, origin.PublicURLID, origin.PublishRunNumber); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("alias final-hop state was replayed", err)
	}
}
