package controlstate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/ippolicy"
)

func TestIntegrationSignedInIPPolicySurvivesStorageKeyRotation(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "private_policy_rotation")
	request := builtinRouteRequest(t, database, now)
	request.AllowedIPPrefixes = []string{"192.0.2.0/24"}
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	var oldPolicyCipher, oldHashes []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT allowed_ip_policy_ciphertext, allowed_ip_hashes
		FROM control.public_urls WHERE id=$1`, route.ID).Scan(&oldPolicyCipher, &oldHashes); err != nil {
		t.Fatal(err)
	}
	var entries []ippolicy.Entry
	if err := json.Unmarshal(oldHashes, &entries); err != nil {
		t.Fatal(err)
	}
	oldKeyID := database.storageKey.CurrentID()
	projection := IngressRoutingTableProjection{
		PublicURLID: route.ID, PublishRunID: "pr_rotation", PublishRunNumber: 1,
		CanonicalHostname: route.CanonicalHostname, PolicyRevision: 1, IPPolicy: IPPolicyHashedAllowlist,
		AllowedIPHashes: entries, IPPolicyKeyID: oldKeyID, PublicUrlExpiresAt: now.Add(time.Hour),
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.ingress_routing_table_events
		(event_kind, public_url_id, publish_run_number, canonical_hostname, entry_revision,
		projection, policy_ciphertext, policy_storage_key_id, public_url_expires_at, created_at)
		VALUES ('public_url_upsert', $1, 1, $2, 1, $3, $4, $5, $6, $7)`,
		route.ID, route.CanonicalHostname, payload, oldPolicyCipher, oldKeyID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	database.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), databaseURL, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	loaded, err := reopened.GetPublicURL(t.Context(), request.ActingIdentityID, route.ID)
	if err != nil || len(loaded.AllowedIPPrefixes) != 1 || loaded.AllowedIPPrefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf("rotated route policy = %+v, %v", loaded, err)
	}
	var rotatedCiphertext []byte
	var rotatedKeyID string
	if err := reopened.pool.QueryRow(t.Context(), `SELECT policy_ciphertext, policy_storage_key_id
		FROM control.ingress_routing_table_events WHERE public_url_id=$1`, route.ID).Scan(&rotatedCiphertext, &rotatedKeyID); err != nil {
		t.Fatal(err)
	}
	if rotatedKeyID != reopened.storageKey.CurrentID() || bytes.Equal(rotatedCiphertext, oldPolicyCipher) {
		t.Fatal("routing event kept old encrypted policy material")
	}
	event, err := reopened.ingressRoutingTableEvent(1, "public_url_upsert", route.ID, 1,
		route.CanonicalHostname, 1, payload, rotatedCiphertext, pgtype.Text{String: rotatedKeyID, Valid: true},
		pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true}, pgtype.Timestamptz{Time: now, Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ippolicy.New(event.Projection.IPPolicyKey, event.Projection.AllowedIPHashes)
	if err != nil || !policy.Allows(netip.MustParseAddr("192.0.2.7")) || policy.Allows(netip.MustParseAddr("192.0.3.7")) {
		t.Fatalf("rotated verifier changed the allowlist: %v", err)
	}
}

func TestIntegrationPreviousKeyStaysRequiredUntilGuestTrialExpires(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "guest_key_retention")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateGuestTrial(t.Context(), guest, "dom_guest", "da_guest", now); err != nil {
		t.Fatal(err)
	}
	database.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	if reopened, err := Open(t.Context(), databaseURL, newKey, ""); err == nil {
		reopened.Close()
		t.Fatal("an active guest trial lost its IP verifier key")
	} else if !strings.Contains(err.Error(), "previous storage key") {
		t.Fatalf("missing guest key failure = %v", err)
	}
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := rotating.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := rotating.GuestSourceMatches(stored, "192.0.2.7/32"); err != nil || !allowed {
		t.Fatalf("previous key rejected bound guest: %t, %v", allowed, err)
	}
	if _, err := rotating.ForgetGuestPrivateState(t.Context(), now.Add(GuestLifetime+time.Second)); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	withoutPrevious, err := Open(t.Context(), databaseURL, newKey, "")
	if err != nil {
		t.Fatalf("expired guest still required its old key: %v", err)
	}
	withoutPrevious.Close()
}
