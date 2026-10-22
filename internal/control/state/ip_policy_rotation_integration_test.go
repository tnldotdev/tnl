package state

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

func TestIntegrationStorageRotationVisitorIPGrant(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "rotation_visitor_grant")
	request := oidcRouteRequest(t, d, now)
	u, err := d.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := d.MutateVisitorIPs(t.Context(), u.ID, request.ActingIdentityID, "set", "", []VisitorIPGrantInput{{Prefix: "192.0.2.0/24"}}, now)
	if err != nil || len(grants) != 1 {
		t.Fatal(grants, err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	checkLockedRotationCount(t, rotating, `SELECT id FROM control.visitor_ip_grants FOR UPDATE`)
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), databaseURL, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	listed, err := reopened.MutateVisitorIPs(t.Context(), u.ID, request.ActingIdentityID, "list", "", nil, now)
	if err != nil || len(listed) != 1 || listed[0] != grants[0] {
		t.Fatalf("underlying visitor grant after retiring key A = %+v, %v", listed, err)
	}
	q := controlstatedb.New(reopened.pool)
	url, err := q.LockPublicURLForRun(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	for source, want := range map[string]bool{"192.0.2.7": true, "192.0.3.7": false} {
		allowed, _, err := reopened.visitorIPAllowed(t.Context(), q, url, source, now)
		if err != nil || allowed != want {
			t.Fatalf("grant authorization for %s = %t, %v", source, allowed, err)
		}
	}
}

func TestIntegrationStorageRotationDeviceLogin(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "rotation_device_login")
	login, credential, err := d.CreateDeviceLogin(t.Context(), DeviceLoginOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	checkLockedRotationCount(t, rotating, `SELECT credential_digest FROM control.device_logins FOR UPDATE`)
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), databaseURL, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	polled, err := reopened.PollDeviceLogin(t.Context(), credential, now)
	if err != nil || polled.UserCode != login.UserCode || polled.Status != DevicePending {
		t.Fatalf("device login after retiring key A = %+v, %v", polled, err)
	}
}

func checkLockedRotationCount(t *testing.T, d *Database, lock string) {
	t.Helper()
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), lock); err != nil {
		t.Fatal(err)
	}
	for {
		n, err := d.ReencryptStorageSecrets(t.Context(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	if remaining, err := d.countPreviousStorageSecrets(t.Context()); err != nil || remaining != 1 {
		t.Fatalf("locked encrypted row omitted from rotation completion count: remaining=%d err=%v", remaining, err)
	}
}

func TestIntegrationStorageRotationBrowserSecrets(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "rotation_browser_secrets")
	r := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, r, now)
	auth := browserTestAuthentication(t, d, u.ID, now)
	binding := bytes.Repeat([]byte{7}, 32)
	verifier := strings.Repeat("v", 43)
	state, err := d.BeginBrowserLogin(t.Context(), "", u.ID, "/settings", "nonce-at-least-sixteen", verifier, binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	issued := browserTestControlSession(t, d, r.ActingIdentityID, now)
	handoff, err := d.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{PublicURLID: u.ID, PublishRunID: auth.PublishRunID, ReturnPath: "/settings"}, BrowserAccessSession{
		IdentityID: r.ActingIdentityID, DisplayName: "Example user", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(24 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	for {
		n, err := rotating.ReencryptStorageSecrets(t.Context(), 1)
		if err != nil || n > 1 {
			t.Fatal("unbounded or failed rotation", n, err)
		}
		if n == 0 {
			break
		}
	}
	if n, err := rotating.countPreviousStorageSecrets(t.Context()); err != nil || n != 0 {
		t.Fatal("browser secret rotation did not converge", n, err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), databaseURL, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	login, err := reopened.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil || login.Verifier != verifier {
		t.Fatal("browser verifier failed after key retirement", err)
	}
	cookie, _, _, _, _, err := reopened.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now)
	if err != nil {
		t.Fatal("browser handoff failed after key retirement", err)
	}
	session, err := reopened.BrowserSession(t.Context(), u.ID, cookie, now)
	if err != nil || session.AccessToken != issued.AccessToken.String() || session.RefreshToken != issued.RefreshToken.String() {
		t.Fatal("browser access/refresh pair failed after key retirement", err)
	}
}

func TestIntegrationSignedInIPPolicySurvivesStorageKeyRotation(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "private_policy_rotation")
	request := oidcRouteRequest(t, database, now)
	request.AllowedIPPrefixes = []string{"192.0.2.0/24"}
	publicURL, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	var oldPolicyCipher, oldHashes []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT allowed_ip_policy_ciphertext, allowed_ip_hashes
		FROM control.public_urls WHERE id=$1`, publicURL.ID).Scan(&oldPolicyCipher, &oldHashes); err != nil {
		t.Fatal(err)
	}
	var entries []ippolicy.Entry
	if err := json.Unmarshal(oldHashes, &entries); err != nil {
		t.Fatal(err)
	}
	oldKeyID := database.storageKey.CurrentID()
	projection := IngressRoutingTableProjection{
		PublicURLID: publicURL.ID, PublishRunID: "pr_rotation", PublishRunNumber: 1,
		CanonicalHostname: publicURL.CanonicalHostname, PolicyRevision: 1, IPPolicy: IPPolicyHashedAllowlist,
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
		publicURL.ID, publicURL.CanonicalHostname, payload, oldPolicyCipher, oldKeyID, now.Add(time.Hour), now); err != nil {
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
	loaded, err := reopened.GetPublicURL(t.Context(), request.ActingIdentityID, publicURL.ID)
	if err != nil || len(loaded.AllowedIPPrefixes) != 1 || loaded.AllowedIPPrefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf("rotated route policy = %+v, %v", loaded, err)
	}
	var rotatedCiphertext []byte
	var rotatedKeyID string
	if err := reopened.pool.QueryRow(t.Context(), `SELECT policy_ciphertext, policy_storage_key_id
		FROM control.ingress_routing_table_events WHERE public_url_id=$1`, publicURL.ID).Scan(&rotatedCiphertext, &rotatedKeyID); err != nil {
		t.Fatal(err)
	}
	if rotatedKeyID != reopened.storageKey.CurrentID() || bytes.Equal(rotatedCiphertext, oldPolicyCipher) {
		t.Fatal("routing event kept old encrypted policy material")
	}
	event, err := reopened.ingressRoutingTableEvent(1, "public_url_upsert", publicURL.ID, 1,
		publicURL.CanonicalHostname, 1, payload, rotatedCiphertext, pgtype.Text{String: rotatedKeyID, Valid: true},
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
	if _, err := database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); err != nil {
		t.Fatal(err)
	}
	const oldPublicURLID = "url_guest_replay"
	oldKeyID := database.storageKey.CurrentID()
	oldVerifier, err := database.storageKey.IPPolicyKey(oldKeyID, "url:"+oldPublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	oldHash, err := ippolicy.Hash(oldVerifier, netip.MustParsePrefix("192.0.2.7/32"))
	if err != nil {
		t.Fatal(err)
	}
	oldProjection, err := json.Marshal(IngressRoutingTableProjection{
		PublicURLID: oldPublicURLID, PublishRunID: "pr_guest_replay", PublishRunNumber: 1,
		CanonicalHostname: "demo-1.guest-replay.example.test", PolicyRevision: 1,
		IPPolicy: IPPolicyHashedAllowlist, AllowedIPHashes: []ippolicy.Entry{oldHash},
		IPPolicyKeyID: oldKeyID, PublicUrlExpiresAt: now.Add(GuestLifetime + time.Hour),
	})
	if err != nil {
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
	event, err := withoutPrevious.ingressRoutingTableEvent(1, "public_url_upsert", oldPublicURLID, 1,
		"demo-1.guest-replay.example.test", 1, oldProjection, nil, pgtype.Text{},
		pgtype.Timestamptz{Time: now.Add(GuestLifetime + time.Hour), Valid: true},
		pgtype.Timestamptz{Time: now, Valid: true})
	if err != nil {
		t.Fatalf("old guest event blocked routing replay: %v", err)
	}
	policy, err := ippolicy.New(event.Projection.IPPolicyKey, event.Projection.AllowedIPHashes)
	if err != nil || policy.Allows(netip.MustParseAddr("192.0.2.7")) {
		t.Fatalf("old guest event allowed traffic after key retirement: %v", err)
	}
	withoutPrevious.Close()
}
