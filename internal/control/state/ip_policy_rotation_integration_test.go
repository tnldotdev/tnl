package state

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationStorageRotationServiceHTTPIPPolicy(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "rotation_service_ip_policy")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	configuration := ProjectServiceConfiguration{
		Target: "http://app.internal:3000",
		HTTP:   &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.0/24"}}},
	}
	r.Configuration.Services["web"] = configuration
	r = selectedProjectRequest(r, "local")
	local, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", WorktreeLabel: "feature",
		ActorID: r.ActorID, Configuration: configuration, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: local.ServiceID}
	assertPolicy := func(db *Database) {
		t.Helper()
		cfg, _, err := db.GetServiceConfiguration(ctx, local.ServiceID, r.ActorID)
		if err != nil || cfg == nil || cfg.HTTP == nil || cfg.HTTP.Access == nil || len(cfg.HTTP.Access.IP) != 1 || cfg.HTTP.Access.IP[0] != "192.0.2.0/24" {
			t.Fatalf("service configuration IP policy after rotation: %+v %v", cfg, err)
		}
		if err := db.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
			t.Fatal(err)
		}
		policy, err := visitorlease.New(scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		result, err := db.readVisitorPolicy(ctx, tx, scope, 0, now)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(result)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := policy.BindAnonymous(netip.MustParseAddr("192.0.2.7"), func() {}); err != nil {
			t.Fatal("allowed source rejected after rotation", err)
		}
		if _, err := policy.BindAnonymous(netip.MustParseAddr("192.0.3.7"), func() {}); err == nil {
			t.Fatal("denied source allowed after rotation")
		}
	}
	assertPolicy(d)
	var beforeKey, afterKey string
	var beforeCipher, afterCipher []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT storage_key_id, configuration_ciphertext FROM control.services WHERE id=$1`, local.ServiceID).Scan(&beforeKey, &beforeCipher); err != nil {
		t.Fatal(err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), databaseURL, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	if err := reopened.pool.QueryRow(t.Context(), `SELECT storage_key_id, configuration_ciphertext FROM control.services WHERE id=$1`, local.ServiceID).Scan(&afterKey, &afterCipher); err != nil {
		t.Fatal(err)
	}
	if beforeKey == afterKey || bytes.Equal(beforeCipher, afterCipher) {
		t.Fatal("storage rotation did not re-encrypt service configuration", beforeKey, afterKey)
	}
	assertPolicy(reopened)
}

func TestIntegrationStorageRotationDeviceLogin(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "rotation_device_login")
	login, credential, err := d.CreateDeviceLogin(t.Context(), DeviceLoginOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := rotating.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `SELECT credential_digest FROM control.device_logins FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	for {
		n, err := rotating.ReencryptStorageSecrets(t.Context(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	if remaining, err := rotating.countPreviousStorageSecrets(t.Context()); err != nil || remaining != 1 {
		t.Fatalf("locked encrypted row omitted from rotation completion count: remaining=%d err=%v", remaining, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), databaseURL, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	polled, err := reopened.PollDeviceLogin(t.Context(), credential, now)
	if err != nil || polled.UserCode != login.UserCode || polled.Status != DevicePending {
		t.Fatalf("device login after retiring key A = %+v, %v", polled, err)
	}
}

func TestIntegrationStorageRotationBrowserSecrets(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "rotation_browser_secrets")
	_, _, _, leases := publishRunPrerequisitesInDatabase(t, d, now, nil)
	f := serviceHTTPFixture{database: d, now: now, project: appliedProjectRequest(t, d, now), leases: leases}
	f.service = f.local(t, "web", nil)
	f.run = f.publish(t, f.service)
	binding := bytes.Repeat([]byte{7}, 32)
	verifier := strings.Repeat("v", 43)
	state, err := d.BeginServiceBrowserLogin(t.Context(), f.auth().Subject, "", "/settings", "nonce-at-least-sixteen", verifier, binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	handoff, issued := f.browser(t, "", f.project.ActorID)
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey, naming.ManagedURLModeGenerated)
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
	reopened, err := Open(t.Context(), databaseURL, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	login, err := reopened.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil || login.Verifier != verifier {
		t.Fatal("browser verifier failed after key retirement", err)
	}
	cookie, err := reopened.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, now)
	if err != nil {
		t.Fatal("browser handoff failed after key retirement", err)
	}
	session, err := reopened.ServiceBrowserSession(t.Context(), f.auth(), cookie.CookieSecret, false, now)
	if err != nil || session.IdentityID != f.project.ActorID || !session.Authenticated {
		t.Fatal("browser authentication failed after key retirement", err)
	}
	digest, _ := browserDigest(cookie.CookieSecret)
	var ciphertext []byte
	var keyID string
	if err := reopened.pool.QueryRow(t.Context(), `SELECT refresh_ciphertext,storage_key_id FROM control.service_http_browser_sessions WHERE token_digest=$1`, digest).Scan(&ciphertext, &keyID); err != nil {
		t.Fatal(err)
	}
	refresh, _, err := reopened.storageKey.Open(keyID, browserContext(digest), ciphertext)
	if err != nil || string(refresh) != issued.RefreshToken.String() {
		t.Fatal("browser refresh secret failed after key retirement", err)
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

func TestIntegrationSignedInServiceHTTPIPPolicySurvivesStorageKeyRotation(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "service_policy_rotation")
	ctx := t.Context()
	session := newOIDCSession(t, database, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	actorCtx := WithControlPrincipal(ctx, principal)
	r := appliedProjectRequest(t, database, now)
	configuration := ProjectServiceConfiguration{
		Target: "http://app.internal:3000",
		HTTP:   &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}},
	}
	r.Configuration.Services["web"] = configuration
	r = selectedProjectRequest(r, "local")
	local, err := database.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", WorktreeLabel: "feature",
		ActorID: r.ActorID, Configuration: configuration, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: local.ServiceID}
	if err := database.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	issued, err := database.IssueVisitorToken(actorCtx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), databaseURL, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	cfg, _, err := reopened.GetServiceConfiguration(ctx, local.ServiceID, r.ActorID)
	if err != nil || cfg == nil || cfg.HTTP == nil || cfg.HTTP.Access == nil || len(cfg.HTTP.Access.IP) != 1 || cfg.HTTP.Access.IP[0] != "192.0.2.0/24" {
		t.Fatalf("rotated service policy = %+v, %v", cfg, err)
	}
	if err := reopened.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	keys := stateTestVisitorKeys(t, reopened, now)
	policy, err := visitorlease.New(scope, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	tx, err := reopened.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	result, err := reopened.readVisitorPolicy(ctx, tx, scope, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	update, err := visitorlease.Decode(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	view, _, _ := policy.Current()
	verified, err := visitortoken.VerifyBearer(issued.Token, view, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = keys
	if _, err := policy.Bind(verified, netip.MustParseAddr("192.0.2.7"), func() {}); err != nil {
		t.Fatal("rotated verifier rejected allowed signed-in source", err)
	}
	if _, err := policy.Bind(verified, netip.MustParseAddr("192.0.3.7"), func() {}); err == nil {
		t.Fatal("rotated verifier allowed denied signed-in source")
	}
}

func TestIntegrationPreviousKeyStaysRequiredUntilGuestTrialExpires(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "guest_key_retention")
	enableGuestTestIngress(t, database)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); err != nil {
		t.Fatal(err)
	}
	database.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	if reopened, err := Open(t.Context(), databaseURL, newKey, "", naming.ManagedURLModeGenerated); err == nil {
		reopened.Close()
		t.Fatal("an active guest trial lost its IP verifier key")
	} else if !strings.Contains(err.Error(), "previous storage key") {
		t.Fatalf("missing guest key failure = %v", err)
	}
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey, naming.ManagedURLModeGenerated)
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
	withoutPrevious, err := Open(t.Context(), databaseURL, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatalf("expired guest still required its old key: %v", err)
	}
	withoutPrevious.Close()
}
