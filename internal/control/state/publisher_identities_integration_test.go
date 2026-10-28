package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

const publisherTestAudience = "https://control.example/v1/publisher-token"

func TestIntegrationPublisherResolvedScopeUsesAuthorizedFacts(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_resolved_scope")
	r := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, r, now)
	service, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActingIdentityID, "publisher-private", "publisher-private", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	m, err := controlstatedb.New(d.pool).GetActivePublishRunMembership(t.Context(), controlstatedb.GetActivePublishRunMembershipParams{TeamID: r.TeamID, IdentityID: r.ActingIdentityID})
	if err != nil {
		t.Fatal(err)
	}
	for _, submitted := range []PublisherScope{
		{TeamID: r.TeamID, Kind: "saved_public_url", PublicURLID: u.ID, MembershipID: "forged", PublicURLScope: PublicURLScopeShared},
		{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID, MembershipID: "forged", PublicURLScope: PublicURLScopeShared},
		{TeamID: r.TeamID, Kind: "service", ServiceID: service.ID},
	} {
		e := publisherEnrollment(t, d, r, submitted, now)
		if e.Scope.Kind == "saved_public_url" && (e.Scope.MembershipID != "" || e.Scope.PublicURLScope != "") {
			t.Fatal("saved URL grant retained submitted namespace ownership", e.Scope)
		}
		if e.Scope.Kind == "namespace" && (e.Scope.MembershipID != m.ID || e.Scope.PublicURLScope != PublicURLScopeMember || e.Scope.Namespace == "") {
			t.Fatal("namespace grant trusted submitted ownership", e.Scope)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
		if err != nil || identity.Scope != e.Scope {
			t.Fatal("enrollment redemption changed resolved scope", identity.Scope, e.Scope, err)
		}
		stored, err := controlstatedb.New(d.pool).GetPublisherGrant(t.Context(), controlstatedb.GetPublisherGrantParams{ID: identity.GrantID, PublisherIdentityID: identity.ID})
		if err != nil || scopeFromGrant(r.TeamID, stored) != e.Scope {
			t.Fatal("grant persistence lost the authorized target", stored, err)
		}
	}
	for _, submitted := range []PublisherScope{
		{TeamID: r.TeamID, Kind: "saved_public_url", PublicURLID: u.ID, ServiceID: service.ID},
		{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID, PublicURLID: u.ID},
		{TeamID: r.TeamID, Kind: "service", ServiceID: service.ID, Namespace: "forged.example"},
	} {
		if _, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{Scope: submitted, Name: "test", Kind: "installed", EditorID: r.ActingIdentityID, EditorMembershipID: m.ID, PolicyRevision: uint64(m.PolicyRevision), Now: now}); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("mixed submitted scope was authorized", submitted, err)
		}
	}
}

func TestIntegrationPublisherFreshBaseline(t *testing.T) {
	d, _ := newControlStateIntegrationDatabase(t, "publisher_baseline")
	for _, name := range []string{"public_url_publish_credentials", "publish_run_publish_credentials", "ephemeral_public_url_allocations", "authority_revision_states", "tcp_port_claims", "ingress_pool_ports", "service_tickets"} {
		var absent bool
		if err := d.pool.QueryRow(t.Context(), `SELECT to_regclass('control.' || $1) IS NULL`, name).Scan(&absent); err != nil || !absent {
			t.Fatalf("legacy table %s exists: %v", name, err)
		}
	}
	for _, name := range []string{"publisher_identities", "publisher_identity_keys", "publisher_grants", "publisher_enrollments", "publisher_assertions", "publisher_access_tokens", "publisher_namespace_allocations", "publish_run_publisher_grants", "publisher_certificate_checkpoints", "previews", "shares", "feedback_threads", "browser_access_sessions", "publisher_service_runs", "publisher_service_connection_slots", "visitor_devices", "connector_visitor_streams"} {
		var present bool
		if err := d.pool.QueryRow(t.Context(), `SELECT to_regclass('control.' || $1) IS NOT NULL`, name).Scan(&present); err != nil || !present {
			t.Fatalf("final table %s missing: %v", name, err)
		}
	}
	files, err := migrationFiles.ReadDir("migrations")
	if err != nil || len(files) != 1 || files[0].Name() != "00001_baseline.sql" || schemaVersion != 1 {
		t.Fatalf("baseline = %v, %v", files, err)
	}
	var actualVersion int64
	var actualBaseline string
	if err := d.pool.QueryRow(t.Context(), `SELECT MAX(version_id) FILTER (WHERE is_applied) FROM control.goose_db_version`).Scan(&actualVersion); err != nil || actualVersion != 1 {
		t.Fatal("fresh database did not initialize schema 1", actualVersion, err)
	}
	if err := d.pool.QueryRow(t.Context(), `SELECT baseline_id FROM control.schema_identity WHERE id=1`).Scan(&actualBaseline); err != nil || actualBaseline != "tnl-control-fresh-v1-public-reservations" {
		t.Fatal("fresh baseline identity changed", actualBaseline, err)
	}
	// an older database's larger migration counter cannot pass this baseline's
	// readiness check just because its numeric version is greater than one.
	if _, err := d.pool.Exec(t.Context(), `ALTER TABLE control.publish_run_publisher_grants RENAME TO missing_publisher_baseline`); err != nil {
		t.Fatal(err)
	}
	if err := d.Readiness(t.Context()); err == nil {
		t.Fatal("pre-cutover schema passed readiness")
	}
}

func publisherEnrollment(t *testing.T, d *Database, r CreatePublicURLRequest, scope PublisherScope, now time.Time) PublisherEnrollment {
	t.Helper()
	m, err := controlstatedb.New(d.pool).GetActivePublishRunMembership(t.Context(), controlstatedb.GetActivePublishRunMembershipParams{TeamID: r.TeamID, IdentityID: r.ActingIdentityID})
	if err != nil {
		t.Fatal(err)
	}
	e, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{Scope: scope, Name: "test", Kind: "installed", EditorID: r.ActingIdentityID, EditorMembershipID: m.ID, PolicyRevision: uint64(m.PolicyRevision), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func publisherAccess(t *testing.T, d *Database, p PublisherIdentity, private ed25519.PrivateKey, source string, now time.Time) PublisherAccess {
	t.Helper()
	assertion, err := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherTestAudience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.ExchangePublisherAssertion(t.Context(), p.ID, p.GrantID, publisherTestAudience, assertion, source, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestIntegrationPublisherEnrollmentConcurrency(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_enrollment")
	request := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, request, now)
	e := publisherEnrollment(t, d, request, PublisherScope{TeamID: u.TeamID, Kind: "saved_public_url", PublicURLID: u.ID}, now)
	keys := make([]ed25519.PublicKey, 2)
	for i := range keys {
		keys[i], _, _ = ed25519.GenerateKey(rand.Reader)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type redemption struct {
		identity PublisherIdentity
		err      error
		key      int
	}
	results := make(chan redemption, 8)
	for i := range 8 {
		workers.Go(func() {
			p, err := d.RedeemPublisherEnrollment(ctx, e.Key, keys[i%2], now)
			results <- redemption{p, err, i % 2}
		})
	}
	winner, id, successful := -1, "", 0
	for range 8 {
		r := awaitIntegrationResult(t, ctx, results)
		if r.err == nil {
			successful++
			if winner < 0 {
				winner, id = r.key, r.identity.ID
			}
			if winner != r.key || id != r.identity.ID {
				t.Fatal("one-use enrollment accepted competing keys")
			}
		} else if !errors.Is(r.err, ErrPublisherEnrollment) {
			t.Fatal(r.err)
		}
	}
	if successful != 4 {
		t.Fatalf("same-key retry successes = %d, want 4", successful)
	}
	if _, err := d.RedeemPublisherEnrollment(ctx, e.Key, keys[winner], e.Until); !errors.Is(err, ErrPublisherEnrollment) {
		t.Fatalf("expired secret retry = %v", err)
	}
	var count int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_identities`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("registered identities = %d, %v", count, err)
	}
}

func TestIntegrationPublisherReplayRotationAndIndependentRevocation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_replay")
	request := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, request, now)
	e := publisherEnrollment(t, d, request, PublisherScope{TeamID: u.TeamID, Kind: "saved_public_url", PublicURLID: u.ID}, now)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	assertion, _ := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherTestAudience, private, now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type exchanged struct {
		access PublisherAccess
		err    error
	}
	results := make(chan exchanged, 8)
	for range 8 {
		workers.Go(func() {
			a, err := d.ExchangePublisherAssertion(ctx, p.ID, p.GrantID, publisherTestAudience, assertion, "", now)
			results <- exchanged{a, err}
		})
	}
	success := 0
	var access PublisherAccess
	for range 8 {
		r := awaitIntegrationResult(t, ctx, results)
		if r.err == nil {
			success++
			access = r.access
		} else if !errors.Is(r.err, ErrPublisherIdentity) {
			t.Fatal(r.err)
		}
	}
	if success != 1 {
		t.Fatalf("replayed assertion minted %d tokens", success)
	}
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	replacement, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	proof, _ := publisherproof.Sign(p.ID, replacement, p.GrantID, "https://control.example/v1/publisher-keys/rotate", newPrivate, now)
	if err := d.RotatePublisherKey(ctx, access.Token, "", replacement, "https://control.example/v1/publisher-keys/rotate", newPublic, proof, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("bearer-only key rotation = %v", err)
	}
	currentProof, _ := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherproof.RotationAudience("https://control.example/v1/publisher-keys/rotate", replacement, newPublic), private, now)
	if err := d.RotatePublisherKey(ctx, access.Token, "", replacement, "https://control.example/v1/publisher-keys/rotate", newPublic, proof, currentProof, now); err != nil {
		t.Fatal(err)
	}
	oldProof, _ := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherTestAudience, private, now)
	if _, err := d.ExchangePublisherAssertion(ctx, p.ID, p.GrantID, publisherTestAudience, oldProof, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("retired key exchange = %v", err)
	}
	if _, err := d.AuthenticatePublisherAccess(ctx, access.Token, "", now); err != nil {
		t.Fatalf("rotation invalidated bounded issued token: %v", err)
	}
	p.KeyID = replacement
	fresh := publisherAccess(t, d, p, newPrivate, "", now)
	secondRequest := request
	secondRequest.CanonicalHostname = "second." + u.CanonicalHostname
	secondRequest.IdempotencyKey = "second"
	second := createTestPublicURL(t, d, secondRequest, now)
	grant, err := d.CreatePublisherGrant(ctx, CreatePublisherGrantRequest{PublisherIdentityID: p.ID, Scope: PublisherScope{TeamID: u.TeamID, Kind: "saved_public_url", PublicURLID: second.ID}, EditorID: request.ActingIdentityID, EditorMembershipID: request.MembershipID, PolicyRevision: 1, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	p2 := p
	p2.GrantID, p2.Scope.PublicURLID = grant, second.ID
	otherAccess := publisherAccess(t, d, p2, newPrivate, "", now)
	if err := d.RevokePublisherGrant(ctx, u.TeamID, p.ID, p.GrantID, request.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(ctx, fresh.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("revoked grant access = %v", err)
	}
	if _, err := d.AuthenticatePublisherAccess(ctx, otherAccess.Token, "", now); err != nil {
		t.Fatal("independent grant revoked")
	}
	if err := d.RevokePublisherIdentity(ctx, u.TeamID, p.ID, request.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(ctx, otherAccess.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revoked identity accepted")
	}
}

func TestIntegrationPublisherNamespaceMemberOwnershipAndRemoval(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_namespace")
	r := oidcRouteRequest(t, d, now)
	e := publisherEnrollment(t, d, r, PublisherScope{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID}, now)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	u, err := d.AllocatePublisherPublicURL(t.Context(), p, invocation, "http://app.internal:3000", []string{}, []byte("null"), now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.AllocatePublisherPublicURL(t.Context(), p, invocation, "http://app.internal:3000", []string{}, []byte("null"), now)
	if err != nil || retry.ID != u.ID {
		t.Fatalf("allocation retry = %+v, %v", retry, err)
	}
	if _, err := d.AllocatePublisherPublicURL(t.Context(), p, invocation, "http://other.internal:3000", []string{}, []byte("null"), now); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatalf("changed retry target = %v", err)
	}
	if !strings.HasSuffix(u.CanonicalHostname, "."+p.Scope.Namespace) || !u.Ephemeral {
		t.Fatal("allocation escaped its namespace")
	}
	e2 := publisherEnrollment(t, d, r, p.Scope, now)
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	other, err := d.RedeemPublisherEnrollment(t.Context(), e2.Key, otherPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	if owns, err := d.PublisherMayStartRun(t.Context(), other, u.ID); err != nil || owns {
		t.Fatalf("foreign allocation ownership = %t, %v", owns, err)
	}
	wrong := AuthorizedPublicURLDeleteRequest{PublicURLID: u.ID, TeamID: u.TeamID, ActingIdentityID: p.CreatorID, PublisherIdentityID: other.ID, PublisherGrantID: other.GrantID}
	if err := d.DeleteAuthorizedPublicURL(t.Context(), wrong, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("foreign allocation cleanup = %v", err)
	}
	wrong.PublisherIdentityID, wrong.PublisherGrantID = p.ID, p.GrantID
	if err := d.DeleteAuthorizedPublicURL(t.Context(), wrong, now); err != nil {
		t.Fatalf("exact allocation cleanup = %v", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at=$2, removed_by_identity_id=identity_id WHERE id=$1`, r.MembershipID, now); err != nil {
		t.Fatal(err)
	}
	assertion, err := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherTestAudience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExchangePublisherAssertion(t.Context(), p.ID, p.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("member-owned credential survived removal: %v", err)
	}
	invocation2, _ := opaqueid.New(opaqueid.InvocationPrefix)
	if _, err := d.AllocatePublisherPublicURL(t.Context(), p, invocation2, "http://app.internal:3000", []string{}, nil, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("removed member allocated another URL: %v", err)
	}
}

func TestIntegrationPublisherRunRetryAndHeartbeatRevocation(t *testing.T) {
	d, now, r, _ := newPublishRunPrerequisites(t)
	url, err := d.GetPublicURLForAuthorization(t.Context(), r.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	base := CreatePublicURLRequest{TeamID: r.TeamID, ActingIdentityID: r.ActingIdentityID}
	e := publisherEnrollment(t, d, base, PublisherScope{TeamID: r.TeamID, Kind: "saved_public_url", PublicURLID: r.PublicURLID}, now)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := d.PublisherRunPlan(t.Context(), p, url, false)
	if err != nil {
		t.Fatal(err)
	}
	r.CertificateCacheKey, r.CertificateScope, r.CertificateIdentifiers, r.CertificateChallenge = plan.CacheKey, plan.Scope, plan.Identifiers, plan.ChallengeMethod
	r.PublisherIdentityID, r.PublisherGrantID, r.PublisherKeyID = p.ID, p.GrantID, p.KeyID
	r.PublisherRunProof, _ = publisherproof.SignRun(private, r.PublicURLID, r.IdempotencyKey)
	r.RetrySecret = nil
	setup, err := d.CreatePublishRun(t.Context(), r, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := d.CreatePublishRun(t.Context(), r, now, time.Minute, time.Minute)
	if err != nil || repeated.PublishRunToken != setup.PublishRunToken || repeated.PublishRunID != setup.PublishRunID {
		t.Fatalf("identity run retry = %+v, %v", repeated, err)
	}
	bad := r
	bad.IdempotencyKey = "changed"
	if _, err := d.CreatePublishRun(t.Context(), bad, now, time.Minute, time.Minute); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("proof reused for another attempt = %v", err)
	}
	e2 := publisherEnrollment(t, d, base, p.Scope, now)
	pk2, sk2, _ := ed25519.GenerateKey(rand.Reader)
	p2, err := d.RedeemPublisherEnrollment(t.Context(), e2.Key, pk2, now)
	if err != nil {
		t.Fatal(err)
	}
	bad = r
	bad.PublisherIdentityID, bad.PublisherGrantID, bad.PublisherKeyID = p2.ID, p2.GrantID, p2.KeyID
	bad.PublisherRunProof, _ = publisherproof.SignRun(sk2, r.PublicURLID, r.IdempotencyKey)
	if _, err := d.CreatePublishRun(t.Context(), bad, now, time.Minute, time.Minute); !errors.Is(err, ErrPublishRunIdempotency) {
		t.Fatalf("foreign identity recovered run = %v", err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: r.PublicURLID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := d.HeartbeatPublishRun(t.Context(), auth, now.Add(time.Second), time.Minute, time.Minute); err != nil {
		t.Fatalf("live publisher heartbeat: %v", err)
	}
	if err := d.RevokePublisherGrant(t.Context(), r.TeamID, p.ID, p.GrantID, r.ActingIdentityID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatPublishRun(t.Context(), auth, now.Add(3*time.Second), time.Minute, time.Minute); !errors.Is(err, ErrPublisherIdentity) && !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("revoked heartbeat = %v", err)
	}
	var closed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL FROM control.publish_runs WHERE id=$1`, setup.PublishRunID).Scan(&closed); err != nil || !closed {
		t.Fatalf("revoked run left open: %t, %v", closed, err)
	}
}

func TestIntegrationPublisherReplayRecordsAreBounded(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_replay_bound")
	r := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, r, now)
	e := publisherEnrollment(t, d, r, PublisherScope{TeamID: u.TeamID, Kind: "saved_public_url", PublicURLID: u.ID}, now)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = publisherAccess(t, d, p, private, "", now)
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.publisher_assertions(publisher_identity_id, assertion_id, expires_at) SELECT $1, lpad(i::text, 24, '0'), $2 FROM generate_series(1,255) i`, p.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertion, _ := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherTestAudience, private, now)
	if _, err := d.ExchangePublisherAssertion(t.Context(), p.ID, p.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("full replay budget = %v", err)
	}
	_ = publisherAccess(t, d, p, private, "", now.Add(61*time.Second))
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_assertions WHERE publisher_identity_id=$1`, p.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expired replay records = %d, %v", count, err)
	}
}

func TestIntegrationGuestPublisherScopeSourceAndExpiry(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "guest_publisher")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := d.CreateGuestTrial(t.Context(), guest, "example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllocateGuestDemoNumber(t.Context(), guest.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.EnsureGuestPrincipal(t.Context(), guest.ID, now); err != nil {
		t.Fatal(err)
	}
	u := createTestPublicURL(t, d, CreatePublicURLRequest{GuestID: guest.ID, TeamID: guest.TeamID, DomainID: domain, MembershipID: guest.MembershipID, ActingIdentityID: guest.ID, IdempotencyKey: "demo", CanonicalHostname: "demo-1." + guest.NamespaceLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeDemo, AllowedIPPrefixes: []string{"192.0.2.7/32"}, DNSState: PublicURLDNSUnmanaged, PolicyRevision: 1, Ephemeral: true}, now)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := d.EnrollGuestPublisher(t.Context(), guest.ID, u.ID, "192.0.2.8/32", public, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("foreign source enrollment = %v", err)
	}
	p, err := d.EnrollGuestPublisher(t.Context(), guest.ID, u.ID, "192.0.2.7/32", public, now)
	if err != nil {
		t.Fatal(err)
	}
	a := publisherAccess(t, d, p, private, "192.0.2.7/32", now)
	if _, err := d.AuthenticatePublisherAccess(t.Context(), a.Token, "192.0.2.8/32", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("guest token moved to another IP")
	}
	if _, err := d.AllocatePublisherPublicURL(t.Context(), p, "invocation", "http://127.0.0.1:3000", []string{}, nil, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("guest received namespace allocation")
	}
	if owns, err := d.PublisherMayStartRun(t.Context(), p, "some-other-demo"); err != nil || owns {
		t.Fatal("guest can publish an unassigned URL")
	}
	for _, reason := range []string{"expires_at=$2", "used_ready_ns=900000000000", "used_bytes=5242880"} {
		query := fmt.Sprintf(`UPDATE control.guest_trials SET %s WHERE id=$1`, reason)
		args := []any{guest.ID}
		if strings.Contains(reason, "$2") {
			args = append(args, now.Add(time.Second))
		}
		if _, err := d.pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
		if _, err := d.AuthenticatePublisherAccess(t.Context(), a.Token, "192.0.2.7/32", now.Add(2*time.Second)); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatalf("guest exhaustion accepted: %s", reason)
		}
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.guest_trials SET expires_at=$2, used_ready_ns=0, used_bytes=0 WHERE id=$1`, guest.ID, now.Add(GuestLifetime)); err != nil {
			t.Fatal(err)
		}
	}
}
