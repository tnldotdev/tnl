package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

const publisherTestAudience = "https://control.example/v1/publisher-token"

func TestIntegrationPublisherResolvedScopeUsesAuthorizedFacts(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_resolved_scope")
	actor := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "publisher-private", "publisher-private", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: actor.TeamID, IdentityID: actor.ActingIdentityID})
	if err != nil {
		t.Fatal(err)
	}
	for _, submitted := range []PublisherScope{
		{TeamID: actor.TeamID, Kind: "namespace", DomainID: actor.DomainID, MembershipID: "forged", NamespaceScope: NamespaceScope("shared")},
		{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID},
	} {
		e := publisherEnrollment(t, d, actor, submitted, now)
		if e.Scope.Kind == "service" && e.Scope != (PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID}) {
			t.Fatal("exact service grant retained unrelated scope facts", e.Scope)
		}
		if e.Scope.Kind == "namespace" && (e.Scope.MembershipID != m.ActorMembershipID || e.Scope.NamespaceScope != NamespaceScopeMember || e.Scope.Namespace == "") {
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
		if err != nil || scopeFromGrant(actor.TeamID, stored) != e.Scope {
			t.Fatal("grant persistence lost the authorized target", stored, err)
		}
	}
	for _, submitted := range []PublisherScope{
		{TeamID: actor.TeamID, Kind: "namespace", DomainID: actor.DomainID, ServiceID: service.ID},
		{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID, Namespace: "forged.example"},
		{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID, DomainID: actor.DomainID},
		{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID, MembershipID: m.ActorMembershipID, NamespaceScope: NamespaceScopeShared},
	} {
		if _, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{Scope: submitted, Name: "test", Kind: "installed", EditorID: actor.ActingIdentityID, EditorMembershipID: m.ActorMembershipID, PolicyRevision: uint64(m.PolicyRevision), Now: now}); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("mixed submitted scope was authorized", submitted, err)
		}
	}
}

func TestIntegrationPublisherFreshBaseline(t *testing.T) {
	d, _ := newControlStateIntegrationDatabase(t, "publisher_baseline")
	for _, name := range []string{"public_url_publish_credentials", "publish_run_publish_credentials", "ephemeral_public_url_allocations", "authority_revision_states", "tcp_port_claims", "ingress_pool_ports", "service_tickets", "publish_run_publisher_grants", "browser_access_sessions", "browser_access_handoffs", "browser_login_attempts", "publisher_service_runs", "publisher_service_connection_slots"} {
		var absent bool
		if err := d.pool.QueryRow(t.Context(), `SELECT to_regclass('control.' || $1) IS NULL`, name).Scan(&absent); err != nil || !absent {
			t.Fatalf("legacy table %s exists: %v", name, err)
		}
	}
	for _, name := range []string{"publisher_identities", "publisher_identity_keys", "publisher_grants", "publisher_enrollments", "publisher_assertions", "publisher_access_tokens", "publisher_namespace_allocations", "publisher_certificate_checkpoints", "previews", "shares", "service_http_browser_sessions", "service_http_browser_logins", "service_http_browser_handoffs", "service_runs", "service_connection_slots", "visitor_devices", "connector_peer_pairs"} {
		var present bool
		if err := d.pool.QueryRow(t.Context(), `SELECT to_regclass('control.' || $1) IS NOT NULL`, name).Scan(&present); err != nil || !present {
			t.Fatalf("final table %s missing: %v", name, err)
		}
	}
	var actualVersion int64
	var actualBaseline string
	if err := d.pool.QueryRow(t.Context(), `SELECT MAX(version_id) FILTER (WHERE is_applied) FROM control.goose_db_version`).Scan(&actualVersion); err != nil || actualVersion != schemaVersion {
		t.Fatal("fresh database did not initialize the current schema", actualVersion, err)
	}
	if err := d.pool.QueryRow(t.Context(), `SELECT baseline_id FROM control.schema_identity WHERE id=1`).Scan(&actualBaseline); err != nil || actualBaseline != baselineID {
		t.Fatal("fresh baseline identity changed", actualBaseline, err)
	}
	// a higher version alone does not prove that the serving binary supports it.
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.goose_db_version (version_id, is_applied) VALUES ($1, true)`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := d.Readiness(t.Context()); err == nil {
		t.Fatal("unsupported schema passed readiness")
	}
}

func publisherEnrollment(t *testing.T, d *Database, actor serviceTestAuthority, scope PublisherScope, now time.Time) PublisherEnrollment {
	t.Helper()
	m, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: actor.TeamID, IdentityID: actor.ActingIdentityID})
	if err != nil {
		t.Fatal(err)
	}
	e, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{Scope: scope, Name: "test", Kind: "installed", EditorID: actor.ActingIdentityID, EditorMembershipID: m.ActorMembershipID, PolicyRevision: uint64(m.PolicyRevision), Now: now})
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
	actor := seedControlServiceAuthority(t, d, now, "enroll")
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "enroll", "enroll", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID}, now)
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
	actor := seedControlServiceAuthority(t, d, now, "replay")
	first, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "first", "first", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: first.ID}, now)
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
	second, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "second", "second", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.CreatePublisherGrant(ctx, CreatePublisherGrantRequest{PublisherIdentityID: p.ID, Scope: PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: second.ID}, EditorID: actor.ActingIdentityID, EditorMembershipID: actor.MembershipID, PolicyRevision: 1, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	p2 := p
	p2.GrantID = grant
	p2.Scope.ServiceID = second.ID
	otherAccess := publisherAccess(t, d, p2, newPrivate, "", now)
	if err := d.RevokePublisherGrant(ctx, actor.TeamID, p.ID, p.GrantID, actor.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(ctx, fresh.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("revoked grant access = %v", err)
	}
	if _, err := d.AuthenticatePublisherAccess(ctx, otherAccess.Token, "", now); err != nil {
		t.Fatal("independent grant revoked")
	}
	if err := d.RevokePublisherIdentity(ctx, actor.TeamID, p.ID, actor.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(ctx, otherAccess.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revoked identity accepted")
	}
}

func TestIntegrationPublisherNamespaceMemberOwnershipAndRemoval(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_namespace")
	actor := oidcRouteRequest(t, d, now)
	e := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "namespace", DomainID: actor.DomainID}, now)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	request := AllocateServiceRequest{Invocation: invocation, Configuration: ProjectServiceConfiguration{Target: "http://app.internal:3000", RequirePostQuantum: new(true)}}
	u, err := d.AllocatePublisherService(t.Context(), p, request, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.AllocatePublisherService(t.Context(), p, request, now)
	if err != nil || retry.ID != u.ID || !retry.RequirePostQuantum {
		t.Fatalf("allocation retry = %+v, %v", retry, err)
	}
	changed := request
	changed.Configuration.Target = "http://other.internal:3000"
	if _, err := d.AllocatePublisherService(t.Context(), p, changed, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("changed retry target = %v", err)
	}
	changed = request
	changed.Configuration.RequirePostQuantum = nil
	if _, err := d.AllocatePublisherService(t.Context(), p, changed, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("retry changed the post-quantum requirement: %v", err)
	}
	if u.Endpoint == nil || !strings.HasSuffix(u.Endpoint.Hostname, "."+p.Scope.Namespace) || !u.Ephemeral || u.ExpiresAt != nil {
		t.Fatal("allocation escaped its namespace")
	}
	e2 := publisherEnrollment(t, d, actor, p.Scope, now)
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	other, err := d.RedeemPublisherEnrollment(t.Context(), e2.Key, otherPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetServiceForPublisher(t.Context(), u.ID, other, now); !failure.Only(err, ErrServiceAccess) {
		t.Fatal("foreign credential did not receive only the access denial", err)
	}
	if err := d.DeletePublisherService(t.Context(), other, u.ID, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("foreign allocation cleanup = %v", err)
	}
	if err := d.DeletePublisherService(t.Context(), p, u.ID, now); err != nil {
		t.Fatalf("exact allocation cleanup = %v", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at=$2, removed_by_identity_id=identity_id WHERE id=$1`, actor.MembershipID, now); err != nil {
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
	request.Invocation = invocation2
	if _, err := d.AllocatePublisherService(t.Context(), p, request, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("removed member allocated another service: %v", err)
	}
}

func TestIntegrationPublisherRunRetryAndHeartbeatRevocation(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	if err := d.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	request := ServiceRunRequest{Metadata: f.service.ServiceMetadata}
	prepared, err := d.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "retry", now, request)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := d.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "retry", now, request)
	if err != nil || !reflect.DeepEqual(repeated, prepared) {
		t.Fatal("prepare retry changed the run", err)
	}
	changed := request
	changed.PreferredRegions = []string{"aws:us-east-1"}
	if _, err := d.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "retry", now, changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("prepare retry changed the request binding: %v", err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "another-attempt", now, request); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("another attempt adopted the prepared run: %v", err)
	}
	f.prepared = prepared
	f.run, err = d.StartServiceRun(t.Context(), f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	started, err := d.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, now)
	if err != nil || started.RunID != f.run.RunID || started.Token != f.run.Token {
		t.Fatal("start retry changed the run or token", err)
	}
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.service.TeamID, ActingIdentityID: f.actor(t)}, f.publisher.Scope, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, foreign, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("foreign identity recovered the run: %v", err)
	}
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
	if _, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now.Add(time.Second), health); err != nil {
		t.Fatalf("live publisher heartbeat: %v", err)
	}
	if err := d.RevokePublisherGrant(t.Context(), f.service.TeamID, f.publisher.ID, f.publisher.GrantID, f.publisher.CreatorID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now.Add(3*time.Second), health); !errors.Is(err, ErrPublisherIdentity) && !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("revoked heartbeat = %v", err)
	}
	var closed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT state='closed' FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatalf("revoked run left open: %t, %v", closed, err)
	}
}

func TestIntegrationPublisherReplayRecordsAreBounded(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_replay_bound")
	actor := seedControlServiceAuthority(t, d, now, "replaybound")
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "replay", "replay", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID}, now)
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
	guest := newGuestTrialForTest(t, d, now)
	now = guestOperationTime(guest)
	u, err := d.AllocateGuestDemoService(t.Context(), AllocateGuestDemoServiceRequest{
		Credential: guestCredentialForTest(guest), IdempotencyKey: "demo", Target: guestLoopbackTarget(t), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.IPv6Unspecified(), netip.MustParseAddr("fe80::1%en0"), netip.MustParseAddr("192.0.2.8")} {
		credential := GuestCredential{Token: guest.Token, SourceIP: source}
		want := ErrGuestUnknown
		if source == netip.MustParseAddr("192.0.2.8") {
			want = authorization.ErrGuestIPChanged
		}
		if _, err := d.EnrollGuestPublisher(t.Context(), credential, u.ID, public, now); !errors.Is(err, want) {
			t.Fatalf("source %s enrolled publisher: %v", source, err)
		}
	}
	p, err := d.EnrollGuestPublisher(t.Context(), guestCredentialForTest(guest), u.ID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != "guest" || p.GuestID != guest.ID || p.Scope.GuestID != guest.ID || p.Scope.TeamID != "" ||
		p.CreatorID != "" || p.OwnerMembershipID != "" || p.Scope.Kind != "service" || p.Scope.ServiceID != u.ID {
		t.Fatalf("guest enrollment invented authority: %+v", p)
	}
	recovered, err := d.EnrollGuestPublisher(t.Context(), guestCredentialForTest(guest), u.ID, public, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(recovered, p) {
		t.Fatalf("enrollment retry changed publisher: %+v, %v", recovered, err)
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.EnrollGuestPublisher(t.Context(), guestCredentialForTest(guest), u.ID, wrongPublic, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("different key replaced guest publisher: %v", err)
	}
	a := publisherAccess(t, d, p, private, "192.0.2.7/32", now)
	if p.ExpiresAt == nil || !p.ExpiresAt.Equal(guest.ExpiresAt) || a.ExpiresAt == nil ||
		!a.ExpiresAt.Equal(*p.ExpiresAt) || !a.Until.Equal(now.Add(PublisherAccessLifetime)) || a.Until.Equal(*a.ExpiresAt) {
		t.Fatalf("guest grant expiry was replaced by token expiry: %+v, %+v", p, a)
	}
	for _, source := range []string{"", "192.0.2.8/32", "192.0.2.0/24", "0.0.0.0/32", "::/128"} {
		if _, err := d.AuthenticatePublisherAccess(t.Context(), a.Token, source, now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatalf("source %q authenticated guest publisher: %v", source, err)
		}
	}
	if _, err := d.AllocatePublisherService(t.Context(), p, AllocateServiceRequest{}, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("guest received namespace allocation")
	}
	if _, err := d.PrepareServiceRun(t.Context(), "svc_0000000000000000000000", p, "unassigned", now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: "tcp", TrustRevision: 1}}); err == nil {
		t.Fatal("guest can publish an unassigned service")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), a.Token, "192.0.2.7/32", now.Add(2*time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("READY exhaustion authenticated publisher: %v", err)
	}
	if _, err := d.EnrollGuestPublisher(t.Context(), guestCredentialForTest(guest), u.ID, public, guest.ExpiresAt); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("absolute trial expiry enrolled publisher: %v", err)
	}
}
