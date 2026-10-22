package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func reviewPublisher(t *testing.T, d *Database, publicURL PublicURL, editor string, now time.Time) (PublisherIdentity, ed25519.PrivateKey) {
	t.Helper()
	e := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: publicURL.TeamID, ActingIdentityID: editor}, PublisherScope{TeamID: publicURL.TeamID, Kind: "saved_public_url", PublicURLID: publicURL.ID}, now)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	return p, private
}

func reviewRunRequest(t *testing.T, d *Database, p PublisherIdentity, private ed25519.PrivateKey, publicURL PublicURL, retry string) PublishRunRequest {
	t.Helper()
	plan, err := d.PublisherRunPlan(t.Context(), p, publicURL, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := publisherproof.SignRun(private, publicURL.ID, retry)
	if err != nil {
		t.Fatal(err)
	}
	return PublishRunRequest{PublicURLID: publicURL.ID, TeamID: publicURL.TeamID, MembershipID: publicURL.MembershipID, ActingIdentityID: p.CreatorID, IdempotencyKey: retry, RequestDigest: sha256.Sum256([]byte(retry)), PolicyRevision: uint64(publicURL.PolicyRevision), ExpectedMutationRevision: publicURL.MutationRevision, CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers, CertificateChallenge: plan.ChallengeMethod, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, PublisherKeyID: p.KeyID, PublisherRunProof: proof}
}

func reviewSharedURL(t *testing.T, f transactionAuthorityFixture) PublicURL {
	t.Helper()
	r := f.createRequest
	r.ActingIdentityID, r.MembershipID, r.PublicURLScope = f.owner, "", PublicURLScopeShared
	r.CanonicalHostname, r.IdempotencyKey = "shared."+f.domain.CanonicalDomain, "shared-publisher"
	return createTestPublicURL(t, f.database, r, f.now)
}

func TestIntegrationPublisherRevocationRechecksWaitingEditor(t *testing.T) {
	for _, mutation := range []string{"identity", "grant"} {
		for _, change := range []string{"removed", "demoted"} {
			t.Run(mutation+"/"+change, func(t *testing.T) {
				f := newTransactionAuthorityFixture(t)
				d := f.database
				p, _ := reviewPublisher(t, d, reviewSharedURL(t, f), f.owner, f.now)
				if err := d.AuthorizePublisherManagement(t.Context(), f.member.TeamID, p.ID, f.member.IdentityID); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				q := controlstatedb.New(gate)
				if _, err := q.LockLocalTeamForMutation(ctx, f.member.TeamID); err != nil {
					t.Fatal(err)
				}
				if _, err := q.LockPublisherIdentity(ctx, p.ID); err != nil {
					t.Fatal(err)
				}
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				revoked := make(chan error, 1)
				revoke := func(editor string) error {
					if mutation == "identity" {
						return d.RevokePublisherIdentity(ctx, f.member.TeamID, p.ID, editor, f.now)
					}
					return d.RevokePublisherGrant(ctx, f.member.TeamID, p.ID, p.GrantID, editor, f.now)
				}
				workers.Go(func() { revoked <- revoke(f.member.IdentityID) })
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), revoked)
				revision, err := q.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{TeamID: f.member.TeamID, UpdatedAt: timestamp(f.now)})
				if err != nil {
					t.Fatal(err)
				}
				if change == "removed" {
					_, err = q.RemoveTeamMembership(ctx, controlstatedb.RemoveTeamMembershipParams{MembershipID: f.member.ID, TeamID: f.member.TeamID, AuthorityRevision: revision, RemovedAt: timestamp(f.now), RemovedByIdentityID: text(f.owner)})
				} else {
					_, err = q.UpdateMembershipRole(ctx, controlstatedb.UpdateMembershipRoleParams{MembershipID: f.member.ID, TeamID: f.member.TeamID, Role: "member", AuthorityRevision: revision, UpdatedAt: timestamp(f.now)})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, revoked); !errors.Is(err, ErrPublisherIdentity) {
					t.Fatalf("stale editor revoked %s after being %s: %v", mutation, change, err)
				}
				var changed bool
				query := `SELECT revoked_at IS NOT NULL FROM control.publisher_identities WHERE id=$1`
				id := p.ID
				if mutation == "grant" {
					query, id = `SELECT revoked_at IS NOT NULL FROM control.publisher_grants WHERE id=$1`, p.GrantID
				}
				if err := d.pool.QueryRow(ctx, query, id).Scan(&changed); err != nil || changed {
					t.Fatalf("rejected revocation committed: %t, %v", changed, err)
				}
				if err := revoke(f.owner); err != nil {
					t.Fatalf("current owner could not revoke: %v", err)
				}
			})
		}
	}
}

func TestIntegrationPublisherHeartbeatDomainReleaseLockOrder(t *testing.T) {
	f := newTransactionAuthorityFixture(t)
	d := f.database
	publicURL := reviewSharedURL(t, f)
	registerCertificatePlanRelays(t, d, f.now)
	p, private := reviewPublisher(t, d, publicURL, f.owner, f.now)
	r := reviewRunRequest(t, d, p, private, publicURL, "release-race")
	setup, err := d.CreatePublishRun(t.Context(), r, f.now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: publicURL.ID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockPublisherIdentity(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	heartbeat, release := make(chan error, 1), make(chan error, 1)
	workers.Go(func() {
		_, err := d.HeartbeatPublishRun(ctx, auth, f.now.Add(time.Second), time.Hour, time.Hour)
		heartbeat <- err
	})
	heartbeatPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), heartbeat)
	workers.Go(func() {
		release <- d.ReleaseTeamDomain(ctx, f.owner, publicURL.TeamID, publicURL.DomainID, f.now.Add(2*time.Second))
	})
	// release now holds team/domain locks and waits for heartbeat's URL lock.
	// heartbeat must not acquire either earlier lock after the publisher gate.
	waitForPostgresBlock(t, ctx, d, heartbeatPID, release)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, heartbeat); err != nil {
		t.Fatalf("heartbeat deadlocked with domain release: %v", err)
	}
	if err := awaitIntegrationResult(t, ctx, release); err != nil {
		t.Fatalf("domain release did not finish: %v", err)
	}
	var closed bool
	if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL AND close_reason='domain_releasing' FROM control.publish_runs WHERE id=$1`, setup.PublishRunID).Scan(&closed); err != nil || !closed {
		t.Fatalf("release failed to close run: %t, %v", closed, err)
	}
}

func TestIntegrationPublisherRetiredKeyOnlyRecoversExactRun(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "retired_publisher_key")
	request := oidcRouteRequest(t, d, now)
	publicURL := createTestPublicURL(t, d, request, now)
	registerCertificatePlanRelays(t, d, now)
	p, private := reviewPublisher(t, d, publicURL, request.ActingIdentityID, now)
	access := publisherAccess(t, d, p, private, "", now)
	r := reviewRunRequest(t, d, p, private, publicURL, "original")
	setup, err := d.CreatePublishRun(t.Context(), r, now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	public, replacement, _ := ed25519.GenerateKey(rand.Reader)
	keyID, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	audience := "https://control.example/v1/publisher-keys/rotate"
	proof, _ := publisherproof.Sign(p.ID, keyID, p.GrantID, audience, replacement, now)
	currentProof, _ := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherproof.RotationAudience(audience, keyID, public), private, now)
	if err := d.RotatePublisherKey(t.Context(), access.Token, "", keyID, audience, public, proof, currentProof, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatalf("bounded old token unexpectedly expired: %v", err)
	}
	retry, err := d.CreatePublishRun(t.Context(), r, now, time.Hour, time.Hour)
	if err != nil || retry.PublishRunToken != setup.PublishRunToken || retry.PublishRunID != setup.PublishRunID {
		t.Fatalf("retired key could not retry its exact run: %v", err)
	}
	changed := r
	changed.RequestDigest = sha256.Sum256([]byte("changed request"))
	if _, err := d.CreatePublishRun(t.Context(), changed, now, time.Hour, time.Hour); !errors.Is(err, ErrPublishRunIdempotency) {
		t.Fatalf("retired key changed its request binding: %v", err)
	}
	if err := d.ClosePublishRun(t.Context(), setup.PublishRunID, setup.PublishRunToken, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	publicURL, err = d.GetPublicURLForAuthorization(t.Context(), publicURL.ID)
	if err != nil {
		t.Fatal(err)
	}
	newRun := reviewRunRequest(t, d, p, private, publicURL, "new-attempt")
	if _, err := d.CreatePublishRun(t.Context(), newRun, now.Add(2*time.Second), time.Hour, time.Hour); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("retired key started a new run: %v", err)
	}
	p.KeyID = keyID
	newRun = reviewRunRequest(t, d, p, replacement, publicURL, "new-attempt")
	if _, err := d.CreatePublishRun(t.Context(), newRun, now.Add(2*time.Second), time.Hour, time.Hour); err != nil {
		t.Fatalf("current key could not start a new run: %v", err)
	}
}

func TestIntegrationPublisherSavedPurposesHaveExactGrants(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_saved_purposes")
	base := oidcRouteRequest(t, d, now)
	registerCertificatePlanRelays(t, d, now)
	for _, purpose := range []PublicURLPurpose{PublicURLPurposeApp, PublicURLPurposeOAuth, PublicURLPurposeWebhooks, PublicURLPurposeAlias, PublicURLPurposeDemo} {
		r := base
		r.Purpose, r.CanonicalHostname, r.IdempotencyKey = purpose, string(purpose)+"."+base.CanonicalHostname, string(purpose)
		publicURL := createTestPublicURL(t, d, r, now)
		p, private := reviewPublisher(t, d, publicURL, r.ActingIdentityID, now)
		a := publisherAccess(t, d, p, private, "", now)
		if got, err := d.AuthenticatePublisherAccess(t.Context(), a.Token, "", now); err != nil || got.Scope.PublicURLID != publicURL.ID {
			t.Fatalf("%s grant unavailable: %+v, %v", purpose, got, err)
		}
		if owns, err := d.PublisherMayStartRun(t.Context(), p, "another-url"); err != nil || owns {
			t.Fatalf("%s grant expanded beyond exact URL", purpose)
		}
		setup, err := d.CreatePublishRun(t.Context(), reviewRunRequest(t, d, p, private, publicURL, "purpose-"+string(purpose)), now, time.Minute, time.Minute)
		if err != nil {
			t.Fatalf("%s publisher run: %v", purpose, err)
		}
		if err := d.ClosePublishRun(t.Context(), setup.PublishRunID, setup.PublishRunToken, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationPublisherSharedGrantSurvivesIssuerRemoval(t *testing.T) {
	f := newTransactionAuthorityFixture(t)
	d := f.database
	publicURL := reviewSharedURL(t, f)
	registerCertificatePlanRelays(t, d, f.now)
	p, private := reviewPublisher(t, d, publicURL, f.member.IdentityID, f.now)
	setup, err := d.CreatePublishRun(t.Context(), reviewRunRequest(t, d, p, private, publicURL, "durable-shared"), f.now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMembership(t.Context(), f.owner, publicURL.TeamID, f.member.ID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: publicURL.ID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := d.HeartbeatPublishRun(t.Context(), auth, f.now.Add(2*time.Second), time.Hour, time.Hour); err != nil {
		t.Fatalf("issuer departure erased its explicitly issued shared grant: %v", err)
	}
	if err := d.RevokePublisherGrant(t.Context(), publicURL.TeamID, p.ID, p.GrantID, f.member.IdentityID, f.now.Add(3*time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("departed issuer retained grant management: %v", err)
	}
	if err := d.RevokePublisherGrant(t.Context(), publicURL.TeamID, p.ID, p.GrantID, f.owner, f.now.Add(3*time.Second)); err != nil {
		t.Fatalf("current owner could not revoke durable grant: %v", err)
	}
	if _, err := d.HeartbeatPublishRun(t.Context(), auth, f.now.Add(4*time.Second), time.Hour, time.Hour); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("revoked shared grant remained live: %v", err)
	}
}
