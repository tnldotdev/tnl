package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationPublicURLPublisherPoolsIndependentDNSCertificates(t *testing.T) {
	d, now, base, leases := newPublishRunPrerequisites(t)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.public_urls SET publisher_pool=true WHERE id=$1`, base.PublicURLID); err != nil {
		t.Fatal(err)
	}
	var runs []publishRunFixture
	var publishers []PublisherIdentity
	for index := range 2 {
		url, err := d.GetPublicURLForAuthorization(t.Context(), base.PublicURLID)
		if err != nil {
			t.Fatal(err)
		}
		enrollment := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: base.TeamID, ActingIdentityID: base.ActingIdentityID}, PublisherScope{TeamID: base.TeamID, Kind: "saved_url", PublicURLID: base.PublicURLID}, now)
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := d.PublisherRunPlan(t.Context(), publisher, url, false)
		if err != nil {
			t.Fatal(err)
		}
		request := base
		request.IdempotencyKey = fmt.Sprintf("publisher-%d", index)
		request.RequestDigest = sha256.Sum256([]byte(request.IdempotencyKey))
		request.ExpectedMutationRevision = url.MutationRevision
		request.CertificateCacheKey, request.CertificateScope, request.CertificateIdentifiers, request.CertificateChallenge = plan.CacheKey, plan.Scope, plan.Identifiers, plan.ChallengeMethod
		request.PublisherIdentityID, request.PublisherGrantID, request.PublisherKeyID = publisher.ID, publisher.GrantID, publisher.KeyID
		request.PublisherRunProof, err = publisheridentity.SignRun(key, url.ID, request.IdempotencyKey)
		if err != nil {
			t.Fatal(err)
		}
		request.RetrySecret = nil
		setup, err := d.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		fixture := publishRunFixture{database: d, now: now, request: request, setup: setup, leases: leases}
		readyTestSession(t, fixture)
		runs = append(runs, fixture)
		publishers = append(publishers, publisher)
	}
	ingress := registerTestIngress(t, d, now)
	snapshot, err := d.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 2 {
		t.Fatalf("two ready certificate holders: %+v %v", snapshot, err)
	}
	controlSession := browserTestControlSession(t, d, base.ActingIdentityID, now)
	handoff, err := d.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{PublicURLID: base.PublicURLID, PublishRunID: runs[0].setup.PublishRunID, ReturnPath: "/"}, BrowserAccessSession{
		IdentityID: base.ActingIdentityID, DisplayName: "pool visitor", AccessToken: controlSession.AccessToken.String(), RefreshToken: controlSession.RefreshToken.String(),
		AccessExpiresAt: controlSession.AccessExpiresAt, ExpiresAt: controlSession.RefreshExpiresAt}, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, _, _, _, err := d.RedeemBrowserHandoff(t.Context(), runs[1].authentication(), handoff.Token, now)
	if err != nil {
		t.Fatalf("pool sibling could not redeem host-bound browser handoff: %v", err)
	}
	var issuances []string
	for _, run := range runs {
		var issuance string
		if err = d.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.publish_runs WHERE id=$1`, run.setup.PublishRunID).Scan(&issuance); err != nil {
			t.Fatal(err)
		}
		issuances = append(issuances, issuance)
	}
	if issuances[0] == issuances[1] {
		t.Fatal("pool publishers shared a certificate issuance")
	}
	if err = d.ClosePublishRun(t.Context(), runs[0].setup.PublishRunID, runs[0].setup.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	if permission, err := d.HTTPVisitorPermission(t.Context(), runs[1].authentication(), HTTPVisitorRequest{SourceIP: "192.0.2.9", BrowserCookieSecret: cookie}, now); err != nil || !permission.VisitAllowed {
		t.Fatalf("closed pool sibling invalidated browser access: %+v %v", permission, err)
	}
	snapshot, err = d.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 1 {
		t.Fatalf("run tombstone removed pool sibling: %+v %v", snapshot, err)
	}
	for _, entry := range snapshot.Entries {
		if entry.Projection.PublishRunID != runs[1].setup.PublishRunID {
			t.Fatalf("closed run remains routable: %+v", entry)
		}
	}
	if err = d.RevokePublisherGrant(t.Context(), base.TeamID, publishers[1].ID, publishers[1].GrantID, base.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err = d.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 0 {
		t.Fatalf("revoked pool run retained projection: %+v %v", snapshot, err)
	}
	row, err := controlstatedb.New(d.pool).GetPublishRun(t.Context(), runs[1].setup.PublishRunID)
	if err != nil || !row.ClosedAt.Valid {
		t.Fatalf("revoked publisher runtime is open: %+v %v", row, err)
	}
}
