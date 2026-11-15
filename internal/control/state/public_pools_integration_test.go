package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationPublicURLPublisherPoolsIndependentDNSCertificates(t *testing.T) {
	d, now, base, leases := newPublishRunPrerequisites(t)
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	base.PublicURLID, base.TeamID, base.ActingIdentityID, base.MembershipID = url.ID, request.TeamID, request.ActingIdentityID, request.MembershipID
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
		enrollment := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: base.TeamID, ActingIdentityID: base.ActingIdentityID}, PublisherScope{TeamID: base.TeamID, Kind: "saved_public_url", PublicURLID: base.PublicURLID}, now)
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
		request.PublisherRunProof, err = publisherproof.SignRun(key, url.ID, request.IdempotencyKey)
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
	// browser replica assertions live in the service-backed test below. this
	// retained suite still proves the legacy pool's DNS/certificate boundaries.
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

func TestIntegrationServicePoolBrowserHandoffSurvivesSiblingClosure(t *testing.T) {
	f := newServiceHTTPFixture(t)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.services SET publisher_pool=true WHERE id=$1`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	f.service.PublisherPool = true
	f.run = f.publish(t, f.service)
	sibling := f
	sibling.run = f.publish(t, f.service)
	handoff, _ := f.browser(t, "", f.project.ActorID)
	cookie, err := f.database.RedeemServiceBrowserHandoff(t.Context(), sibling.auth(), handoff.Token, f.now)
	if err != nil {
		t.Fatalf("pool sibling could not redeem host-bound browser handoff: %v", err)
	}
	var first, second string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT a.certificate_issuance_id,b.certificate_issuance_id
		FROM control.service_runs a CROSS JOIN control.service_runs b WHERE a.id=$1 AND b.id=$2`,
		f.run.RunID, sibling.run.RunID).Scan(&first, &second); err != nil || first == second {
		t.Fatal("service pool publishers shared a certificate issuance", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	if permission, err := f.database.ServiceBrowserSession(t.Context(), sibling.auth(), cookie.CookieSecret, false, f.now); err != nil || !permission.VisitAllowed {
		t.Fatalf("closed pool sibling invalidated browser access: %+v %v", permission, err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, sibling.auth().Subject, BrowserSessionTokenSource{Secret: cookie.CookieSecret}, f.now); err != nil {
		t.Fatal("closed pool sibling invalidated captured browser permission", err)
	}
}
