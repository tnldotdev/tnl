package controlstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/zalando/go-keyring"
)

// the controlled CA fixture exercises real publisher CSRs, persistent private
// cache keys, issuance/install acknowledgments, relay readiness and routing.
func TestIntegrationPublicPublisherScopedCertificateCachePool(t *testing.T) {
	d, now, base, leases := newPublishRunPrerequisites(t)
	creation := oidcRouteRequest(t, d, now)
	creation.PublisherPool = true
	url, err := d.CreatePublicURL(t.Context(), creation, now)
	if err != nil {
		t.Fatal(err)
	}
	base.PublicURLID, base.TeamID, base.ActingIdentityID, base.MembershipID, base.PolicyRevision = url.ID, url.TeamID, creation.ActingIdentityID, url.MembershipID, uint64(url.PolicyRevision)
	keyring.MockInit()
	root := filepath.Join(t.TempDir(), "client-state")
	local, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = local.Close() })
	profile, err := local.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	var runs []publishRunFixture
	var publishers []PublisherIdentity
	var signingKeys []ed25519.PrivateKey
	var materials []clientstate.Material
	var csrs [][]byte
	for index := range 2 {
		enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: url.TeamID, Kind: "saved_url", PublicURLID: url.ID}, now)
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		current, err := d.GetPublicURLForAuthorization(t.Context(), url.ID)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := d.PublisherRunPlan(t.Context(), publisher, current, false)
		if err != nil {
			t.Fatal(err)
		}
		request := base
		request.ExpectedMutationRevision = current.MutationRevision
		request.IdempotencyKey = fmt.Sprintf("publisher-cache-%d", index)
		request.RequestDigest = sha256.Sum256([]byte(request.IdempotencyKey))
		request.CertificateCacheKey, request.CertificateScope, request.CertificateIdentifiers, request.CertificateChallenge = plan.CacheKey, plan.Scope, plan.Identifiers, plan.ChallengeMethod
		request.PublisherIdentityID, request.PublisherGrantID, request.PublisherKeyID = publisher.ID, publisher.GrantID, publisher.KeyID
		request.PublisherRunProof, err = publisheridentity.SignRun(key, url.ID, request.IdempotencyKey)
		if err != nil {
			t.Fatal(err)
		}
		setup, err := d.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		run := publishRunFixture{database: d, now: now, request: request, setup: setup, leases: leases}
		cache, err := profile.CertificatesForPublisher(url.TeamID, publisher.ID, controlv1.CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod)})
		if err != nil {
			t.Fatal(err)
		}
		lock, err := cache.Lock(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lock.Close() })
		pending, err := cache.Pending(t.Context(), url.CanonicalHostname)
		if err != nil {
			_ = lock.Close()
			t.Fatal(err)
		}
		material := deliverLifecycleCertificate(t, d, cache, run.authentication(), url.CanonicalHostname, run.certificatePlan(), now)
		if _, err = d.MarkPublicURLCertificateInstalled(t.Context(), run.authentication(), material.IssuanceID, material.Certificate.Leaf.NotAfter, now); err != nil {
			_ = lock.Close()
			t.Fatal(err)
		}
		if err = cache.Promote(t.Context(), url.CanonicalHostname, material.IssuanceID); err != nil {
			_ = lock.Close()
			t.Fatal(err)
		}
		_ = lock.Close()
		for slot := range 2 {
			claimTestConnection(t, run, slot, now)
		}
		if _, err = d.MarkPublishRunReady(t.Context(), run.authentication(), now); err != nil {
			t.Fatal(err)
		}
		order, err := controlstatedb.New(d.pool).GetACMEOrder(t.Context(), material.IssuanceID)
		if err != nil || !bytes.Equal(order.CsrDer, pending.CSRDER) {
			t.Fatal("issued certificate did not use this publisher's persistent CSR", err)
		}
		csr, err := x509.ParseCertificateRequest(order.CsrDer)
		if err != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, material.Certificate.Leaf.RawSubjectPublicKeyInfo) {
			t.Fatal("issued public certificate does not match its publisher key", err)
		}
		runs = append(runs, run)
		publishers = append(publishers, publisher)
		signingKeys = append(signingKeys, key)
		materials = append(materials, material)
		csrs = append(csrs, bytes.Clone(pending.CSRDER))
	}
	if bytes.Equal(csrs[0], csrs[1]) || bytes.Equal(materials[0].Certificate.Leaf.RawSubjectPublicKeyInfo, materials[1].Certificate.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("pooled publishers shared a CSR/private TLS key")
	}
	ingress := registerTestIngress(t, d, now)
	snapshot, err := d.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 2 {
		t.Fatalf("both independently certified publishers are not routable: %+v %v", snapshot, err)
	}
	for _, entry := range snapshot.Entries {
		if entry.CanonicalHostname != url.CanonicalHostname || len(entry.Projection.PublisherConnections) != 2 {
			t.Fatal("pool routing did not retain the common hostname and each run's two slots")
		}
	}
	if err = local.Close(); err != nil {
		t.Fatal(err)
	}
	local, err = clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = local.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ClosePublishRun(t.Context(), runs[0].setup.PublishRunID, runs[0].setup.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	current, err := d.GetPublicURLForAuthorization(t.Context(), url.ID)
	if err != nil {
		t.Fatal(err)
	}
	request := runs[0].request
	request.IdempotencyKey = "publisher-cache-restart"
	request.ExpectedMutationRevision = current.MutationRevision
	request.PublisherRunProof, err = publisheridentity.SignRun(signingKeys[0], url.ID, request.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := d.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	restarted := publishRunFixture{database: d, now: now, request: request, setup: setup, leases: leases}
	plan := runs[0].certificatePlan()
	cache, err := profile.CertificatesForPublisher(url.TeamID, publishers[0].ID, controlv1.CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod)})
	if err != nil {
		t.Fatal(err)
	}
	reused, found, err := cache.Current(t.Context(), url.CanonicalHostname)
	if err != nil || !found || reused.IssuanceID != materials[0].IssuanceID {
		t.Fatal("publisher restart lost its own acknowledged cache", err)
	}
	if _, err = d.MarkPublicURLCertificateInstalled(t.Context(), restarted.authentication(), reused.IssuanceID, reused.Certificate.Leaf.NotAfter, now); err != nil {
		t.Fatal(err)
	}
	for slot := range 2 {
		claimTestConnection(t, restarted, slot, now)
	}
	if _, err = d.MarkPublishRunReady(t.Context(), restarted.authentication(), now); err != nil {
		t.Fatal(err)
	}
	var issued int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.acme_orders`).Scan(&issued); err != nil || issued != 2 {
		t.Fatalf("restart requested another CA issuance instead of own reuse: %d %v", issued, err)
	}
	snapshot, err = d.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 2 {
		t.Fatal("restart removed a healthy pool sibling", err)
	}
}
