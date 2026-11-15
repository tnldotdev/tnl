package state

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/zalando/go-keyring"
)

// the controlled CA fixture exercises real publisher CSRs, persistent private
// cache keys, issuance/install acknowledgments, relay readiness and routing.
func TestIntegrationPublicPublisherScopedCertificateCachePool(t *testing.T) {
	d, now, actor, leases := newPublishRunPrerequisites(t)
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "pool", "pool",
		ServicePlacement{}, now, ServiceMetadata{PublisherPool: true},
		&ProjectServiceConfiguration{Target: "localhost:3000", Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
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
	var runs []servicePublicationFixture
	var materials []clientstate.Material
	var csrs [][]byte
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
	ingress := registerTestIngress(t, d, now)
	checkPool := func(expected ...servicePublicationFixture) {
		t.Helper()
		snapshot, err := d.ReadIngressServices(t.Context(), ingress.IngressLeaseIdentity, now)
		if err != nil || len(snapshot.Runs) != len(expected) {
			t.Fatal("pool returned starting, closed, or missing publishers", len(snapshot.Runs), len(expected), err)
		}
		seen := make(map[string]bool, len(expected))
		for _, admission := range snapshot.Runs {
			if admission.ServiceID != service.ID || len(admission.Relays) != 2 || seen[admission.RunID] {
				t.Fatal("pool lost a certified publisher or its two connection slots", admission)
			}
			seen[admission.RunID] = true
			var selected *servicePublicationFixture
			for i := range expected {
				if expected[i].run.RunID == admission.RunID && expected[i].run.RunNumber == admission.RunNumber {
					selected = &expected[i]
					break
				}
			}
			if selected == nil || selected.prepared.Hostname != service.Endpoint.Hostname {
				t.Fatal("pool selected a foreign run or hostname", admission)
			}
			for i, relay := range admission.Relays {
				slot := selected.run.Connections[i]
				if relay.PublisherConnectionID != slot.PublisherConnectionID || relay.ConnectionSlot != slot.ConnectionSlot {
					t.Fatal("pool admission mixed publisher connection slots")
				}
			}
		}
	}
	for index := range 2 {
		publisher, _ := reviewPublisher(t, d, service, actor.ActingIdentityID, actor.MembershipID, 1, now)
		run := servicePublicationFixture{database: d, now: now, service: service, publisher: publisher, leases: leases}
		run.start(t, fmt.Sprintf("publisher-cache-%d", index), now)
		plan := run.prepared.CertificatePlan
		if index == 1 {
			pending, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.run.RunID, run.run.Token, now, health)
			if err != nil || pending.State != "starting" {
				t.Fatal("uncertified publisher became ready", pending, err)
			}
			if ready, err := d.HeartbeatServiceRun(t.Context(), service.ID, runs[0].run.RunID, runs[0].run.Token, now, health); err != nil || ready.State != "ready" {
				t.Fatal("starting pooled publisher blocked its ready sibling", ready, err)
			}
			checkPool(runs[0])
		}
		cache, err := profile.CertificatesForPublisher(service.TeamID, publisher.ID, controlv1.CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod)})
		if err != nil {
			t.Fatal(err)
		}
		lock, err := cache.Lock(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lock.Close() })
		pending, err := cache.Pending(t.Context(), service.Endpoint.Hostname)
		if err != nil {
			_ = lock.Close()
			t.Fatal(err)
		}
		material := deliverLifecycleCertificate(t, d, cache, run.run, service.Endpoint.Hostname, plan, now)
		if err = d.MarkServiceCertificateInstalled(t.Context(), service.ID, run.run.RunID, run.run.Token, material.IssuanceID, run.run.RunNumber, material.Certificate.Leaf.NotAfter, now); err != nil {
			_ = lock.Close()
			t.Fatal(err)
		}
		if err = cache.Promote(t.Context(), service.Endpoint.Hostname, material.IssuanceID); err != nil {
			_ = lock.Close()
			t.Fatal(err)
		}
		_ = lock.Close()
		run.readyConnections(t, now)
		if ready, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.run.RunID, run.run.Token, now, health); err != nil || ready.State != "ready" {
			t.Fatal("certified publisher with both connections did not become ready", ready, err)
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
		materials = append(materials, material)
		csrs = append(csrs, bytes.Clone(pending.CSRDER))
	}
	if bytes.Equal(csrs[0], csrs[1]) || bytes.Equal(materials[0].Certificate.Leaf.RawSubjectPublicKeyInfo, materials[1].Certificate.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("pooled publishers shared a CSR/private TLS key")
	}
	checkPool(runs...)
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
	if err = d.CloseServiceRun(t.Context(), service.ID, runs[0].run.RunID, runs[0].run.Token, now); err != nil {
		t.Fatal(err)
	}
	checkPool(runs[1])
	restarted := runs[0]
	restarted.start(t, "publisher-cache-restart", now)
	plan := restarted.prepared.CertificatePlan
	cache, err := profile.CertificatesForPublisher(service.TeamID, restarted.publisher.ID, controlv1.CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod)})
	if err != nil {
		t.Fatal(err)
	}
	reused, found, err := cache.Current(t.Context(), service.Endpoint.Hostname)
	if err != nil || !found || reused.IssuanceID != materials[0].IssuanceID {
		t.Fatal("publisher restart lost its own acknowledged cache", err)
	}
	if err = d.MarkServiceCertificateInstalled(t.Context(), service.ID, restarted.run.RunID, restarted.run.Token, reused.IssuanceID, restarted.run.RunNumber, reused.Certificate.Leaf.NotAfter, now); err != nil {
		t.Fatal(err)
	}
	restarted.readyConnections(t, now)
	if ready, err := d.HeartbeatServiceRun(t.Context(), service.ID, restarted.run.RunID, restarted.run.Token, now, health); err != nil || ready.State != "ready" {
		t.Fatal("cached certificate did not restore the restarted publisher", ready, err)
	}
	var issued int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.acme_orders`).Scan(&issued); err != nil || issued != 2 {
		t.Fatalf("restart requested another CA issuance instead of own reuse: %d %v", issued, err)
	}
	checkPool(restarted, runs[1])
}
