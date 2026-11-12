package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationManagedCertificateRunAuthority(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	r := retainedEnvironmentProject(t, d, now)
	definition, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ProjectLabel: "storefront", ActorID: r.ActorID, Definition: ServiceDefinition{Services: map[string]ServiceDefinitionService{"orders": {Protocol: "postgres"}, "api": {Protocol: "http"}}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := d.CreateEnvironment(t.Context(), CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ProjectLabel: "storefront", ActorID: r.ActorID, Name: "production", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"orders": {Address: "orders.internal:5432"}, "api": {Address: "api.internal:3000"}}, IdempotencyKey: "certificate-environment", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	e := retainedPublisherEnrollment(t, d, r, applied, 2)
	a, b := retainedPublisherReplica(t, d, e, now), retainedPublisherReplica(t, d, e, now)
	if len(a.assignments.CertificateStatePlans) != 0 || len(b.assignments.CertificateStatePlans) != 0 {
		t.Fatal("fresh replicas required nonexistent certificate state")
	}
	attempt := 0
	start := func(replica environmentPublisherReplica, name string) (ServiceRunPreparation, ServiceRunState) {
		t.Helper()
		var assignment EnvironmentPublisherAssignment
		for _, candidate := range replica.assignments.Services {
			if candidate.Service == name {
				assignment = candidate
			}
		}
		access := environmentAssignmentAccess(t, d, replica, assignment, now)
		attempt++
		prep, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, fmt.Sprintf("managed-test-%d", attempt), now, ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}, &replica.assignments.Environment)
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		return prep, run
	}
	prep, run := start(a, "orders")
	readySlots := func(active ServiceRunState) {
		t.Helper()
		for _, slot := range active.Connections {
			lease := leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, active.ServiceID, active.RunID, active.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
				t.Fatal(err)
			}
			if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, active.RunID, active.RunNumber, slot.Revision, lease, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	readySlots(run)
	if state, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "starting" {
		t.Fatal("run became ready without a service certificate", state, err)
	}
	_, other := start(b, "orders")
	_, sibling := start(a, "api")
	plan := prep.CertificatePlan
	var namespace string
	if err := d.pool.QueryRow(t.Context(), `SELECT assignment.namespace FROM control.environments environment JOIN control.project_publisher_groups assignment ON assignment.id=environment.group_id WHERE environment.id=$1`, applied.ID).Scan(&namespace); err != nil {
		t.Fatal(err)
	}
	if plan.Scope != namespace || !slices.Equal(plan.Identifiers, []string{"*." + namespace}) || plan.ChallengeMethod != "dns-01" {
		t.Fatal("private run did not capture its exact group plan", plan)
	}
	const directory = "https://acme.example.test/directory"
	if _, err = d.EnsureACMEAccount(t.Context(), directory, "operator@example.test", now); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: plan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := d.CreateServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token, directory, "csr", run.RunNumber, csr, now)
	if err != nil || issue.PublicURLID != "" || issue.PublishRunID != "" || issue.ServiceRunID != run.RunID {
		t.Fatal("private issuance required a public subject", issue, err)
	}
	checkpointBoundary, err := d.GetEnvironmentPublisherAssignments(t.Context(), a.lease.AccessToken, now)
	if err != nil || len(checkpointBoundary.CertificateStatePlans) == 0 {
		t.Fatal("issuance did not require durable state for future replacements", err)
	}
	if len(checkpointBoundary.CertificateStatePlans) != 1 || checkpointBoundary.CertificateStatePlans[0].CacheKey != plan.CacheKey || !slices.Equal(checkpointBoundary.CertificateStatePlans[0].Identifiers, plan.Identifiers) {
		t.Fatal("issuance did not checkpoint its exact plan", checkpointBoundary.CertificateStatePlans)
	}
	t.Run("checkpoint-survives-order-retention", func(t *testing.T) {
		tx, err := d.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `DELETE FROM control.service_certificate_requests WHERE issuance_id=$1`, issue.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `DELETE FROM control.acme_orders WHERE id=$1`, issue.ID); err != nil {
			t.Fatal(err)
		}
		checkpoints, err := controlstatedb.New(tx).ListPublisherCertificateCheckpoints(t.Context(), a.member.PublisherIdentityID)
		if err != nil || len(checkpoints) != 1 {
			t.Fatal("order cleanup erased durable plan checkpoint", err)
		}
	})
	independent, err := d.GetEnvironmentPublisherAssignments(t.Context(), b.lease.AccessToken, now)
	if err != nil || len(independent.CertificateStatePlans) != 0 {
		t.Fatal("another replica inherited the certificate-state requirement", err)
	}
	retry, err := d.CreateServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token, directory, "csr", run.RunNumber, csr, now)
	if err != nil || retry.ID != issue.ID {
		t.Fatal("issuance response recovery changed the order", retry, err)
	}
	t.Run("pending-issuance-after-restart", func(t *testing.T) {
		original := run.RunID
		if err = d.CloseServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now); err != nil {
			t.Fatal(err)
		}
		_, replacement := start(a, "orders")
		readySlots(replacement)
		recovered, err := d.CreateServiceCertificateIssuance(t.Context(), replacement.ServiceID, replacement.RunID, replacement.Token, directory, "pending-recovery", replacement.RunNumber, csr, now)
		if err != nil || recovered.ID != issue.ID || recovered.ServiceRunID != original || recovered.PublisherIdentityID != a.member.PublisherIdentityID || recovered.NewOrder {
			t.Fatal("replacement created another order or changed its provenance", recovered.ID, err)
		}
		if _, err = d.GetServiceCertificateIssuance(t.Context(), replacement.ServiceID, replacement.RunID, replacement.Token, issue.ID, now); err != nil {
			t.Fatal("replacement could not poll its original CSR", err)
		}
		if _, err = d.GetServiceCertificateIssuance(t.Context(), other.ServiceID, other.RunID, other.Token, issue.ID, now); !errors.Is(err, ErrCertificateIssuanceNotFound) {
			t.Fatal("another replica could poll this issuance", err)
		}
		shared, err := d.CreateServiceCertificateIssuance(t.Context(), sibling.ServiceID, sibling.RunID, sibling.Token, directory, "sibling-recovery", sibling.RunNumber, csr, now)
		if err != nil || shared.ID != issue.ID || shared.NewOrder {
			t.Fatal("sibling service lost the shared pending key", shared.ID, err)
		}
		changedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		changedCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: plan.Identifiers}, changedKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.CreateServiceCertificateIssuance(t.Context(), replacement.ServiceID, replacement.RunID, replacement.Token, directory, "pending-recovery", replacement.RunNumber, changedCSR, now); !errors.Is(err, ErrCertificateIssuanceIdempotency) {
			t.Fatal("recovered request key changed its CSR", err)
		}
		run = replacement
	})
	wide, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"*.tunnels.example.test"}}, key)
	if _, err = d.CreateServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token, directory, "wide", run.RunNumber, wide, now); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatal("publisher expanded its certificate authority", err)
	}
	work, found, err := d.ClaimACMEOrderWork(t.Context(), "managed-cert-test", now, time.Minute)
	if err != nil || !found || work.ID != issue.ID || work.Subject.ID != run.ServiceID || work.Subject.Kind != CertificateSubjectService {
		t.Fatal("shared ACME worker did not claim the private subject", work, found, err)
	}
	expires := now.Add(time.Hour)
	work.State = "authorizing"
	work.Authorizations = []ACMEAuthorizationWork{{Identifier: plan.Identifiers[0], AuthorizationURL: "https://acme.example.test/authz/1", ChallengeType: "dns-01", ChallengeURL: "https://acme.example.test/challenge/1", ChallengeToken: "challenge", ChallengeDigest: sha256.Sum256([]byte("challenge")), State: "presenting", AvailableAt: now, ExpiresAt: &expires}}
	work, err = d.SaveACMEOrderWork(t.Context(), work, now)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := d.GetDNSChallengeContextForSubject(t.Context(), work.Subject, work.Authorizations[0].ID)
	if err != nil || challenge.ServiceID != run.ServiceID || challenge.PublicURLID != "" || challenge.Identifier != plan.Identifiers[0] {
		t.Fatal("DNS-01 lost private namespace authority", challenge, err)
	}
	assertDNSChallengeSubjectBinding(t, d, work.Subject, challenge)
	work, found, err = d.ClaimACMEOrderWork(t.Context(), "managed-cert-test", now, time.Minute)
	if err != nil || !found {
		t.Fatal(err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	ca, _ = x509.ParseCertificate(caDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: plan.Identifiers, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	work.CertificatePEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	renew := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
	work.State, work.NotBefore, work.NotAfter, work.RenewAt = "waiting_for_install", &leaf.NotBefore, &leaf.NotAfter, &renew
	work.Authorizations[0].State = "complete"
	work.Authorizations[0].CleanupCompletedAt = &now
	if _, err = d.SaveACMEOrderWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	if err = d.MarkServiceCertificateInstalled(t.Context(), run.ServiceID, run.RunID, run.Token, issue.ID, run.RunNumber, leaf.NotAfter, now); err != nil {
		t.Fatal("publisher could not install its own certificate", err)
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("certified run did not become ready", state, err)
	}
	if err = d.MarkServiceCertificateInstalled(t.Context(), sibling.ServiceID, sibling.RunID, sibling.Token, issue.ID, sibling.RunNumber, leaf.NotAfter, now); err != nil {
		t.Fatal("same publisher could not reuse its namespace cache", err)
	}
	if err = d.MarkServiceCertificateInstalled(t.Context(), other.ServiceID, other.RunID, other.Token, issue.ID, other.RunNumber, leaf.NotAfter, now); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatal("a different replica adopted the certificate", err)
	}
	var publicRows int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&publicRows); err != nil || publicRows != 0 {
		t.Fatal("private certificate work created public URLs", publicRows, err)
	}
	t.Run("cached-install-after-restart", func(t *testing.T) {
		if err = d.CloseServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now); err != nil {
			t.Fatal(err)
		}
		_, replacement := start(a, "orders")
		readySlots(replacement)
		for range 2 {
			if err = d.MarkServiceCertificateInstalled(t.Context(), replacement.ServiceID, replacement.RunID, replacement.Token, issue.ID, replacement.RunNumber, leaf.NotAfter, now); err != nil {
				t.Fatal("replacement could not acknowledge the same cached certificate", err)
			}
		}
		if state, err := d.HeartbeatServiceRun(t.Context(), replacement.ServiceID, replacement.RunID, replacement.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
			t.Fatal("cached replacement did not become ready", state, err)
		}
		var events int
		if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1 AND event_type='certificate.install'`, replacement.ServiceID).Scan(&events); err != nil || events != 2 {
			t.Fatal("install audit did not distinguish runs and deduplicate retries", events, err)
		}
		run = replacement
	})
	t.Run("direct-admission", func(t *testing.T) {
		testDirectManagedAdmission(t, d, r, applied, run, now)
	})
	t.Run("namespace-retirement", func(t *testing.T) {
		uncertain, err := d.CreateServiceCertificateIssuance(t.Context(), other.ServiceID, other.RunID, other.Token, directory, "uncertain-finalize", other.RunNumber, csr, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.acme_orders SET finalization_possible=true WHERE id=$1`, uncertain.ID); err != nil {
			t.Fatal(err)
		}
		testServiceNamespaceCertificateRetirement(t, d, r, applied.ID, now, uncertain.ID)
	})
}

func testServiceNamespaceCertificateRetirement(t *testing.T, d *Database, r environmentPublisherTestProject, environment string, now time.Time, uncertain string) {
	t.Helper()
	current, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, environment, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	var oldGroup, namespace, namespaceLabel string
	if err := d.pool.QueryRow(t.Context(), `SELECT assignment.id,assignment.namespace,assignment.name FROM control.environments environment JOIN control.project_publisher_groups assignment ON assignment.id=environment.group_id WHERE environment.id=$1`, current.ID).Scan(&oldGroup, &namespace, &namespaceLabel); err != nil {
		t.Fatal(err)
	}
	if err := d.RetireEnvironment(t.Context(), RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: current.ID, ExpectedRevision: current.MutationRevision, Now: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	// settle the DNS retirement receipts introduced by the direct-exposure test
	// before checking the independent certificate quarantine deadline.
	for range len(current.Services) {
		work, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "retirement", now.Add(2*time.Second), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			break
		}
		if work.State != PublicURLDNSRemoving {
			t.Fatal("retired endpoint did not request DNS removal", work.State)
		}
		work.State, work.AvailableAt = PublicURLDNSRemoved, time.Time{}
		if _, err := d.SaveServiceEndpointDNSWork(t.Context(), work, now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	replacement := r
	replacement.ProjectKey, replacement.SourceFingerprint = "replacement", fmt.Sprintf("%064x", 5)
	services := map[string]ServiceDefinitionService{}
	for _, service := range current.Services {
		services[service.Service] = ServiceDefinitionService{Protocol: service.Protocol}
	}
	_, err = d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: replacement.ProjectKey, SourceFingerprint: replacement.SourceFingerprint, ProjectLabel: "storefront", ActorID: r.ActorID, Definition: ServiceDefinition{Services: services}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = retainedNamespaceClaim(t, d, replacement, namespaceLabel, current.DomainID, now.Add(8*24*time.Hour)); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("quarantine elapsed before the outstanding certificate expired", err)
	}
	if _, err = retainedNamespaceClaim(t, d, replacement, namespaceLabel, current.DomainID, now.Add(31*24*time.Hour)); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("uncertain finalization allowed namespace reuse", err)
	}
	// the provider has now resolved uncertain work and established its actual
	// lifetime. canceled work cannot erase the possible certificate's authority.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.acme_orders SET state='canceled',not_after=$2,not_before=$3 WHERE id=$1`, uncertain, now.Add(45*24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err = retainedNamespaceClaim(t, d, replacement, namespaceLabel, current.DomainID, now.Add(31*24*time.Hour)); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("late certificate lifetime ignored", err)
	}
	reused, err := retainedNamespaceClaim(t, d, replacement, namespaceLabel, current.DomainID, now.Add(46*24*time.Hour))
	if err != nil {
		t.Fatal("retired certificate authority burned the namespace forever", err)
	}
	var reusedNamespace string
	if err := d.pool.QueryRow(t.Context(), `SELECT namespace FROM control.project_publisher_groups WHERE id=$1`, reused).Scan(&reusedNamespace); err != nil {
		t.Fatal(err)
	}
	if reused == oldGroup || reusedNamespace != namespace {
		t.Fatal("retired certificate authority burned the namespace forever", reused, err)
	}
}
