package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationVisitorCredentialCoverageKeepsUnrelatedRevisionsAndRevokesExactSources(t *testing.T) {
	f, run, owners := capacityFixture(t, 8)
	d, now, ctx := f.database, f.now, t.Context()
	prepareVisitorTokenKeys(t, d, now)
	var identity string
	if err := d.pool.QueryRow(ctx, `SELECT created_by_identity_id FROM control.services WHERE id=$1`, run.ServiceID).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	parent := browserTestControlSession(t, d, identity, now)
	principal := WithControlPrincipal(ctx, ControlPrincipal{IdentityID: identity, SessionID: parent.SessionID})
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(principal, identity, public, now)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET public=true WHERE id=$1`, run.ServiceID); err != nil {
		t.Fatal(err)
	}
	issued, err := d.IssueVisitorClientCertificate(principal, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := d.IssueVisitorClientCertificate(principal, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, csr, now.Add(time.Second))
	if err != nil || retried.CertificatePEM != issued.CertificatePEM {
		t.Fatal("lost-response recovery changed the active certificate", err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(issued.IssuerPEM)) {
		t.Fatal("invalid certificate issuer")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: chains}
	token, err := visitortoken.CertificateToken(leaf)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.CreateVisitorGrantCredentials(principal, testVisitorIssuer, scope, "token", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	read := func() visitortoken.View {
		t.Helper()
		policy, err := d.ReadIngressVisitorPolicy(ctx, owners[0], scope, 0, now)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(policy)
		if err != nil {
			t.Fatal(err)
		}
		return update.View
	}
	before := read()
	if _, err := d.CreateVisitorGrantCredentials(principal, testVisitorIssuer, scope, "share", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	current := read()
	if current.VisitorPolicyRevision <= before.VisitorPolicyRevision {
		t.Fatal("fixture did not change the resource policy")
	}
	if _, err := visitortoken.VerifyCertificate(token, current, state, now); err != nil {
		t.Fatal("unrelated grant invalidated an exact current certificate", err)
	}
	if _, err := visitortoken.VerifyBearer(grant.Token, current, now); err != nil {
		t.Fatal("unrelated grant invalidated an exact current bearer", err)
	}
	allocation, err := d.AllocateStreamCapacity(ctx, capacityRequest(run, owners[0], "direct-audit", 2), now)
	if err != nil {
		t.Fatal(err)
	}
	// the publisher's authenticated policy report owns the installation ack;
	// this audit fixture starts with the already confirmed allocation fact.
	if _, err := d.pool.Exec(ctx, `UPDATE control.stream_capacity_allocations SET publisher_observed_at=$2 WHERE id=$1`, allocation.ID, now); err != nil {
		t.Fatal(err)
	}
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.Raw)
	observation := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: scope.ID, ServiceKind: "service", EventType: "connection.open", OccurredAt: now,
		RunID: run.RunID, RunNumber: run.RunNumber, StreamAllocationID: allocation.ID, VisitorConnectionID: visitor, SourceIP: "192.0.2.44", Outcome: "allowed",
		VisitorReference: tunnelv1.ServiceVisitorReference{Kind: "certificate", ID: hex.EncodeToString(digest[:])}}
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}
	if accepted, err := d.IngestIngressServiceObservations(ctx, owners[0], batch, now); err != nil || accepted.Accepted != 1 {
		t.Fatal("exact direct visitor audit was denied", err)
	}
	if duplicate, err := d.IngestIngressServiceObservations(ctx, owners[0], batch, now); err != nil || duplicate.Duplicates != 1 {
		t.Fatal("direct visitor audit retry was duplicated", err)
	}
	if _, err := d.IngestIngressServiceObservations(ctx, owners[1], batch, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal("another ingress attributed a direct visitor", err)
	}
	for _, change := range []func(*serviceaudit.Observation){
		func(o *serviceaudit.Observation) { o.VisitorReference.ID = strings.Repeat("0", 64) },
		func(o *serviceaudit.Observation) { o.StreamAllocationID = "salloc_0123456789ABCDEFGHIJKL" },
		func(o *serviceaudit.Observation) { o.RunID = "srun_0123456789ABCDEFGHIJKL" },
	} {
		bad := observation
		bad.EventID = serviceaudit.NewID()
		change(&bad)
		if _, err := d.IngestIngressServiceObservations(ctx, owners[0], serviceaudit.Batch{Events: []serviceaudit.Observation{bad}}, now); !errors.Is(err, ErrServiceAuditAccess) {
			t.Fatal("direct audit accepted a mismatched credential, allocation, or run", err)
		}
	}
	var team string
	if err := d.pool.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1`, scope.ID).Scan(&team); err != nil {
		t.Fatal(err)
	}
	page, err := d.ListServiceAudit(ctx, team, identity, ServiceAuditFilter{ServiceID: scope.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, event := range page.Events {
		if event.ID == observation.EventID {
			found = true
			if event.ActorIdentityID != identity || event.DeviceID != device.ID || event.SourceIP != observation.SourceIP || event.PublisherIdentityID == "" {
				t.Fatal("direct audit changed authenticated attribution", event)
			}
		}
	}
	if !found {
		t.Fatal("direct visitor audit did not enter the saved service history")
	}
	grantVisit := observation
	grantVisit.EventID = serviceaudit.NewID()
	grantVisit.VisitorConnectionID = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	grantVisit.VisitorReference = tunnelv1.ServiceVisitorReference{Kind: "grant", ID: grant.GrantID}
	if accepted, err := d.IngestIngressServiceObservations(ctx, owners[0], serviceaudit.Batch{Events: []serviceaudit.Observation{grantVisit}}, now); err != nil || accepted.Accepted != 1 {
		t.Fatal("signed bearer grant lost direct audit scope", err)
	}
	page, err = d.ListServiceAudit(ctx, team, identity, ServiceAuditFilter{ServiceID: scope.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	grantFound := false
	for _, event := range page.Events {
		if event.ID == grantVisit.EventID {
			if event.ActorIdentityID != "" || event.DeviceID != "" || event.PublisherIdentityID == "" {
				t.Fatal("bearer grant issuer was mistaken for the visitor or feedback author", event)
			}
			grantFound = true
		}
	}
	if !grantFound {
		t.Fatal("signed bearer grant observation was not stored")
	}
	if err := d.RevokeVisitorDevice(principal, identity, device.ID, now); err != nil {
		t.Fatal(err)
	}
	current = read()
	if _, err := visitortoken.VerifyCertificate(token, current, state, now); err == nil {
		t.Fatal("revoked device retained certificate coverage")
	}
	if _, err := visitortoken.VerifyBearer(grant.Token, current, now); err != nil {
		t.Fatal("device revocation changed an independent explicit grant", err)
	}
	if err := d.RevokeServiceHTTPGrant(principal, scope.ID, identity, grant.GrantID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyBearer(grant.Token, read(), now); err == nil {
		t.Fatal("revoked grant retained background coverage")
	}
	// attribution is historical, independent of current revocation or CSR state.
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	event := serviceaudit.Event{}
	observation = serviceaudit.Observation{ServiceID: scope.ID, OccurredAt: now, VisitorReference: tunnelv1.ServiceVisitorReference{Kind: "certificate", ID: hex.EncodeToString(digest[:])}}
	if err := resolveDirectAuditVisitor(ctx, tx, observation, &event); err != nil || event.ActorIdentityID != identity || event.DeviceID != device.ID {
		t.Fatal("revocation erased immutable certificate attribution", err)
	}
	observation.ServiceID = "svc_aaaaaaaaaaaaaaaaaaaaaa"
	if err := resolveDirectAuditVisitor(ctx, tx, observation, &event); err == nil {
		t.Fatal("certificate attribution crossed service scopes")
	}
}
