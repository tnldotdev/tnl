package state

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationIngressVisitorPolicyBindsExactRunProjectionAndProcess(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	d, now := f.database, f.now
	register := func(id string, lifetime time.Duration) IngressLease {
		t.Helper()
		lease, err := d.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: id, IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
			ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
		}, now, lifetime)
		if err != nil {
			t.Fatal(err)
		}
		return lease
	}
	owner := register("policy-ingress", time.Minute)
	second := register("second-policy-ingress", 3*time.Second)
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	read := func(lease IngressLeaseIdentity, at time.Time) (IngressServiceRun, error) {
		return readIngressServiceRun(t.Context(), d, lease, f.service.ID, f.run.RunID, at)
	}
	routing, err := read(owner.IngressLeaseIdentity, now)
	if err != nil || routing.ServiceID != f.service.ID || routing.RunID != f.run.RunID ||
		routing.RunNumber != f.run.RunNumber || !routing.ValidUntil.Equal(now.Add(visitortoken.PolicyLifetime)) {
		t.Fatal("ingress routing lost its exact run or observation deadline", routing, err)
	}
	auth := ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		RunID: f.run.RunID, Number: f.run.RunNumber, Token: credentials.ServiceRunToken(f.run.Token)}
	policy, err := d.ReadPublisherVisitorPolicy(f.ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now)
	if err != nil || policy.Policy.Resource.Id != f.service.ID || policy.Policy.Resource.Kind != "service" ||
		policy.Policy.Hostname != f.service.Endpoint.Hostname {
		t.Fatal("publisher policy lost its exact service/run binding", err)
	}
	bounded, err := read(second.IngressLeaseIdentity, now)
	if err != nil || !bounded.ValidUntil.Equal(second.LeaseExpiresAt) {
		t.Fatal("routing outlived its ingress process lease", bounded, err)
	}
	authority, err := tunnelv1.ReadVisitorSourceAuthority(routing.SourceAuthority)
	if err != nil || authority.IngressID != owner.IngressID || authority.IngressRunID != owner.IngressRunID ||
		authority.IngressLeaseRevision != owner.IngressLeaseRevision {
		t.Fatal("source delegation lost its exact ingress process", err)
	}
	otherAuthority, err := tunnelv1.ReadVisitorSourceAuthority(bounded.SourceAuthority)
	if err != nil || otherAuthority.IngressID != second.IngressID || otherAuthority.IngressRunID != second.IngressRunID ||
		otherAuthority.IngressLeaseRevision != second.IngressLeaseRevision || bytes.Equal(otherAuthority.MAC, authority.MAC) {
		t.Fatal("sibling ingress reused another process's delegation", err)
	}
	binding := tunnelv1.VisitorSourceBinding{ServiceID: f.service.ID, ServiceRunID: f.run.RunID, RunNumber: uint64(f.run.RunNumber),
		VisitorConnectionID: visitor, Source: netip.MustParseAddrPort("192.0.2.1:3000"), Destination: netip.MustParseAddrPort("198.51.100.1:443")}
	proof, err := visitortoken.SignVisitorSource([32]byte(routing.SourceKey), authority, 1, binding, now)
	if err != nil || visitortoken.VerifyVisitorSource(f.run.VisitorSourceKey, proof, binding, authority.VisitorPolicyRevision, now) != nil {
		t.Fatal("publisher rejected its exact delegated socket facts", err)
	}
	if _, err := visitortoken.SignVisitorSource([32]byte(bounded.SourceKey), otherAuthority, 1, binding, second.LeaseExpiresAt); err == nil {
		t.Fatal("expired ingress delegation signed another visitor")
	}
	for _, field := range []string{"service", "run", "number", "visitor", "process", "source", "port"} {
		t.Run(field, func(t *testing.T) {
			crossed, evidence := binding, proof
			switch field {
			case "service":
				crossed.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix)
			case "run":
				crossed.ServiceRunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix)
			case "number":
				crossed.RunNumber++
			case "visitor":
				crossed.VisitorConnectionID = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			case "process":
				evidence.Authority = otherAuthority
			case "source":
				crossed.Source = netip.MustParseAddrPort("192.0.2.2:3000")
			case "port":
				crossed.Destination = netip.MustParseAddrPort("198.51.100.1:25443")
			}
			if err := visitortoken.VerifyVisitorSource(f.run.VisitorSourceKey, evidence, crossed, authority.VisitorPolicyRevision, now); err == nil {
				t.Fatal("source evidence crossed its exact run/process/socket tuple")
			}
		})
	}
	if _, err := d.ReadPublisherVisitorPolicy(f.ctx, auth.Subject, auth.RunID, auth.Number, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0, now); err == nil {
		t.Fatal("wrong run token prepared publisher policy")
	}
	stale := owner.IngressLeaseIdentity
	stale.IngressLeaseRevision++
	if _, err := read(stale, now); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("an older ingress lease read routing authority", err)
	}
	if err := visitortoken.VerifyVisitorSource(f.run.VisitorSourceKey, proof, binding, authority.VisitorPolicyRevision, routing.ValidUntil); err == nil {
		t.Fatal("source evidence survived its fixed routing deadline")
	}
	if err := d.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadPublisherVisitorPolicy(f.ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now); err == nil {
		t.Fatal("a closed run prepared publisher policy")
	}
	if _, err := read(owner.IngressLeaseIdentity, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("a closed run remained in ingress routing", err)
	}
	var rows int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_service_visitors WHERE service_id=$1`, f.service.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("HTTP routing wrote visitor coordination rows", rows, err)
	}
}

func TestIntegrationIngressVisitorPolicyDoesNotWaitForRenewalRow(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	owner, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "policy-row-lock", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback(t.Context())
	if _, err := held.Exec(t.Context(), `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE`, owner.IngressID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	if _, err := f.database.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now); err != nil {
		t.Fatal("publisher policy preparation waited behind ingress renewal", err)
	}
	if _, err := f.database.ReadIngressServices(ctx, owner.IngressLeaseIdentity, f.now); err != nil {
		t.Fatal("ingress routing preparation waited behind ingress renewal", err)
	}
}
