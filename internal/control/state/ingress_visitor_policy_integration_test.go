package state

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
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
	source := netip.MustParseAddr("192.0.2.1")
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	admit := func(lease IngressLeaseIdentity, id string, ip netip.Addr) (PublicServiceVisitorAdmission, error) {
		return d.AdmitPublicServiceVisitor(t.Context(), lease, PrimaryIngressPoolID, id,
			f.service.Endpoint.Hostname, 443, ip, now)
	}
	admission, err := admit(owner.IngressLeaseIdentity, visitor, source)
	if err != nil || admission.ServiceID != f.service.ID || admission.RunID != f.run.RunID ||
		admission.RunNumber != f.run.RunNumber || !admission.ExpiresAt.Equal(now.Add(10*time.Second)) {
		t.Fatal("ingress admission lost its exact run or setup deadline", admission, err)
	}
	auth := ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		RunID: f.run.RunID, Number: f.run.RunNumber, Token: credentials.ServiceRunToken(f.run.Token)}
	policy, err := d.ReadPublisherVisitorPolicy(f.ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now)
	if err != nil || policy.Policy.Resource.Id != f.service.ID || policy.Policy.Resource.Kind != "service" ||
		policy.Policy.Hostname != f.service.Endpoint.Hostname {
		t.Fatal("publisher policy lost its exact service/run binding", err)
	}
	bounded, err := admit(second.IngressLeaseIdentity, mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), source)
	if err != nil || !bounded.ExpiresAt.Equal(second.LeaseExpiresAt) {
		t.Fatal("admission outlived its ingress process lease", bounded, err)
	}
	// source authority is now the stored admission tuple, not an ingress policy
	// projection or a delegated signing key.
	if _, err := admit(second.IngressLeaseIdentity, visitor, source); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another ingress process reused the visitor reservation", err)
	}
	if _, err := admit(owner.IngressLeaseIdentity, visitor, netip.MustParseAddr("192.0.2.2")); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("a changed source reused the visitor reservation", err)
	}
	status, err := d.PublicServiceVisitorStatus(t.Context(), second.IngressLeaseIdentity, visitor, now)
	if err != nil || status.State != PublicServiceVisitorDenied {
		t.Fatal("another ingress process observed the visitor's permission", status, err)
	}
	for _, field := range []string{"service", "run", "number", "token", "source", "port"} {
		t.Run(field, func(t *testing.T) {
			crossed, ip, port := auth, source, 443
			switch field {
			case "service":
				crossed.Subject.ID = mustOpaqueID(t, opaqueid.ServicePrefix)
			case "run":
				crossed.RunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix)
			case "number":
				crossed.Number++
			case "token":
				crossed.Token = credentials.ServiceRunToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			case "source":
				ip = netip.MustParseAddr("192.0.2.2")
			case "port":
				port = 25443
			}
			if _, err := d.AuthorizeServiceHTTPVisitor(f.ctx, crossed, visitor, ip, port, now); err == nil {
				t.Fatal("publisher authorization crossed its admission tuple")
			}
		})
	}
	stale := owner.IngressLeaseIdentity
	stale.IngressLeaseRevision++
	if _, err := admit(stale, mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), source); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("an older ingress lease admitted a visitor", err)
	}
	if _, err := d.AuthorizeServiceHTTPVisitor(f.ctx, auth, visitor, source, 443, now); err != nil {
		t.Fatal("the exact publisher/admission tuple was rejected", err)
	}
	if err := d.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadPublisherVisitorPolicy(f.ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now); err == nil {
		t.Fatal("a closed run prepared publisher policy")
	}
	if _, err := admit(owner.IngressLeaseIdentity, mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), source); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("a closed run admitted a visitor", err)
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
}
