package state

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationServiceEndpointChangesRetainConnectorAuthority(t *testing.T) {
	f := newConnectorPairFixture(t)
	d, ctx, now := f.d, f.visitor, f.now
	pair := f.create(t)
	before := connectorPairSavedAuthority(t, d, pair.ID)
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.run.ServiceID}
	permission, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, f.request.Source, now)
	if err != nil || permission.Permission.Port != 0 {
		t.Fatal("connector permission used an ingress port", err)
	}
	policy, err := d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.GetService(ctx, f.run.ServiceID, f.request.Subject.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	change := func(public bool) ServiceRecord {
		t.Helper()
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, tx)
		if err := d.setLocalServiceExposure(ctx, tx, service.ID, public, now); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		current, err := d.GetService(ctx, service.ID, f.request.Subject.IdentityID)
		if err != nil || current.TrustRevision != service.TrustRevision || current.Endpoint.Hostname != service.Endpoint.Hostname || current.Endpoint.Public != public {
			t.Fatal("exposure changed connector identity", current, err)
		}
		return current
	}
	assertRetained := func() {
		t.Helper()
		if !bytes.Equal(before, connectorPairSavedAuthority(t, d, pair.ID)) {
			t.Fatal("endpoint mutation changed a connector owner, run, slot, or publisher grant")
		}
		current, err := d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
		if err != nil || current.Policy.Port != 0 || current.Policy.MetadataRevision != policy.Policy.MetadataRevision ||
			current.Policy.VisitorPolicyRevision != policy.Policy.VisitorPolicyRevision {
			t.Fatal("endpoint mutation invalidated prepared visitor permission", err)
		}
	}
	first := change(true)
	if first.Endpoint.Port != 25443 || first.EndpointRevision <= service.EndpointRevision {
		t.Fatal("first exposure did not allocate a separately revisioned endpoint", first)
	}
	assertRetained()
	change(false)
	assertRetained()
	released, err := d.ReleaseServiceEndpoint(ctx, service.ID, f.request.Subject.IdentityID, first.EndpointRevision, first.Endpoint.Port, now)
	if err != nil || released.Endpoint.Port != 0 || released.TrustRevision != service.TrustRevision || released.EndpointRevision != first.EndpointRevision+1 {
		t.Fatal("release changed connector trust or retained the old public binding", released, err)
	}
	assertRetained()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	second := change(true)
	if second.Endpoint.Port != 25444 {
		t.Fatal("replacement reused a quarantined reservation", second.Endpoint)
	}
	assertRetained()
	lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "endpoint-lifetime", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{25443, 25444}, ProtocolVersion: 1, ConnectionCapacity: 8}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	admit := func(port int) (PublicServiceVisitorAdmission, error) {
		return d.AdmitPublicServiceVisitor(ctx, lease.IngressLeaseIdentity, PrimaryIngressPoolID,
			mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), "", port, netip.MustParseAddr("192.0.2.10"), now)
	}
	if _, err := admit(first.Endpoint.Port); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("stale public destination retained authority", err)
	}
	if admitted, err := admit(second.Endpoint.Port); err != nil || admitted.RunID != f.run.RunID {
		t.Fatal("replacement endpoint required a new publisher run", admitted, err)
	}
	renewal := f.request
	renewal.Action, renewal.PreviousPairID, renewal.PreviousGeneration = "renew", pair.ID, pair.DeliveryGeneration
	renewal.RequestedAt = now.Add(time.Second)
	f.sign(t, &renewal)
	renewed, err := d.RenewConnectorPeerPair(ctx, testVisitorIssuer, renewal, renewal.RequestedAt)
	if err != nil || renewed.ID != pair.ID || renewed.SessionKey != pair.SessionKey || renewed.TrustRevision != pair.TrustRevision ||
		renewed.VisitorPermission.Permission.Port != 0 || renewed.Metadata.Endpoint.Port != second.Endpoint.Port {
		t.Fatal("connector renewal adopted ingress authority or replaced its retained session", err)
	}
}
