package state

import (
	"crypto/x509"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationVisitorPolicySeparatesDirectReachabilityAndClientTrust(t *testing.T) {
	f, run, owners := capacityFixture(t, 1)
	d, ctx := f.database, t.Context()
	prepareVisitorTokenKeys(t, d, f.now)
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}
	before, err := d.ReadIngressVisitorPolicy(ctx, owners[0], scope, 0, f.now)
	if err != nil || !before.Policy.Enabled || before.Policy.Public || before.Policy.ClientIssuerPem != nil {
		t.Fatal("connector-only service gained direct reachability or unprepared certificate trust", err)
	}
	issuer, err := d.ServiceClientIssuer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET public=true WHERE id=$1`, run.ServiceID); err != nil {
		t.Fatal(err)
	}
	current, err := d.ReadIngressVisitorPolicy(ctx, owners[0], scope, before.Policy.VisitorPolicyRevision, f.now)
	if err != nil || !current.Policy.Public || current.Policy.VisitorPolicyRevision <= before.Policy.VisitorPolicyRevision || current.Policy.ClientIssuerPem == nil {
		t.Fatal("direct endpoint mutation did not publish its independent policy facts", err)
	}
	decoded, err := visitorlease.Decode(current)
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	if !want.AppendCertsFromPEM(issuer.CertificatePEM()) || decoded.ClientAuthorities == nil || !decoded.ClientAuthorities.Equal(want) {
		t.Fatal("prepared client trust differs from control's durable issuer")
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET public=false WHERE id=$1`, run.ServiceID); err != nil {
		t.Fatal(err)
	}
	closed, err := d.ReadIngressVisitorPolicy(ctx, owners[0], scope, current.Policy.VisitorPolicyRevision, f.now)
	if err != nil || closed.Policy.Public || !closed.Policy.Enabled || closed.Policy.VisitorPolicyRevision <= current.Policy.VisitorPolicyRevision {
		t.Fatal("closing direct reachability also changed native permission availability", err)
	}
}
