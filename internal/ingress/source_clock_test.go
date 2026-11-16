package ingress

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestServiceRoutingSourceProofWithUnequalConfirmationLatency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		ingressStarted := time.Now()
		policy, err := visitorlease.New(visitorscope.Scope{Kind: visitorscope.Service, ID: snapshot.Runs[0].ServiceId}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		// all participants share this clock. ingress starts its request earlier,
		// but both authenticated replies report the same control observation.
		time.Sleep(190 * time.Millisecond)
		publisherRequest := policy.Begin()
		time.Sleep(10 * time.Millisecond)
		snapshot.ObservedAt = time.Now()
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(ingressStarted, lease, snapshot); err != nil {
			t.Fatal(err)
		}
		update := visitorlease.Update{View: visitortoken.View{
			Scope:                 visitorscope.Scope{Kind: visitorscope.Service, ID: snapshot.Runs[0].ServiceId},
			VisitorPolicyRevision: 1, ObservedAt: snapshot.ObservedAt, ValidUntil: snapshot.ValidUntil,
		}, KeyRevision: 1, Enabled: true, Snapshot: true}
		if err := policy.Apply(publisherRequest, update); err != nil {
			t.Fatal(err)
		}
		routes := routing.lookup("route.example", 443, lease, time.Now())
		if len(routes) != 1 {
			t.Fatal("current ingress confirmation did not install its service")
		}
		route := routes[0]
		binding := tunnelv1.VisitorSourceBinding{
			ServiceID: route.run.ServiceId, ServiceRunID: route.run.ServiceRunId, RunNumber: uint64(route.run.RunNumber),
			VisitorConnectionID: publicServiceTestID(t, "vc_"),
			Source:              netip.MustParseAddrPort("192.0.2.1:3000"), Destination: netip.MustParseAddrPort("203.0.113.1:443"),
		}
		proof, err := visitortoken.SignVisitorSource(route.sourceKey, route.source, route.sequence.next.Add(1), binding, route.authorityTime(time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
		view, enabled, _ := policy.Current()
		publisherNow := view.AuthorityTime(time.Now())
		ahead := time.UnixMicro(proof.ObservedAt).Sub(publisherNow)
		if !enabled || !route.until.After(time.Now()) || !view.ValidUntil.After(time.Now()) ||
			!view.ControlTime.Equal(route.observedAt) || ahead != 185*time.Millisecond {
			t.Fatal("fixture did not retain two current confirmations with unequal request latency", ahead)
		}
		if err := visitortoken.VerifyVisitorSource([32]byte{1}, proof, binding, view.VisitorPolicyRevision, publisherNow); err != nil {
			t.Fatal("current source proof rejected across independent confirmation clocks", ahead, err)
		}
	})
}
