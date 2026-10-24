package ingress

import (
	"net/netip"
	"testing"
	"time"

	ingressbackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/ingress/clienthello"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
)

type auditSinkFunc func(serviceaudit.Observation) bool

func (f auditSinkFunc) Observe(o serviceaudit.Observation) bool { return f(o) }

func TestNetworkPolicyDenialAuditedAtIngress(t *testing.T) {
	var events []serviceaudit.Observation
	route := PublicURL{ID: "url_0123456789ABCDEFGHIJKL", PublishRunID: "pr_0123456789ABCDEFGHIJKL", PublishRunNumber: 1, Backends: []ingressbackend.Backend{&singleBackend{}}}
	s := &Server{config: Config{Lookup: func(string) (PublicURL, LookupReason) { return route, LookupCurrent }, AuditSink: auditSinkFunc(func(o serviceaudit.Observation) bool { events = append(events, o); return true })}}
	if err := s.forward(nil, netip.MustParseAddrPort("192.0.2.8:1234"), netip.MustParseAddrPort("203.0.113.1:443"), clienthello.ClientHello{ServerName: "private.example"}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Validate() != nil || events[0].Outcome != "denied" || events[0].Reason != "ip_policy" || events[0].SourceIP != "192.0.2.8" {
		t.Fatalf("network rejection lost: %+v", events)
	}
}

func TestPrivateVisitorAuditCorrelatesAdmissionAndRevocationClose(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	events := make(chan serviceaudit.Observation, 2)
	connector.config.AuditSink = auditSinkFunc(func(o serviceaudit.Observation) bool { events <- o; return true })
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	var opened serviceaudit.Observation
	select {
	case opened = <-events:
	case <-time.After(time.Second):
		t.Fatal("private admission did not emit")
	}
	if opened.Validate() != nil || opened.EventType != "connection.open" || opened.Outcome != "allowed" || opened.RunID != control.run || opened.ConnectorSessionID != control.session {
		t.Fatalf("private admission scope: %+v", opened)
	}
	updateNativePolicy(t, connector, control, func(update *visitorlease.Update) { update.Enabled = false; update.View.VisitorPolicyRevision++ })
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	_, _ = stream.Read(one[:])
	select {
	case closed := <-events:
		if closed.Validate() != nil || closed.EventType != "connection.close" || closed.VisitorConnectionID != opened.VisitorConnectionID || closed.EventID == opened.EventID || closed.Reason != "authorization" {
			t.Fatalf("uncorrelated private close: %+v", closed)
		}
	case <-time.After(time.Second):
		t.Fatal("private revocation did not emit close")
	}
}

func TestKnownUnavailableServiceIsAuditedWithoutInventingARun(t *testing.T) {
	var events []serviceaudit.Observation
	s := &Server{config: Config{Lookup: func(string) (PublicURL, LookupReason) {
		return PublicURL{ID: "url_0123456789ABCDEFGHIJKL"}, LookupNoBackends
	}, AuditSink: auditSinkFunc(func(o serviceaudit.Observation) bool { events = append(events, o); return true })}}
	if err := s.forward(nil, netip.MustParseAddrPort("192.0.2.8:1234"), netip.MustParseAddrPort("203.0.113.1:443"), clienthello.ClientHello{ServerName: "private.example"}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Validate() != nil || events[0].RunID != "" || events[0].RunNumber != 0 || events[0].Reason != "unavailable" {
		t.Fatalf("lost service-level denial: %+v", events)
	}
}
