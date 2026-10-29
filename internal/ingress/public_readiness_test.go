package ingress

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type readinessControlClient struct {
	ControlClient
	renew func(ingressv1.IngressRenewal) ingressv1.IngressLease
}

func (c readinessControlClient) RenewIngress(_ context.Context, _ string, body ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	return c.renew(body), nil
}

type readinessVisitorControl struct{ calls atomic.Int32 }

func (c *readinessVisitorControl) ReadIngressVisitorPolicy(context.Context, string, ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	c.calls.Add(1)
	return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
}
func (c *readinessVisitorControl) AllocateStreamCapacity(context.Context, string, ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error) {
	c.calls.Add(1)
	return controlv1.StreamCapacityAllocation{}, errors.New("control unavailable")
}
func (c *readinessVisitorControl) RetireStreamCapacity(context.Context, string, string, ingressv1.StreamCapacityRetirement) error {
	c.calls.Add(1)
	return errors.New("control unavailable")
}

func preparedReadinessController(t *testing.T, f *admissionTransportFixture) *Controller {
	t.Helper()
	lease := testIngressLease(time.Now())
	lease.IngressId, lease.IngressRunId = "fixture-ingress", "fixture-process"
	f.prepared.capacity.owner = lease
	readyAt := time.Now()
	f.entry.PublishRunReadyAt = &readyAt
	return &Controller{routingTable: &RoutingTable{initialized: true, revision: 7, routes: map[string]routingTableEntry{"ready": {entry: f.entry}}},
		lease: lease, registration: ingressv1.IngressRegistration{IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, ProtocolVersion: lease.ProtocolVersion, ConnectionCapacity: lease.ConnectionCapacity},
		routingTableCurrent: true, visitorControl: &readinessVisitorControl{}, now: time.Now, renewalInterval: time.Millisecond,
		load: func() int64 { return 0 }, publicVisitors: map[string]*publicVisitorRun{f.entry.PublishRunId: f.prepared}}
}

func renewReadinessController(t *testing.T, c *Controller, wantRevision int64) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c.client = readinessControlClient{renew: func(body ingressv1.IngressRenewal) ingressv1.IngressLease {
		if body.RoutingTableRevision != wantRevision {
			t.Errorf("routing installation acknowledgement=%d want=%d", body.RoutingTableRevision, wantRevision)
		}
		lease := c.Lease()
		lease.RoutingTableRevision = body.RoutingTableRevision
		cancel()
		return lease
	}}
	if err := c.renewLoop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPublicReadinessIsolationAndFirstAuthorizedRequest(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	var application atomic.Int32
	startSeparatedPublisher(t, f, publisher.PublicURLServerConfig{Certificate: testCertificate(t, "route.example"), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		application.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})}, func(update *visitorlease.Update) { update.Anonymous = false })
	c := preparedReadinessController(t, f)
	// a joining receiver whose snapshot contains final-ready state cannot
	// latch health or accept the first request before preparing that run.
	c.publicVisitors = make(map[string]*publicVisitorRun)
	renewReadinessController(t, c, 7)
	c.markPublicRoutingPrepared()
	if c.Ready(time.Now()) {
		t.Fatal("joining receiver became healthy with an unprepared final-ready snapshot")
	}
	if _, reason := c.LookupPublicURLs(f.entry.CanonicalHostname, f.forwarder, time.Now()); reason != LookupIngressUnavailable {
		t.Fatal("joining receiver accepted visitors before its preparation")
	}
	c.publicVisitors[f.entry.PublishRunId] = f.prepared
	f.prepared.capacity.ready = false
	if c.publicRoutingPrepared(7, time.Now()) {
		t.Fatal("joining ingress did not gate an already-ready URL on local setup")
	}
	f.prepared.capacity.ready = true
	if c.Ready(time.Now()) {
		t.Fatal("joining ingress became healthy before installed preparation was checked")
	}
	// preparation can finish between lease renewals; no control round trip is
	// needed to make the installed local snapshot healthy.
	c.markPublicRoutingPrepared()
	if !c.Ready(time.Now()) {
		t.Fatal("prepared ingress did not become healthy")
	}
	stalled := f.entry
	stalled.PublicUrlId, stalled.PublishRunId, stalled.CanonicalHostname = "url_"+strings.Repeat("D", 22), "pr_"+strings.Repeat("E", 22), "stalled.example"
	stalled.PublishRunReadyAt = nil
	c.routingTable.routes["stalled"] = routingTableEntry{entry: stalled}
	c.registration.IngressPoolId = "ingress-a"
	foreign := stalled
	foreignPool := "another-pool"
	foreign.IngressPoolId, foreign.PublishRunReadyAt = &foreignPool, f.entry.PublishRunReadyAt
	c.routingTable.routes["foreign"] = routingTableEntry{entry: foreign}
	c.routingTable.revision = 8
	if !c.publicRoutingPrepared(8, time.Now()) {
		t.Fatal("unprepared starting URL blocked health-aware joining for ready URL B")
	}
	renewReadinessController(t, c, 8)
	if !c.Ready(time.Now()) {
		t.Fatal("unprepared URL A removed an already-serving ingress from health")
	}
	if _, reason := c.LookupPublicURLs(stalled.CanonicalHostname, f.forwarder, time.Now()); reason != LookupNoBackends {
		t.Fatalf("unprepared URL A lookup=%s", reason)
	}
	observed := f.prepared.observationsFor(f.entry, c.Lease(), time.Now())
	if len(observed) != 1 {
		t.Fatal("installed URL B did not supply its own observation")
	}
	if application.Load() != 0 {
		t.Fatal("preparation contacted the application")
	}
	s, address := startIngress(t, Config{RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, LookupPool: func(host string) ([]PublicURL, LookupReason) {
		return c.LookupPublicURLs(host, f.forwarder, time.Now())
	}, OnError: func(err error) { t.Log(err) }})
	f.forwarder.SetPromotionHandler(s.PromotePendingAdmission)
	now := time.Now()
	token, err := visitortoken.Sign("https://control.example.test", "fixture", ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32))), visitortoken.Permission{
		Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: f.entry.PublicUrlId}, Hostname: f.entry.CanonicalHostname, Port: 443, VisitorPolicyRevision: 1,
		Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)}, ExpiresAt: now.Add(time.Minute),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(separatedVisitor(t, address, "203.0.113.1:40002", 443), &tls.Config{ServerName: "route.example", InsecureSkipVerify: true}) // local fixture certificate.
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(fixtureTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: route.example\r\nTnl-Visitor-Token: %s\r\nConnection: close\r\n\r\n", token.Reveal()); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("first authorized request failed (no retry): %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || application.Load() != 1 {
		t.Fatalf("first authorized request: status=%d application calls=%d", response.StatusCode, application.Load())
	}
	if calls := c.visitorControl.(*readinessVisitorControl).calls.Load(); calls != 0 {
		t.Fatalf("visitor arrival made %d control calls", calls)
	}
}

func TestPublicReadinessObservesOnlyInstalledExactCurrentSetup(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	startSeparatedPublisher(t, f, publisher.PublicURLServerConfig{Certificate: testCertificate(t, "route.example"), Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("preparation contacted application") })})
	c := preparedReadinessController(t, f)
	now, process := time.Now(), c.Lease()
	if len(f.prepared.observationsFor(f.entry, process, now)) != 1 {
		t.Fatal("installed setup not observed")
	}
	for _, change := range []func(*ingressv1.IngressLease){
		func(p *ingressv1.IngressLease) { p.IngressId = "other" },
		func(p *ingressv1.IngressLease) { p.IngressRunId = "other" },
		func(p *ingressv1.IngressLease) { p.IngressLeaseRevision++ },
	} {
		other := process
		change(&other)
		if len(f.prepared.observationsFor(f.entry, other, now)) != 0 {
			t.Fatal("another ingress process observed local setup")
		}
	}
	for _, change := range []func(*ingressv1.IngressRoutingTableEntry){
		func(e *ingressv1.IngressRoutingTableEntry) { e.PublicUrlId = "other" },
		func(e *ingressv1.IngressRoutingTableEntry) { e.PublishRunId = "other" },
		func(e *ingressv1.IngressRoutingTableEntry) { e.PublishRunNumber++ },
	} {
		other := f.entry
		change(&other)
		if len(f.prepared.observationsFor(other, process, now)) != 0 {
			t.Fatal("another resource/run observed local setup")
		}
	}
	f.prepared.capacity.ready = false
	if len(f.prepared.observationsFor(f.entry, process, now)) != 0 {
		t.Fatal("unobserved publisher setup was acknowledged")
	}
	f.prepared.capacity.ready = true
	if len(f.prepared.observationsFor(f.entry, process, now.Add(11*time.Second))) != 0 {
		t.Fatal("expired local setup was acknowledged")
	}
	f.prepared.policy.lease.Close()
	if len(f.prepared.observationsFor(f.entry, process, now)) != 0 {
		t.Fatal("closed local policy was acknowledged")
	}
}

func TestPublicReadinessConnectorOnlyPointer(t *testing.T) {
	for _, value := range []*bool{nil, new(bool), new(true)} {
		c := &Controller{registration: ingressv1.IngressRegistration{ConnectorOnly: value}, routingTable: &RoutingTable{}}
		if got, want := c.publicRoutingPrepared(0, time.Now()), value != nil && *value; got != want {
			t.Fatalf("connector-only health gate=%t want=%t", got, want)
		}
	}
}
