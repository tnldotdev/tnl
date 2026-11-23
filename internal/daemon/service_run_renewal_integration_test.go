package daemon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type observedRunRenewal struct {
	at      time.Time
	run     string
	delay   time.Duration
	refused bool
}

type observedRunControl struct {
	publisherservice.RunControl
	calls chan observedRunRenewal
	miss  atomic.Bool
}

func (c *observedRunControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, report controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	at := time.Now()
	if c.miss.Swap(false) {
		select {
		case c.calls <- observedRunRenewal{at: at, run: run, refused: true}:
		case <-ctx.Done():
		}
		return controlv1.ServiceRunState{}, clientcontrol.ErrUnavailable
	}
	state, err := c.RunControl.HeartbeatServiceRun(ctx, service, run, token, report)
	if err == nil {
		select {
		case c.calls <- observedRunRenewal{at: at, run: run, delay: time.Duration(state.RenewAfterMs) * time.Millisecond}:
		case <-ctx.Done():
		}
	}
	return state, err
}

func TestIntegrationServingPublisherFollowsControlRenewal(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	const initial, tuned = 9 * time.Second, 6 * time.Second
	f := newServiceRuntimeFixture(t, false, nil)
	if err := f.database.ConfigureServiceRunLease(initial); err != nil {
		t.Fatal(err)
	}
	process := startSeparatedPrivateIngress(t, f, 0, "quic", nil)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.URL.Path) }))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	protocol := controlv1.ServiceProtocol("http")
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "renewal", "renewal", controlv1.ServiceMetadata{Protocol: protocol}, &controlv1.ProjectServiceConfiguration{Protocol: &protocol, Public: new(true), Target: target.URL})
	if err != nil {
		t.Fatal(err)
	}
	c := &observedRunControl{calls: make(chan observedRunRenewal, 32)}
	startPrivateHTTPPublisher(t, f, service, target.Listener.Addr().String(), func(cfg *publisherservice.RunConfig) {
		c.RunControl = cfg.Control
		cfg.Control = c
		cfg.HeartbeatInterval = 0
	})
	grant, err := f.identity.routes.CreateServiceHTTPGrant(t.Context(), service.Id, controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tls := f.visitorRoots.Clone()
	tls.ServerName = service.Endpoint.Hostname
	transport := &http.Transport{TLSClientConfig: tls, DialContext: workloadPublicEndpointDialer(t, process.ingresses[0].server, service.Endpoint.Port), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	addr := "https://" + service.Endpoint.Hostname
	awaitServiceHTTPStatus(t, client, addr+"/ready", "Tnl-Visitor-Token", grant.Permission.VisitorToken, http.StatusOK)
	checks := 0
	check := func() {
		path := fmt.Sprintf("/visitor-%d", checks)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Tnl-Visitor-Token", grant.Permission.VisitorToken)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 || string(data) != path {
			t.Fatalf("visitor %d: status=%d bytes=%q error=%v", checks, res.StatusCode, data, err)
		}
		checks++
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	ctx, cancel := context.WithTimeout(t.Context(), 2*initial+10*time.Second)
	defer cancel()
	next := func() observedRunRenewal {
		for {
			select {
			case r := <-c.calls:
				return r
			case <-tick.C:
				check()
			case <-ctx.Done():
				t.Fatal("publisher did not renew", ctx.Err())
			}
		}
	}
	pending := next()
	if pending.delay < initial*4/15-time.Millisecond || pending.delay > initial/3 {
		t.Fatalf("initial hint: %v", pending)
	}
	if err := f.database.ConfigureServiceRunLease(tuned); err != nil {
		t.Fatal(err)
	}
	c.miss.Store(true)
	var failed observedRunRenewal
	for !failed.refused {
		failed = next()
	}
	after := next()
	if after.run != pending.run || after.refused || after.at.Sub(failed.at) > 2*time.Second || after.delay < tuned*4/15-time.Millisecond || after.delay > tuned/3 {
		t.Fatalf("failed=%+v next=%+v", failed, after)
	}
	follow := next()
	if delta := follow.at.Sub(after.at); follow.run != after.run || delta < after.delay-100*time.Millisecond || delta > after.delay+time.Second {
		t.Fatalf("hint=%s actual=%s", after.delay, delta)
	}
	check()
	t.Logf("verified %d fresh visitor responses on one run, initial hint %s, retry %s, tuned hint %s, next renewal %s", checks, pending.delay, after.at.Sub(failed.at), after.delay, follow.at.Sub(after.at))
}
