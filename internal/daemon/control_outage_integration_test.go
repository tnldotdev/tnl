package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type outageTrafficGate struct {
	mu            sync.Mutex
	blocked       bool
	grants        map[string]controloutage.Confirmation
	runID         string
	runToken      credentials.ServiceRunToken
	refusals      map[string]int
	roleDeadlines func() map[string]time.Time
}

func (g *outageTrafficGate) record(key string, started, observed, until time.Time) {
	next, err := g.grants[key].Confirm(started, observed, until, time.Now())
	if err == nil {
		g.grants[key] = next
	}
}

func (g *outageTrafficGate) transition(blocked bool) (time.Time, time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked = blocked
	now := time.Now()
	var earliest time.Time
	for _, grant := range g.grants {
		if earliest.IsZero() || grant.Deadline.Before(earliest) {
			earliest = grant.Deadline
		}
	}
	if g.roleDeadlines != nil {
		for _, deadline := range g.roleDeadlines() {
			if earliest.IsZero() || deadline.Before(earliest) {
				earliest = deadline
			}
		}
	}
	return now, earliest
}

type outagePublisherControl struct {
	publisherservice.RunControl
	gate *outageTrafficGate
}

func (c outagePublisherControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	started := time.Now()
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		c.gate.refusals["publisher"]++
		return controlv1.ServiceRunState{}, clientcontrol.ErrUnavailable
	}
	state, err := c.RunControl.HeartbeatServiceRun(ctx, service, run, token, body)
	if err == nil {
		c.gate.record("publisher", started, state.ObservedAt, state.PublisherExpiresAt)
		c.gate.runID, c.gate.runToken = run, token
	}
	return state, err
}

func (c outagePublisherControl) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	started := time.Now()
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		c.gate.refusals["policy"]++
		return controlv1.VisitorPolicyUpdate{}, clientcontrol.ErrUnavailable
	}
	state, err := c.RunControl.ReadPublisherVisitorPolicy(ctx, body, token)
	if err == nil {
		c.gate.record("policy", started, state.Policy.ObservedAt, state.Policy.ValidUntil)
	}
	return state, err
}

func (c outagePublisherControl) ListConnectorPeerPairs(ctx context.Context, service, run, after string, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	started := time.Now()
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		return controlv1.ConnectorPeerPairCandidates{}, clientcontrol.ErrUnavailable
	}
	page, err := c.RunControl.ListConnectorPeerPairs(ctx, service, run, after, token)
	if err == nil {
		for _, item := range page.Items {
			if grant := item.OwnerAuthority; grant != nil {
				c.gate.record("publisher-owner", started, grant.ObservedAt, grant.ExpiresAt)
			}
		}
	}
	return page, err
}

func (c outagePublisherControl) DeliverConnectorPeerPair(ctx context.Context, service, run, pair string, generation int64, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairDelivery, error) {
	started := time.Now()
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		return controlv1.ConnectorPeerPairDelivery{}, clientcontrol.ErrUnavailable
	}
	delivery, err := c.RunControl.DeliverConnectorPeerPair(ctx, service, run, pair, generation, token)
	if err == nil {
		c.gate.record("publisher-installation", started, delivery.ObservedAt, delivery.ExpiresAt)
	}
	return delivery, err
}

func (c outagePublisherControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		return clientcontrol.ErrUnavailable
	}
	return c.RunControl.CloseServiceRun(ctx, service, run, token)
}

type outageConnectorControl struct {
	connectorstream.Control
	gate *outageTrafficGate
}

func (c outageConnectorControl) PrepareConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	// exact retries carry this original signed request time. recording the last
	// retry's call entry would hide time already spent by the connector owner.
	started := body.RequestedAt
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		return controlv1.ConnectorPeerPair{}, clientcontrol.ErrUnavailable
	}
	pair, err := c.Control.PrepareConnectorPeerPair(ctx, service, body)
	if err == nil {
		c.gate.record("connector", started, pair.ObservedAt, pair.ExpiresAt)
	}
	return pair, err
}

func (c outageConnectorControl) RenewConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
	started := body.RequestedAt
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		c.gate.refusals["connector"]++
		return controlv1.ConnectorPeerPairRenewal{}, clientcontrol.ErrUnavailable
	}
	renewed, err := c.Control.RenewConnectorPeerPair(ctx, service, body)
	if err == nil {
		c.gate.record("connector", started, renewed.Pair.ObservedAt, renewed.Pair.ExpiresAt)
		c.gate.record("visitor-permission", started, renewed.Pair.ObservedAt, renewed.VisitorPermission.ExpiresAt)
	}
	return renewed, err
}

func (c outageConnectorControl) RebindConnectorPeerPair(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	if c.gate.blocked {
		return controlv1.ConnectorPeerPairRebindState{}, clientcontrol.ErrUnavailable
	}
	return c.Control.RebindConnectorPeerPair(ctx, service, pair, body)
}

func newOutagePrivateProxy(t *testing.T, cfg *daemonconfig.Config, ca *testCertificateAuthority, gate *outageTrafficGate) func() {
	t.Helper()
	address := cfg.PrivateControlListen
	upstream, err := url.Parse("https://" + cfg.ServerHostname())
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: cfg.ServerHostname(), MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.StatusCode != 200 {
			return nil
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		response.Body = io.NopCloser(bytes.NewReader(body))
		var snapshot ingressv1.IngressServices
		if json.Unmarshal(body, &snapshot) == nil && !snapshot.ObservedAt.IsZero() && len(snapshot.Runs) != 0 {
			until := snapshot.ValidUntil
			for _, run := range snapshot.Runs {
				source, err := tunnelv1.ReadVisitorSourceAuthority(run.SourceAuthority)
				if err != nil {
					return err
				}
				until = minTime(until, time.Unix(source.ValidUntil, 0))
			}
			// the handler holds the same fault lock through the complete reply.
			started, _ := response.Request.Context().Value(outageRequestStarted{}).(time.Time)
			gate.record("routing", started, snapshot.ObservedAt, until)
		}
		return nil
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		gate.mu.Lock()
		defer gate.mu.Unlock()
		if gate.blocked {
			gate.refusals["private"]++
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), outageRequestStarted{}, started)))
	}))
	server.TLS = serviceRuntimeTLS(t, ca, cfg.ServerHostname())
	server.StartTLS()
	stop := func() {
		server.CloseClientConnections()
		server.Close()
		proxy.Transport.(*http.Transport).CloseIdleConnections()
	}
	cfg.PrivateControlListen = server.Listener.Addr().String()
	return stop
}

type outageRequestStarted struct{}

type outageHTTPStream struct {
	body     io.ReadCloser
	response *http.Response
	lines    chan string
	done     chan outageHTTPStreamEnd
}

type outageHTTPStreamEnd struct {
	at  time.Time
	err error
}

func openOutageHTTPStream(t *testing.T, client *http.Client, address, token string) *outageHTTPStream {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), "GET", address, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Tnl-Visitor-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		t.Fatal("stream admission failed", response.StatusCode)
	}
	stream := &outageHTTPStream{body: response.Body, response: response, lines: make(chan string, 8), done: make(chan outageHTTPStreamEnd, 1)}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		reader := bufio.NewReader(response.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				stream.done <- outageHTTPStreamEnd{time.Now(), err}
				return
			}
			select {
			case stream.lines <- line:
			case <-t.Context().Done():
				stream.done <- outageHTTPStreamEnd{time.Now(), context.Cause(t.Context())}
				return
			}
		}
	}()
	t.Cleanup(func() { _ = stream.body.Close(); <-joined })
	return stream
}

func outageTerminalOnly(err error) bool {
	if err == nil {
		return true
	}
	// a physical close failure cannot borrow an expected expiry cause.
	var physical *muxsession.QUICTransportCloseError
	if errors.As(err, &physical) {
		return false
	}
	// this scenario expires role leases before shutdown can acknowledge a drain.
	// only that exact refusal is expected; other control or cleanup errors remain.
	if problem, ok := err.(*relay.ControlProblemError); ok {
		return problem.Operation == "drain relay" && problem.Status == http.StatusConflict &&
			problem.Problem != nil && problem.Problem.Code == relayv1.RelayLeaseStale
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !outageTerminalOnly(child) {
				return false
			}
		}
		return true
	}
	if failure.Only(err, clientcontrol.ErrUnavailable) || failure.Only(err, context.Canceled) ||
		failure.Only(err, context.DeadlineExceeded) || failure.Only(err, publisherservice.ErrPrivateStream) ||
		failure.Only(err, controloutage.ErrDeadline) || failure.Only(err, ingress.ErrIngressLeaseLost) ||
		failure.Only(err, connectorstream.ErrServiceConnection) {
		return true
	}
	// cleanup may wrap a join of different expected expiry causes. inspect every
	// leaf instead of requiring that the whole wrapped join match one cause.
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		cause := wrapped.Unwrap()
		return cause != nil && outageTerminalOnly(cause)
	}
	return false
}

func TestIntegrationControlOutageTraffic(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	const tolerance = 12 * time.Second
	gate := &outageTrafficGate{grants: make(map[string]controloutage.Confirmation), refusals: make(map[string]int)}
	var stopProxy func()
	f := newServiceRuntimeFixtureTiming(t, false, nil, false, func(cfg *daemonconfig.Config, _ *http.Transport, ca *testCertificateAuthority) {
		cfg.ControlOutageTolerance = tolerance
		stopProxy = newOutagePrivateProxy(t, cfg, ca, gate)
	})
	f.owner.cleanupResource(t, stopProxy)
	if f.controlConfig.IngressLeaseDuration != 5*time.Second || f.controlConfig.RelayLeaseDuration != 5*time.Second {
		t.Fatal("outage proof requires the original five-second role liveness")
	}
	// restore control before the topology's joined shutdown, including after a
	// failed assertion. outage traffic is checked before this cleanup can run.
	t.Cleanup(func() { gate.transition(false) })
	if err := f.database.ConfigureControlOutageTolerance(tolerance); err != nil {
		t.Fatal(err)
	}
	process := startSeparatedPrivateIngress(t, f, 0, "quic", nil)
	gate.roleDeadlines = func() map[string]time.Time {
		deadlines := map[string]time.Time{"ingress": process.ingresses[0].controller.Lease().ServingUntil}
		for id, relay := range f.relayProcesses {
			deadlines[id] = relay.process.relays[0].controller.Lease().ServingUntil
		}
		return deadlines
	}
	progress := map[string]chan string{"/public": make(chan string), "/connector": make(chan string)}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, streaming := progress[r.URL.Path]; !streaming {
			_, _ = io.WriteString(w, "ready\n")
			return
		}
		_, _ = io.WriteString(w, "ready\n")
		w.(http.Flusher).Flush()
		for {
			select {
			case line := <-progress[r.URL.Path]:
				_, _ = io.WriteString(w, line)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	protocol := controlv1.ServiceProtocol("http")
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "outage-http", "outage-http",
		controlv1.ServiceMetadata{Protocol: protocol}, &controlv1.ProjectServiceConfiguration{Protocol: &protocol, Public: new(true), Target: target.URL})
	if err != nil {
		t.Fatal(err)
	}
	startPrivateHTTPPublisher(t, f, service, target.Listener.Addr().String(), func(cfg *publisherservice.RunConfig) {
		cfg.Control = outagePublisherControl{cfg.Control, gate}
	})
	// this scenario intentionally reaches the fixed serving fence. retain all
	// independent cleanup failures instead of accepting every publisher error.
	for _, processes := range [][]runtimeProcess{f.owner.publishers, f.owner.ingress, f.owner.relays} {
		for i := range processes {
			wait := processes[i].wait
			processes[i].wait = func() error {
				err := wait()
				if !outageTerminalOnly(err) {
					return err
				}
				t.Logf("joined expected outage terminal result: %v", err)
				return nil
			}
		}
	}
	credential, err := f.identity.routes.CreateServiceHTTPGrant(t.Context(), service.Id,
		controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	roots := f.visitorRoots.Clone()
	roots.ServerName = service.Endpoint.Hostname
	publicTransport := &http.Transport{TLSClientConfig: roots.Clone(),
		DialContext: workloadPublicEndpointDialer(t, process.ingresses[0].server, service.Endpoint.Port)}
	defer publicTransport.CloseIdleConnections()
	publicClient := &http.Client{Transport: publicTransport}
	publicAddress := "https://" + service.Endpoint.Hostname
	awaitServiceHTTPStatus(t, publicClient, publicAddress+"/missing", "Tnl-Visitor-Token", credential.Permission.VisitorToken, http.StatusOK)
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	_, tcp := f.connectors()
	local, stopConnector := startRuntimeConnector(t, f, service,
		connectorstream.Config{Control: outageConnectorControl{control, gate}, IdentityID: person.Identity.Id,
			RelayQUIC: privateDisabledConnector(), RelayWebSocket: tcp}, outageTerminalOnly)
	defer stopConnector()
	localTransport := &http.Transport{TLSClientConfig: roots.Clone()}
	defer localTransport.CloseIdleConnections()
	streams := map[string]*outageHTTPStream{
		"/public":    openOutageHTTPStream(t, publicClient, publicAddress+"/public", credential.Permission.VisitorToken),
		"/connector": openOutageHTTPStream(t, &http.Client{Transport: localTransport}, "https://"+local.Addr().String()+"/connector", ""),
	}
	receive := func(path, want string) {
		t.Helper()
		select {
		case line := <-streams[path].lines:
			if line != want {
				t.Fatal(path, line, want)
			}
		case err := <-streams[path].done:
			t.Fatal("traffic stopped before its captured deadline", path, err)
		case <-time.After(2 * time.Second):
			t.Fatal("traffic made no progress", path)
		}
	}
	for path := range streams {
		receive(path, "ready\n")
	}
	exchange := func(label string) {
		t.Helper()
		for path := range streams {
			select {
			case progress[path] <- label + "\n":
			case err := <-streams[path].done:
				t.Fatal("target connection stopped", path, err)
			case <-time.After(2 * time.Second):
				t.Fatal("target did not receive the original stream", path)
			}
			receive(path, label+"\n")
			t.Logf("%s original request progressed phase=%s at=%s", path, label, time.Now().Format(time.RFC3339Nano))
		}
	}
	exchange("before")
	firstOutage, firstUntil := gate.transition(true)
	if firstUntil.Sub(firstOutage) <= 2*time.Second {
		t.Fatal("fixture did not capture enough issued allowance", firstOutage, firstUntil)
	}
	exchange("during")
	privateWait(t, 4*time.Second, func(context.Context) (bool, error) {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		for _, key := range []string{"publisher", "policy", "connector", "private"} {
			if gate.refusals[key] == 0 {
				return false, nil
			}
		}
		return true, nil
	})
	exchange("after-failed-refresh")
	gate.transition(false)
	exchange("recovered")
	privateWait(t, 5*time.Second, func(context.Context) (bool, error) {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		for _, key := range []string{"publisher", "policy", "connector", "visitor-permission", "publisher-installation", "routing"} {
			if !gate.grants[key].ObservedAt.After(firstOutage) || !gate.grants[key].Deadline.After(time.Now().Add(7*time.Second)) {
				return false, nil
			}
		}
		return true, nil
	})
	outageAt, earliest := gate.transition(true)
	gate.mu.Lock()
	// both requests use this publisher's heartbeat and visitor policy. these
	// captured recipient deadlines are an upper bound even if another parent
	// (connector permission, relay, certificate) ends earlier.
	trafficUntil := minTime(gate.grants["publisher"].Deadline, gate.grants["policy"].Deadline)
	runAuthorityUntil := gate.grants["publisher"].ValidUntil
	gate.mu.Unlock()
	for role, deadline := range gate.roleDeadlines() {
		t.Logf("%s accepted local serving deadline=%s", role, deadline.Format(time.RFC3339Nano))
	}
	t.Logf("outage started=%s earliest captured serving deadline=%s allowance=%s", outageAt.Format(time.RFC3339Nano), earliest.Format(time.RFC3339Nano), tolerance)
	if earliest.Sub(outageAt) <= time.Second {
		t.Fatal("second outage started without current authority")
	}
	exchange("inside")
	// role liveness still expires after five seconds in this topology. traffic
	// must not stop there while its separately issued serving grant remains live.
	if earliest.Sub(outageAt) <= 6*time.Second {
		t.Fatal("fixture cannot distinguish liveness from serving authorization", earliest.Sub(outageAt))
	}
	crossLiveness := time.NewTimer(time.Until(outageAt.Add(5500 * time.Millisecond)))
	select {
	case <-crossLiveness.C:
	case <-t.Context().Done():
		crossLiveness.Stop()
		t.Fatal(context.Cause(t.Context()))
	}
	exchange("past-liveness")
	ingressLease := process.ingresses[0].controller.Lease()
	if ingressLease.LeaseExpiresAt.IsZero() || ingressLease.LeaseExpiresAt.After(time.Now()) {
		t.Fatal("public traffic did not cross the actual issued ingress liveness deadline")
	}
	for id, relay := range f.relayProcesses {
		lease := relay.process.relays[0].controller.Lease()
		if lease.LeaseExpiresAt.IsZero() || lease.LeaseExpiresAt.After(time.Now()) {
			t.Fatal("traffic did not cross the actual issued relay liveness deadline", id)
		}
	}
	for path, stream := range streams {
		timer := time.NewTimer(time.Until(trafficUntil.Add(time.Second)))
		select {
		case end := <-stream.done:
			timer.Stop()
			if end.at.Before(earliest) {
				t.Fatal("traffic ended before the earliest captured grant", path, end.err, end.at, earliest)
			}
			if end.at.After(trafficUntil.Add(time.Second)) {
				t.Fatal("traffic outlived its captured serving grant", path, end.at, trafficUntil)
			}
			t.Logf("%s stream stopped at=%s error=%v", path, end.at.Format(time.RFC3339Nano), end.err)
		case <-timer.C:
			t.Fatal("traffic outlived its captured serving grant", path)
		}
	}
	// recipient clocks spend response latency. control may retain the same run
	// for that small remainder, so cross its persisted deadline before asking
	// whether an old run can be renewed.
	runExpired := time.NewTimer(max(0, time.Until(runAuthorityUntil)))
	select {
	case <-runExpired.C:
	case <-t.Context().Done():
		runExpired.Stop()
		t.Fatal(context.Cause(t.Context()))
	}
	gate.transition(false)
	gate.mu.Lock()
	runID, runToken := gate.runID, gate.runToken
	gate.mu.Unlock()
	_, err = f.identity.routes.HeartbeatServiceRun(t.Context(), service.Id, runID, runToken,
		controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 64})
	var problem *clientcontrol.ProblemError
	if !errors.Is(err, clientcontrol.ErrNotFound) || !errors.As(err, &problem) ||
		problem.Status != http.StatusNotFound || problem.Problem.Code != controlv1.NotFound {
		t.Fatal("recovery did not require fresh run authority", err)
	}
	for path, stream := range streams {
		select {
		case line := <-stream.lines:
			t.Fatal("recovery revived the expired request", path, line)
		default:
		}
	}
	// only fresh control permission can create another service run after this
	// point; neither the old request nor its expired connector owner is reused.
	var runState string
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT state FROM control.service_runs WHERE service_id=$1 ORDER BY run_number DESC LIMIT 1`, service.Id).Scan(&runState); err != nil {
		t.Fatal(err)
	}
	t.Logf("expired run state=%s; existing public and connector requests remain closed", runState)
}
