package service

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type endpointReadinessControl struct {
	*lifecycleControl
	endpointMu sync.Mutex
	ready      bool
	revision   int64
	calls      int
	last       controlv1.ServiceRunState
}

func (c *endpointReadinessControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	state, err := c.lifecycleControl.HeartbeatServiceRun(ctx, service, run, token, health)
	if err != nil {
		return state, err
	}
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	state.PublicEndpointReady, state.EndpointRevision = c.ready, c.revision
	c.calls++
	c.last = state
	return state, nil
}

func (c *endpointReadinessControl) set(ready bool, revision int64) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	c.ready, c.revision = ready, revision
}

func (c *endpointReadinessControl) snapshot() (int, controlv1.ServiceRunState) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	return c.calls, c.last
}

type endpointReadinessObservations struct {
	mu            sync.Mutex
	status        RunStatus
	readyStatuses int
	notifications int
	preparations  int
	prepared      controlv1.ServiceRunPreparation
	bound         *Bound
	slots         [2]*heldSlot
}

type aliasEndpointReadinessControl struct {
	*endpointReadinessControl
	hostname     *string
	aliasReady   *bool
	confirmHosts bool
	reads        map[string]int
}

func (c *aliasEndpointReadinessControl) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	update, err := c.lifecycleControl.ReadPublisherVisitorPolicy(ctx, body, token)
	if err == nil && body.Hostname != "" {
		if body.Hostname != c.prep.Hostname && (c.prep.RunHostname == nil || body.Hostname != *c.prep.RunHostname) {
			return controlv1.VisitorPolicyUpdate{}, ErrPrivateStream
		}
		update.Policy.Hostname = body.Hostname
		if c.confirmHosts {
			c.endpointMu.Lock()
			c.reads[body.Hostname]++
			c.endpointMu.Unlock()
			key := strings.Repeat("a", 64)
			if body.Hostname == c.prep.Hostname {
				key = strings.Repeat("c", 64)
			}
			update.ConfirmationKey = &key
			update.Policy.ValidUntil = update.Policy.ObservedAt.Add(12 * time.Second)
		}
	}
	return update, err
}

func (c *aliasEndpointReadinessControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	state, err := c.endpointReadinessControl.HeartbeatServiceRun(ctx, service, run, token, health)
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	state.RunHostname, state.RunAliasReady = c.hostname, c.aliasReady
	if c.confirmHosts {
		evidence := func(host, digit string) *controlv1.PublisherPolicyConfirmation {
			return &controlv1.PublisherPolicyConfirmation{Hostname: host, ConfirmationKey: strings.Repeat(digit, 64), ObservedAt: state.ObservedAt, ValidUntil: state.ObservedAt.Add(12 * time.Second)}
		}
		state.PolicyConfirmation = evidence(c.prep.Hostname, "c")
		state.AliasPolicyConfirmation = evidence(*c.prep.RunHostname, "a")
	}
	return state, err
}

func (c *aliasEndpointReadinessControl) setAlias(hostname *string, ready *bool) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	c.hostname, c.aliasReady = hostname, ready
}

func endpointReadinessFixture(t *testing.T, protocol controlv1.ServiceProtocol, public, ready bool, revision int64) (RunConfig, *endpointReadinessControl, *endpointReadinessObservations) {
	t.Helper()
	cfg, base := lifecycleFixture(t)
	approved, err := base.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Public, approved.EndpointRevision = protocol, public, 7
	if protocol == controlv1.ServiceProtocolHTTP {
		approved.Endpoint.Port = 443
		cfg.Target = ""
		cfg.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	base.approved = &approved
	cfg.Metadata.Protocol = protocol
	cfg.HeartbeatInterval = 50 * time.Millisecond
	cfg.Connectivity.DisableDirect = true
	unused := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		t.Error("readiness fixture attempted a real relay dial")
		return nil, ErrPrivateStream
	})
	cfg.RelayQUIC, cfg.RelayWebSocket = unused, unused
	control := &endpointReadinessControl{lifecycleControl: base, ready: ready, revision: revision}
	cfg.Control = control
	observed := &endpointReadinessObservations{}
	cfg.Prepared = func(p controlv1.ServiceRunPreparation) error {
		observed.mu.Lock()
		defer observed.mu.Unlock()
		observed.preparations++
		observed.prepared = p
		return nil
	}
	cfg.Connect = func(_ context.Context, bound *Bound, slot uint8, _ ConnectOptions) (SlotSession, error) {
		observed.mu.Lock()
		defer observed.mu.Unlock()
		if observed.bound != nil && observed.bound != bound {
			t.Error("publisher slots selected different run owners")
		}
		if observed.slots[slot] != nil {
			t.Error("endpoint readiness replaced a healthy publisher connection")
		}
		session := &heldSlot{stopped: make(chan struct{})}
		observed.bound, observed.slots[slot] = bound, session
		return session, nil
	}
	cfg.ObserveReadiness = func(status RunStatus) {
		observed.mu.Lock()
		defer observed.mu.Unlock()
		observed.status = status
		if status.Ready {
			observed.readyStatuses++
		}
	}
	cfg.Ready = func() error {
		_, state := control.snapshot()
		observed.mu.Lock()
		defer observed.mu.Unlock()
		observed.notifications++
		p := observed.prepared
		if observed.preparations != 1 || p.ServiceId != cfg.ServiceID || p.ServiceRunId != base.setup.ServiceRunId ||
			p.RunNumber != base.setup.RunNumber || p.Hostname != approved.Endpoint.Hostname ||
			state.ServiceId != p.ServiceId || state.ServiceRunId != p.ServiceRunId || state.RunNumber != p.RunNumber {
			t.Error("ready notification did not belong to the original prepared run and address")
		}
		if public && (!state.PublicEndpointReady || state.EndpointRevision != approved.EndpointRevision) {
			t.Error("ready notification advertised an unready or replaced public endpoint")
		}
		return nil
	}
	return cfg, control, observed
}

func assertEndpointReadinessPrerequisites(t *testing.T, control *endpointReadinessControl, observed *endpointReadinessObservations) {
	t.Helper()
	_, state := control.snapshot()
	observed.mu.Lock()
	defer observed.mu.Unlock()
	if state.State != "ready" || state.Healthy == nil || !*state.Healthy ||
		!state.PublisherExpiresAt.After(time.Now()) || !observed.status.TargetHealthy ||
		!observed.status.ConfigurationCurrent || observed.status.Connected != [2]bool{true, true} ||
		observed.bound == nil || observed.slots[0] == nil || observed.slots[1] == nil {
		t.Fatal("endpoint fact was not the only remaining readiness boundary")
	}
	if _, err := observed.bound.prepared.currentCertificate(); err != nil {
		t.Fatal("fixture did not install the real run certificate", err)
	}
	if !observed.bound.prepared.currentPolicy() {
		t.Fatal("fixture did not prepare current protocol-shaped visitor policy")
	}
}

func assertEndpointReadiness(t *testing.T, observed *endpointReadinessObservations, ready bool, notifications int) {
	t.Helper()
	observed.mu.Lock()
	defer observed.mu.Unlock()
	if observed.status.Ready != ready || observed.notifications != notifications {
		t.Fatal("endpoint readiness observation or one-time notification was incorrect", observed.status.Ready, observed.notifications)
	}
	if notifications == 0 && observed.readyStatuses != 0 {
		t.Fatal("an earlier readiness observation advertised the unready endpoint")
	}
	if ready && observed.readyStatuses == 0 {
		t.Fatal("ready notification had no matching ready observation")
	}
}

func assertEndpointHeartbeatsContinue(t *testing.T, cfg RunConfig, control *endpointReadinessControl) {
	t.Helper()
	before, _ := control.snapshot()
	time.Sleep(3 * cfg.HeartbeatInterval)
	synctest.Wait()
	after, _ := control.snapshot()
	if after < before+2 {
		t.Fatal("endpoint readiness blocked control heartbeats", before, after)
	}
}

func startEndpointReadinessRun(t *testing.T, cfg RunConfig, control *endpointReadinessControl, observed *endpointReadinessObservations) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	joined := make(chan struct{})
	var result error
	go func() { defer close(joined); result = Publish(ctx, cfg) }()
	stop := sync.OnceFunc(func() {
		before, state := control.snapshot()
		stoppedAt := time.Now()
		cancel()
		synctest.Wait()
		select {
		case <-joined:
		default:
			t.Fatal("publisher cancellation waited for endpoint readiness instead of joining cleanup")
		}
		if result != nil {
			t.Error("publisher cleanup failed", result)
		}
		after, last := control.snapshot()
		if after != before || !last.PublisherExpiresAt.Equal(state.PublisherExpiresAt) || !time.Now().Equal(stoppedAt) {
			t.Error("endpoint readiness cancellation renewed or waited past the captured authority")
		}
		control.mu.Lock()
		if control.bad != nil || control.prepares != 1 || control.binds != 2 || control.closes != 1 {
			t.Error("endpoint readiness changed the original service-run lifecycle", control.bad)
		}
		control.mu.Unlock()
		observed.mu.Lock()
		defer observed.mu.Unlock()
		for _, session := range observed.slots {
			if session == nil {
				continue
			}
			select {
			case <-session.stopped:
			default:
				t.Error("publisher returned before its relay slot joined")
			}
		}
	})
	t.Cleanup(stop)
	time.Sleep(time.Second)
	synctest.Wait()
	select {
	case <-joined:
		t.Fatal("publisher returned before endpoint readiness could be observed", result)
	default:
	}
	return stop
}

func TestPublicServiceRunReadinessWaitsForEndpointDNS(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.ServiceProtocol("tcp")} {
		for _, dns := range []string{"pending", "failed"} {
			t.Run(string(protocol)+"/"+dns, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					cfg, control, observed := endpointReadinessFixture(t, protocol, true, false, 7)
					stop := startEndpointReadinessRun(t, cfg, control, observed)
					defer stop()
					assertEndpointReadinessPrerequisites(t, control, observed)
					assertEndpointReadiness(t, observed, false, 0)
					// pending and failed DNS both arrive as a false endpoint fact,
					// not a blocked heartbeat or a fabricated publication error.
					assertEndpointHeartbeatsContinue(t, cfg, control)
					assertEndpointReadiness(t, observed, false, 0)
					control.set(true, 7)
					assertEndpointHeartbeatsContinue(t, cfg, control)
					assertEndpointReadinessPrerequisites(t, control, observed)
					assertEndpointReadiness(t, observed, true, 1)
					assertEndpointHeartbeatsContinue(t, cfg, control)
					assertEndpointReadiness(t, observed, true, 1)
					control.set(false, 7)
					assertEndpointHeartbeatsContinue(t, cfg, control)
					assertEndpointReadiness(t, observed, false, 1)
					control.set(true, 7)
					assertEndpointHeartbeatsContinue(t, cfg, control)
					assertEndpointReadiness(t, observed, true, 1)
				})
			})
		}
	}
}

func TestPublicServiceRunReadinessWaitsForItsExactAlias(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, base, observed := endpointReadinessFixture(t, controlv1.ServiceProtocolHTTP, true, true, 7)
		base.prep.RunHostname = new(httpRunAlias)
		plan := *base.prep.CertificatePlan
		plan.CacheKey, plan.Scope = "run-alias/readiness", base.prep.Hostname
		plan.Identifiers = []string{base.prep.Hostname, httpRunAlias}
		base.prep.CertificatePlan = &plan
		control := &aliasEndpointReadinessControl{endpointReadinessControl: base}
		cfg.Control = control
		stop := startEndpointReadinessRun(t, cfg, base, observed)
		defer stop()
		assertEndpointReadinessPrerequisites(t, base, observed)
		for _, observation := range []struct {
			hostname *string
			ready    *bool
		}{
			{new(httpRunAlias), new(false)},
			{new(httpRunAlias), nil},
			{nil, new(true)},
			{new("r-bbbbbbbbbbbbbbbbbbbbbbbbbb.example.test"), new(true)},
		} {
			control.setAlias(observation.hostname, observation.ready)
			assertEndpointHeartbeatsContinue(t, cfg, base)
			assertEndpointReadiness(t, observed, false, 0)
		}
		control.setAlias(new(httpRunAlias), new(true))
		assertEndpointHeartbeatsContinue(t, cfg, base)
		assertEndpointReadiness(t, observed, true, 1)
		control.setAlias(new(httpRunAlias), new(false))
		assertEndpointHeartbeatsContinue(t, cfg, base)
		assertEndpointReadiness(t, observed, false, 1)
		control.setAlias(new(httpRunAlias), new(true))
		assertEndpointHeartbeatsContinue(t, cfg, base)
		assertEndpointReadiness(t, observed, true, 1)
	})
}

func TestServiceRunRenewsBothHostnamePolicies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, base, observed := endpointReadinessFixture(t, controlv1.ServiceProtocolHTTP, true, true, 7)
		cfg.HeartbeatInterval = time.Second
		base.prep.RunHostname = new(httpRunAlias)
		plan := *base.prep.CertificatePlan
		plan.CacheKey, plan.Scope = "run-alias/renewal", base.prep.Hostname
		plan.Identifiers = []string{base.prep.Hostname, httpRunAlias}
		base.prep.CertificatePlan = &plan
		control := &aliasEndpointReadinessControl{endpointReadinessControl: base, hostname: new(httpRunAlias), aliasReady: new(true), confirmHosts: true, reads: map[string]int{}}
		cfg.Control = control
		stop := startEndpointReadinessRun(t, cfg, base, observed)
		defer stop()
		count := func(host string) int {
			control.endpointMu.Lock()
			defer control.endpointMu.Unlock()
			return control.reads[host]
		}
		a, b := count(base.prep.Hostname), count(httpRunAlias)
		time.Sleep(24 * time.Second)
		synctest.Wait()
		if a == 0 || b == 0 || count(base.prep.Hostname) != a || count(httpRunAlias) != b {
			t.Fatal("a quiet hostname refetched policy after its original deadline", a, b, count(base.prep.Hostname), count(httpRunAlias))
		}
		assertEndpointReadiness(t, observed, true, 1)
	})
}

func TestPublicServiceRunReadinessRejectsDifferentEndpointRevision(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.ServiceProtocol("tcp")} {
		for _, revision := range []int64{6, 8} {
			name := "older"
			if revision > 7 {
				name = "newer"
			}
			t.Run(string(protocol)+"/"+name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					cfg, control, observed := endpointReadinessFixture(t, protocol, true, true, revision)
					stop := startEndpointReadinessRun(t, cfg, control, observed)
					defer stop()
					assertEndpointReadinessPrerequisites(t, control, observed)
					assertEndpointReadiness(t, observed, false, 0)
					assertEndpointHeartbeatsContinue(t, cfg, control)
					assertEndpointReadiness(t, observed, false, 0)
					// cancellation must join while the public revision remains
					// mismatched; it cannot wait for a different address to match.
					stop()
					assertEndpointReadiness(t, observed, false, 0)
				})
			})
		}
	}
}

func TestPublicServiceRunCancellationDoesNotWaitForEndpointDNS(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.ServiceProtocol("tcp")} {
		t.Run(string(protocol), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, control, observed := endpointReadinessFixture(t, protocol, true, false, 7)
				stop := startEndpointReadinessRun(t, cfg, control, observed)
				defer stop()
				assertEndpointReadinessPrerequisites(t, control, observed)
				assertEndpointHeartbeatsContinue(t, cfg, control)
				assertEndpointReadiness(t, observed, false, 0)
				stop()
				assertEndpointReadiness(t, observed, false, 0)
			})
		})
	}
}

func TestConnectorOnlyServiceRunReadinessIgnoresEndpointDNS(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.ServiceProtocol("tcp")} {
		t.Run(string(protocol), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, control, observed := endpointReadinessFixture(t, protocol, false, false, 8)
				stop := startEndpointReadinessRun(t, cfg, control, observed)
				defer stop()
				assertEndpointReadinessPrerequisites(t, control, observed)
				assertEndpointReadiness(t, observed, true, 1)
				assertEndpointHeartbeatsContinue(t, cfg, control)
				assertEndpointReadiness(t, observed, true, 1)
			})
		})
	}
}
