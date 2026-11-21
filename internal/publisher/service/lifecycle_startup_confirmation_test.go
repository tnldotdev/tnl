package service

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type startupConfirmationHeartbeat struct {
	at, deadline, issuedUntil time.Time
	certificate, policy       bool
	slots                     [2]bool
	state                     controlv1.ServiceRunState
}

type startupConfirmationControl struct {
	*lifecycleControl
	recordMu                sync.Mutex
	ackEntered, ackReturned chan struct{}
	allowACK                chan struct{}
	acknowledged            bool
	beforePromotion         func(context.Context) error
	bound                   *Bound
	slots                   [2]*startupConfirmationSlot
	calls                   []startupConfirmationHeartbeat
	policyCalls             []time.Time
	leaseUntil              time.Time
	endpointReady           bool
	endpointRevision        int64
	confirmations           int
	confirmationEntered     chan struct{}
	confirmationError       error
	blockConfirmation       bool
}

func (c *startupConfirmationControl) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.ServiceRunToken) error {
	close(c.ackEntered)
	defer close(c.ackReturned)
	select {
	case <-c.allowACK:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := c.lifecycleControl.MarkServiceCertificateInstalled(ctx, service, run, number, issuance, expires, token); err != nil {
		return err
	}
	c.recordMu.Lock()
	c.acknowledged = true
	beforePromotion := c.beforePromotion
	c.recordMu.Unlock()
	if beforePromotion != nil {
		return beforePromotion(ctx)
	}
	return nil
}

func (c *startupConfirmationControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	c.recordMu.Lock()
	c.policyCalls = append(c.policyCalls, time.Now())
	c.recordMu.Unlock()
	return c.lifecycleControl.ReadPublisherVisitorPolicy(ctx, request, token)
}

func (c *startupConfirmationControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	state, err := c.lifecycleControl.HeartbeatServiceRun(ctx, service, run, token, health)
	if err != nil {
		return state, err
	}
	call := startupConfirmationHeartbeat{at: time.Now()}
	call.deadline, _ = ctx.Deadline()
	c.recordMu.Lock()
	bound := c.bound
	for slot, session := range c.slots {
		call.slots[slot] = session != nil
	}
	c.recordMu.Unlock()
	if bound != nil {
		_, certificateErr := bound.prepared.currentCertificate()
		call.certificate, call.policy = certificateErr == nil, bound.prepared.currentPolicy()
	}
	c.recordMu.Lock()
	if c.leaseUntil.IsZero() {
		c.leaseUntil = call.at.Add(45 * time.Second)
	}
	state.PublisherExpiresAt = c.leaseUntil
	state.PublicEndpointReady, state.EndpointRevision = c.endpointReady, c.endpointRevision
	if !c.acknowledged {
		state.State = "starting"
	}
	call.issuedUntil, call.state = c.leaseUntil, state
	c.calls = append(c.calls, call)
	eligible := c.acknowledged && call.certificate && call.policy && call.slots == [2]bool{true, true} && health.Healthy
	firstConfirmation := false
	if eligible {
		c.confirmations++
		firstConfirmation = c.confirmations == 1
		if firstConfirmation {
			close(c.confirmationEntered)
		}
	}
	block, confirmationErr := c.blockConfirmation, c.confirmationError
	burst := len(c.calls) > 8
	c.recordMu.Unlock()
	// bound a broken immediate-retry loop without introducing a test timer.
	if burst {
		return controlv1.ServiceRunState{}, errors.New("unexpected startup heartbeat burst")
	}
	if firstConfirmation && block {
		<-ctx.Done()
		return controlv1.ServiceRunState{}, errors.Join(ctx.Err(), confirmationErr)
	}
	if firstConfirmation && confirmationErr != nil {
		return controlv1.ServiceRunState{}, confirmationErr
	}
	return state, nil
}

func (c *startupConfirmationControl) snapshot() []startupConfirmationHeartbeat {
	c.recordMu.Lock()
	defer c.recordMu.Unlock()
	return append([]startupConfirmationHeartbeat(nil), c.calls...)
}

type startupConfirmationSlot struct {
	*heldSlot
	joined    chan struct{}
	cleanup   error
	closeOnce sync.Once
}

func (s *startupConfirmationSlot) Serve(ctx context.Context) error {
	defer close(s.joined)
	return s.heldSlot.Serve(ctx)
}

func (s *startupConfirmationSlot) Close() error {
	s.closeOnce.Do(func() { _ = s.heldSlot.Close() })
	return s.cleanup
}

type startupConfirmationFixture struct {
	t                       *testing.T
	config                  RunConfig
	control                 *startupConfirmationControl
	cache                   *clientstate.CertificateCache
	ctx                     context.Context
	cancel                  context.CancelFunc
	startedAt               time.Time
	joined                  chan struct{}
	result                  error
	allowSecondSlot         chan struct{}
	releaseACK, releaseSlot func()
	observationMu           sync.Mutex
	status                  RunStatus
	readyAt                 []time.Time
	readyStatuses           int
	wantErrors              []error
	wantErrorText           string
	stopped                 bool
}

func newStartupConfirmationFixture(t *testing.T, protocol controlv1.ServiceProtocol, public bool) *startupConfirmationFixture {
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
	// exercise the production default, not the old fixture's five-ms ticker.
	cfg.HeartbeatInterval = 0
	cfg.Connectivity.DisableDirect = true
	unused := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		t.Error("startup confirmation attempted a real relay dial")
		return nil, ErrPrivateStream
	})
	cfg.RelayQUIC, cfg.RelayWebSocket = unused, unused
	control := &startupConfirmationControl{
		lifecycleControl: base, ackEntered: make(chan struct{}), ackReturned: make(chan struct{}),
		allowACK: make(chan struct{}), confirmationEntered: make(chan struct{}), endpointRevision: 7,
	}
	cfg.Control = control
	cache, err := cfg.State.CertificatesForPublisher(base.prep.TeamId, cfg.PublisherIdentityID, *base.prep.CertificatePlan)
	if err != nil {
		t.Fatal(err)
	}
	f := &startupConfirmationFixture{
		t: t, config: cfg, control: control, cache: cache, joined: make(chan struct{}),
		allowSecondSlot: make(chan struct{}),
	}
	f.releaseACK = sync.OnceFunc(func() { close(control.allowACK) })
	f.releaseSlot = sync.OnceFunc(func() { close(f.allowSecondSlot) })
	f.config.Connect = func(ctx context.Context, bound *Bound, slot uint8, _ ConnectOptions) (SlotSession, error) {
		control.recordMu.Lock()
		if control.bound != nil && control.bound != bound {
			t.Error("startup confirmation selected a different run owner")
		}
		control.bound = bound
		control.recordMu.Unlock()
		if slot == 1 {
			select {
			case <-f.allowSecondSlot:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		session := &startupConfirmationSlot{heldSlot: &heldSlot{stopped: make(chan struct{})}, joined: make(chan struct{})}
		control.recordMu.Lock()
		if control.slots[slot] != nil {
			t.Error("startup confirmation replaced a healthy slot")
		}
		control.slots[slot] = session
		control.recordMu.Unlock()
		return session, nil
	}
	f.config.ObserveReadiness = func(status RunStatus) {
		f.observationMu.Lock()
		defer f.observationMu.Unlock()
		f.status = status
		if status.Ready {
			f.readyStatuses++
		}
	}
	f.config.Ready = func() error {
		calls := control.snapshot()
		last := calls[len(calls)-1]
		if !last.certificate || !last.policy || last.slots != [2]bool{true, true} ||
			last.state.State != "ready" || public && (!last.state.PublicEndpointReady || last.state.EndpointRevision != approved.EndpointRevision) {
			t.Error("startup notification preceded actual local or control readiness")
		}
		f.observationMu.Lock()
		defer f.observationMu.Unlock()
		f.readyAt = append(f.readyAt, time.Now())
		return nil
	}
	return f
}

func (f *startupConfirmationFixture) start() {
	f.t.Helper()
	f.startedAt = time.Now()
	f.ctx, f.cancel = context.WithTimeout(f.t.Context(), 30*time.Second)
	go func() {
		defer close(f.joined)
		f.result = Publish(f.ctx, f.config)
	}()
	synctest.Wait()
	f.control.lifecycleControl.mu.Lock()
	starts := f.control.binds
	f.control.lifecycleControl.mu.Unlock()
	if starts != 1 || len(f.control.snapshot()) != 0 {
		f.t.Fatal("fixture did not reach the existing uncertain-start retry")
	}
	// the worker is now blocked on the real recovery timer; advance that timer.
	f.advance(f.startedAt.Add(100 * time.Millisecond))
	f.assertCalls(1)
	startupConfirmationRequireClosed(f.t, f.control.ackEntered, "certificate acknowledgment")
}

func (f *startupConfirmationFixture) advance(at time.Time) {
	f.t.Helper()
	synctest.Wait()
	if time.Now().After(at) {
		f.t.Fatal("startup confirmation already passed the requested observation time")
	}
	time.Sleep(time.Until(at))
	synctest.Wait()
}

func startupConfirmationRequireClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	default:
		t.Fatal(name + " did not reach its synchronized boundary")
	}
}

func (f *startupConfirmationFixture) assertCalls(want int) []startupConfirmationHeartbeat {
	f.t.Helper()
	calls := f.control.snapshot()
	if len(calls) != want {
		var at []time.Duration
		for _, call := range calls {
			at = append(at, call.at.Sub(f.startedAt))
		}
		f.t.Fatalf("startup heartbeat calls = %d, want %d; times since start = %v", len(calls), want, at)
	}
	return calls
}

func (f *startupConfirmationFixture) assertReadiness(ready bool, notifications int) {
	f.t.Helper()
	f.observationMu.Lock()
	defer f.observationMu.Unlock()
	if f.status.Ready != ready || len(f.readyAt) != notifications || notifications == 0 && f.readyStatuses != 0 {
		f.t.Fatalf("startup readiness = %t, notifications = %d, ready observations = %d", f.status.Ready, len(f.readyAt), f.readyStatuses)
	}
}

func (f *startupConfirmationFixture) assertJoined() {
	f.t.Helper()
	startupConfirmationRequireClosed(f.t, f.joined, "publisher cleanup")
	f.control.recordMu.Lock()
	slots, bound := f.control.slots, f.control.bound
	f.control.recordMu.Unlock()
	for _, session := range slots {
		if session != nil {
			startupConfirmationRequireClosed(f.t, session.stopped, "slot close")
			startupConfirmationRequireClosed(f.t, session.joined, "slot worker join")
		}
	}
	startupConfirmationRequireClosed(f.t, f.control.ackReturned, "certificate worker acknowledgment exit")
	if bound != nil {
		bound.mu.Lock()
		closed := bound.closed
		bound.mu.Unlock()
		if !closed || bound.prepared.currentPolicy() {
			f.t.Error("publisher returned before invalidating the run and joining policy cleanup")
		}
	}
	f.control.lifecycleControl.mu.Lock()
	defer f.control.lifecycleControl.mu.Unlock()
	if f.control.bad != nil || f.control.prepares != 1 || f.control.binds != 2 || f.control.closes != 1 {
		f.t.Error("startup confirmation changed preparation, exact start retry, or close ownership", f.control.bad)
	}
}

func (f *startupConfirmationFixture) stop() {
	f.t.Helper()
	if f.cancel == nil || f.stopped {
		return
	}
	f.stopped = true
	before, stoppedAt := len(f.control.snapshot()), time.Now()
	f.cancel()
	synctest.Wait()
	f.assertJoined()
	if len(f.wantErrors) == 0 && f.wantErrorText == "" && f.result != nil {
		f.t.Error("publisher cleanup failed", f.result)
	}
	for _, want := range f.wantErrors {
		if !errors.Is(f.result, want) {
			f.t.Error("publisher lost an independent operation or cleanup failure", f.result, want)
		}
	}
	if f.wantErrorText != "" && (f.result == nil || !strings.Contains(f.result.Error(), f.wantErrorText)) {
		f.t.Error("publisher lost the real certificate cache failure", f.result)
	}
	if len(f.control.snapshot()) != before || !time.Now().Equal(stoppedAt) {
		f.t.Error("cancellation renewed authority or waited for another heartbeat")
	}
}

func TestServiceRunStartupConfirmationCertificateLast(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.ServiceProtocol("tcp")} {
		t.Run(string(protocol), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newStartupConfirmationFixture(t, protocol, false)
				defer f.stop()
				f.releaseSlot()
				f.start()
				initial := f.assertCalls(1)[0].at
				f.advance(initial.Add(time.Second))
				f.assertReadiness(false, 0)
				f.releaseACK()
				synctest.Wait()
				calls := f.assertCalls(2)
				last := calls[1]
				until := calls[0].issuedUntil
				if budget, _ := f.ctx.Deadline(); budget.Before(until) {
					until = budget
				}
				if !last.at.Equal(time.Now()) || !last.certificate || !last.policy || last.slots != [2]bool{true, true} ||
					!last.deadline.Equal(until) {
					t.Fatal("confirmation did not follow actual installation through the bounded heartbeat path")
				}
				f.assertReadiness(true, 1)
				f.advance(initial.Add(9 * time.Second))
				f.assertCalls(2)
				f.advance(initial.Add(10 * time.Second))
				calls = f.assertCalls(3)
				if !calls[2].at.Equal(initial.Add(10 * time.Second)) {
					t.Fatal("startup confirmation reset the original heartbeat ticker")
				}
				f.assertReadiness(true, 1)
				f.control.recordMu.Lock()
				defer f.control.recordMu.Unlock()
				// the first policy notice reconciles once against the startup
				// snapshot. the readiness heartbeat does not start another read
				// or move the independent policy timer.
				wantPolicyCalls := []time.Duration{0, 0, 2 * time.Second, 4 * time.Second, 6 * time.Second, 8 * time.Second, 10 * time.Second}
				var gotPolicyCalls []time.Duration
				for _, at := range f.control.policyCalls {
					gotPolicyCalls = append(gotPolicyCalls, at.Sub(initial))
				}
				if !slices.Equal(gotPolicyCalls, wantPolicyCalls) {
					t.Errorf("policy reads after startup = %v, want %v", gotPolicyCalls, wantPolicyCalls)
				}
			})
		})
	}
}

func TestServiceRunStartupConfirmationSlotsLast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newStartupConfirmationFixture(t, controlv1.ServiceProtocolHTTP, false)
		defer f.stop()
		f.start()
		f.releaseACK()
		synctest.Wait()
		f.control.recordMu.Lock()
		prepared := f.control.bound.prepared
		f.control.recordMu.Unlock()
		if _, err := prepared.currentCertificate(); err != nil || !prepared.currentPolicy() {
			t.Fatal("slots-last fixture did not complete real certificate installation and policy preparation", err)
		}
		f.assertCalls(1)
		f.assertReadiness(false, 0)
		f.advance(f.control.snapshot()[0].at.Add(time.Second))
		f.releaseSlot()
		synctest.Wait()
		f.assertCalls(2)
		f.assertReadiness(true, 1)
	})
}

func TestServiceRunStartupConfirmationHeldAcknowledgment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newStartupConfirmationFixture(t, controlv1.ServiceProtocolHTTP, true)
		defer f.stop()
		f.releaseSlot()
		f.start()
		initial := f.assertCalls(1)[0].at
		f.advance(initial.Add(9 * time.Second))
		f.assertCalls(1)
		f.assertReadiness(false, 0)
		f.advance(initial.Add(10 * time.Second))
		calls := f.assertCalls(2)
		if calls[1].certificate || calls[1].state.State != "starting" {
			t.Fatal("held acknowledgment fabricated serving material or control readiness")
		}
		f.assertReadiness(false, 0)
		f.stop()
	})
}

func TestServiceRunStartupConfirmationTransientFailureWaitsForOriginalTick(t *testing.T) {
	for _, reason := range []failure.Reason{failure.ServerUnavailable, failure.ServerRateLimited} {
		t.Run(string(reason), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newStartupConfirmationFixture(t, controlv1.ServiceProtocolHTTP, false)
				defer f.stop()
				f.control.confirmationError = failure.Wrap("startup confirmation", reason, errors.New("transient startup failure"))
				f.releaseSlot()
				f.start()
				initial := f.assertCalls(1)[0].at
				f.advance(initial.Add(time.Second))
				f.releaseACK()
				synctest.Wait()
				f.assertCalls(2)
				f.assertReadiness(false, 0)
				f.advance(initial.Add(9 * time.Second))
				f.assertCalls(2)
				f.assertReadiness(false, 0)
				f.advance(initial.Add(10 * time.Second))
				calls := f.assertCalls(3)
				if !calls[2].at.Equal(initial.Add(10 * time.Second)) {
					t.Fatal("transient startup failure replaced the original tick with a retry timer")
				}
				f.assertReadiness(true, 1)
			})
		})
	}
}

func TestServiceRunStartupConfirmationDefaultTimeline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newStartupConfirmationFixture(t, controlv1.ServiceProtocolHTTP, true)
		defer f.stop()
		f.releaseSlot()
		f.start()
		initial := f.assertCalls(1)[0].at
		f.advance(initial.Add(10 * time.Second))
		f.assertCalls(2)
		f.advance(initial.Add(11600 * time.Millisecond))
		f.releaseACK()
		synctest.Wait()
		calls := f.assertCalls(3)
		if !calls[2].at.Equal(initial.Add(11600*time.Millisecond)) || calls[2].state.State != "ready" || calls[2].state.PublicEndpointReady {
			t.Fatal("certificate-last confirmation did not advance control observation before the next tick")
		}
		f.assertReadiness(false, 0)
		// model the independently observed DNS completion only after the earlier
		// control confirmation. the unchanged runtime diagnostic owns real DNS.
		f.advance(calls[2].at.Add(3 * time.Second))
		f.control.recordMu.Lock()
		f.control.endpointReady = true
		f.control.recordMu.Unlock()
		f.assertCalls(3)
		f.assertReadiness(false, 0)
		f.advance(initial.Add(20 * time.Second))
		calls = f.assertCalls(4)
		if !calls[3].at.Equal(initial.Add(20*time.Second)) || !calls[3].state.PublicEndpointReady {
			t.Fatal("original twenty-second tick did not observe the completed public endpoint")
		}
		f.assertReadiness(true, 1)
		f.advance(initial.Add(29 * time.Second))
		f.assertCalls(4)
		f.assertReadiness(true, 1)
		deadline, _ := f.ctx.Deadline()
		if !deadline.Equal(f.startedAt.Add(30*time.Second)) || !time.Now().Before(deadline) {
			t.Fatal("startup fixture changed or exceeded the original thirty-second budget")
		}
	})
}

func TestServiceRunStartupConfirmationEndpointGuards(t *testing.T) {
	for _, endpoint := range []struct {
		name     string
		ready    bool
		revision int64
	}{
		{"pending", false, 7},
		{"older", true, 6},
		{"newer", true, 8},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newStartupConfirmationFixture(t, controlv1.ServiceProtocolHTTP, true)
				defer f.stop()
				f.control.endpointReady, f.control.endpointRevision = endpoint.ready, endpoint.revision
				f.releaseSlot()
				f.start()
				initial := f.assertCalls(1)[0].at
				f.advance(initial.Add(time.Second))
				f.releaseACK()
				synctest.Wait()
				f.assertCalls(2)
				f.assertReadiness(false, 0)
				f.advance(initial.Add(10 * time.Second))
				f.assertCalls(3)
				f.assertReadiness(false, 0)
				f.advance(initial.Add(19 * time.Second))
				f.assertCalls(3)
				f.assertReadiness(false, 0)
				f.stop()
			})
		})
	}
}

func TestServiceRunStartupConfirmationPromotionFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newStartupConfirmationFixture(t, controlv1.ServiceProtocolHTTP, true)
		defer f.stop()
		f.wantErrorText = "acknowledged certificate does not match staged material"
		f.control.beforePromotion = func(ctx context.Context) error {
			// rotate the real pending record after ACK, so real Promote rejects
			// it. no fake cache, permissions trick, or serving fallback is used.
			_, err := f.cache.NewPending(ctx, f.control.prep.Hostname)
			return err
		}
		f.releaseSlot()
		f.start()
		f.releaseACK()
		synctest.Wait()
		f.assertCalls(1)
		f.assertReadiness(false, 0)
		f.assertJoined()
		f.control.recordMu.Lock()
		prepared := f.control.bound.prepared
		f.control.recordMu.Unlock()
		if _, err := prepared.currentCertificate(); err == nil {
			t.Error("successful ACK served a certificate whose promotion failed")
		}
		f.stop()
	})
}

func TestServiceRunStartupConfirmationCancellationAndExpiry(t *testing.T) {
	for _, mode := range []string{"cancel", "expiry", "cancel_with_failures"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newStartupConfirmationFixture(t, controlv1.ServiceProtocolHTTP, true)
				defer f.stop()
				f.control.blockConfirmation = true
				operationFailure, cleanupFailure := errors.New("confirmation failed during cancellation"), errors.New("slot cleanup failed")
				if mode == "expiry" {
					f.control.leaseUntil = time.Now().Add(5 * time.Second)
					f.wantErrors = []error{context.DeadlineExceeded}
				}
				if mode == "cancel_with_failures" {
					f.control.confirmationError = operationFailure
					f.wantErrors = []error{operationFailure, cleanupFailure}
				}
				f.releaseSlot()
				f.start()
				if mode == "cancel_with_failures" {
					f.control.recordMu.Lock()
					f.control.slots[0].cleanup = errors.Join(context.Canceled, cleanupFailure)
					f.control.recordMu.Unlock()
				}
				initial := f.assertCalls(1)[0].at
				f.advance(initial.Add(time.Second))
				f.releaseACK()
				synctest.Wait()
				startupConfirmationRequireClosed(t, f.control.confirmationEntered, "early confirmation request")
				calls := f.assertCalls(2)
				until := calls[0].issuedUntil
				budget, _ := f.ctx.Deadline()
				if budget.Before(until) {
					until = budget
				}
				if !calls[1].deadline.Equal(until) {
					t.Fatal("early heartbeat escaped the currently issued publisher expiry or caller budget", calls[1].deadline, until)
				}
				f.assertReadiness(false, 0)
				if mode == "expiry" {
					f.advance(until)
					f.assertJoined()
					if !time.Now().Equal(until) {
						t.Error("expiry cleanup waited beyond the originally issued authority")
					}
				}
				f.stop()
				f.assertCalls(2)
			})
		})
	}
}
