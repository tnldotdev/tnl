package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPairDenialKeepsStartupAndRetirementBoundaries(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		for _, stage := range []string{"startup", "renewal"} {
			t.Run(transport+"/"+stage, func(t *testing.T) {
				problem := &clientcontrol.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden, Title: "connector peer pair source or run is no longer authorized"}}
				denied := failure.Wrap("request control API", failure.ServerDenied, problem)
				var selections, preparations, renewals, closed atomic.Int32
				f := newConfiguredConnectorFixture(t, transport, "", func(f *connectorFixture, config *Config) {
					f.wantStartupError = stage == "startup"
					control, err := NewControlWithConfig(ControlConfig{
						Signer: f.ConnectorSigner,
						Resolve: func(ctx context.Context, service string) (Run, error) {
							selections.Add(1)
							return f.ResolveService(ctx, service)
						},
						Pair: func(ctx context.Context, service string, request controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
							preparations.Add(1)
							if stage == "startup" {
								return controlv1.ConnectorPeerPair{}, denied
							}
							return f.PrepareConnectorPeerPair(ctx, service, request)
						},
						RenewPair: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
							renewals.Add(1)
							return controlv1.ConnectorPeerPairRenewal{}, denied
						},
						Permission: f.VisitorPermission,
						RebindPair: f.RebindConnectorPeerPair,
						Close:      func(context.Context) error { closed.Add(1); return nil },
					})
					if err != nil {
						t.Fatal(err)
					}
					config.Control = control
				})
				if stage == "renewal" {
					local := f.local(t)
					if _, err := io.WriteString(local, "admitted"); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(local, make([]byte, len("admitted"))); err != nil {
						t.Fatal(err)
					}
					before := preparations.Load()
					f.denied.Store(true)
					select {
					case <-f.finished:
					case <-time.After(3 * time.Second):
						t.Fatal("denied renewal did not retire the connector")
					}
					_ = local.SetReadDeadline(time.Now().Add(time.Second))
					if _, err := local.Read(make([]byte, 1)); err == nil {
						t.Fatal("denied renewal retained its admitted stream")
					} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
						t.Fatal("denied renewal did not close its admitted stream", err)
					}
					if conn, err := net.DialTimeout("tcp", f.localAddress, time.Second); err == nil {
						_ = conn.Close()
						t.Fatal("denied renewal retained its listener")
					}
					if renewals.Load() != 1 || preparations.Load() != before || f.opened.Load() != 1 || f.assignments[0].Load() != 1 || f.assignments[1].Load() != 1 {
						t.Fatal("denied renewal retried or replaced its pair, carriers, or application stream")
					}
				} else if preparations.Load() != 1 || renewals.Load() != 0 {
					t.Fatal("denied startup retried")
				}
				if errors.Is(f.serveErr, ErrServiceConnection) != (stage == "renewal") {
					t.Fatal("denial lost its startup or retired-connection boundary", f.serveErr)
				}
				if reason, ok := failure.ReasonOf(f.serveErr); !ok || reason != failure.ServerDenied || !errors.Is(f.serveErr, problem) || IsMetadataReload(f.serveErr) {
					t.Fatal("denial lost its cause or allowed metadata reload", f.serveErr)
				}
				if selections.Load() != 1 || closed.Load() != 1 {
					t.Fatal("denial reselected a run or returned before joining control cleanup")
				}
			})
		}
	}
}

func TestConnectorRefreshBlockedWriterDoesNotSpendSiblingBudget(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	blocked, blockedPeer := net.Pipe()
	defer blockedPeer.Close()
	healthy, healthyPeer := net.Pipe()
	defer healthyPeer.Close()
	makeUse := func(conn net.Conn, entry tunnelv1.ConnectorPeerVisitorEntry) *connectorUse {
		prepared := &PreparedConnector{ctx: p.ctx, conn: conn, stream: streamPrepared{}, permission: permissionUsable{}, callbackDone: make(chan struct{})}
		prepared.stop = context.AfterFunc(p.ctx, func() { defer close(prepared.callbackDone); _ = conn.Close() })
		return &connectorUse{entry: entry, prepared: prepared}
	}
	p.mu.Lock()
	blockedUse, healthyUse := makeUse(blocked, p.openings[0].entry), makeUse(healthy, p.openings[1].entry)
	permission := p.permission
	p.mu.Unlock()
	defer blockedUse.prepared.Close()
	defer healthyUse.prepared.Close()
	updates := make(chan tunnelv1.ConnectorPermissionUpdate, 2)
	f.mu.Lock()
	f.peers[p.pair.PairId].updates = updates
	f.mu.Unlock()
	written := make(chan error, 1)
	go func() { _, err := blocked.Write([]byte("blocked application bytes")); written <- err }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.renewActive([]*connectorUse{blockedUse, healthyUse}, permission, time.Now().Add(5*time.Second))
	}()
	seen := make(map[string]bool)
	for range 2 {
		select {
		case update := <-updates:
			seen[update.VisitorConnectionID] = true
		case <-time.After(time.Second):
			t.Fatal("blocked application writer spent renewal budget")
		}
	}
	if !seen[blockedUse.entry.VisitorConnectionID] || !seen[healthyUse.entry.VisitorConnectionID] {
		t.Fatal("control stream did not independently renew both visitors")
	}
	_ = blockedPeer.Close()
	<-written
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("renewal workers did not join")
	}
}

func TestConnectorRefreshPreparesReplacementOpeningsBeforePublishing(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	var armed, blocked atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	var once sync.Once
	signer := f.device
	signer.Sign = func(message []byte) []byte {
		if blocked.Load() {
			once.Do(func() { close(entered) })
			<-release
		}
		return f.device.Sign(message)
	}
	control, err := NewControlWithConfig(ControlConfig{
		Signer: f.ConnectorSigner, Resolve: f.ResolveService, Pair: f.PrepareConnectorPeerPair, Permission: f.VisitorPermission, RebindPair: f.RebindConnectorPeerPair,
		RenewPair: func(ctx context.Context, service string, request controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
			renewal, err := f.RenewConnectorPeerPair(ctx, service, request)
			if armed.Load() {
				blocked.Store(true)
			}
			return renewal, err
		}, Close: f.Close,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := f.config
	config.Control, config.MaxConnections = control, 64
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, config, signer)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	defer resume()
	exchange := func(message string) {
		t.Helper()
		local, app := net.Pipe()
		defer app.Close()
		done := make(chan error, 1)
		go func() { defer local.Close(); done <- p.Forward(t.Context(), local) }()
		_ = app.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(app, message); err != nil {
			t.Fatal("background refresh withdrew a prepared opening", err)
		}
		response := make([]byte, len(message))
		if _, err := io.ReadFull(app, response); err != nil || string(response) != message {
			t.Fatal("application waited for background signing or lost its prepared opening", err)
		}
		_ = app.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("application forwarding did not join")
		}
	}
	// consume the warm TCP stream so the next arrival needs an ordinary opening.
	exchange("before-refresh")
	armed.Store(true)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh did not reach background opening preparation")
	}
	exchange("during-refresh")
	p.mu.Lock()
	changed := p.changed
	p.mu.Unlock()
	resume()
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("prepared replacement pool was not published")
	}
	exchange("after-refresh")
}

func TestConnectorRefreshDoesNotReselectRetainedRun(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	var selections atomic.Int32
	control, err := NewControlWithConfig(ControlConfig{
		Signer: f.ConnectorSigner,
		Resolve: func(ctx context.Context, service string) (Run, error) {
			if selections.Add(1) != 1 {
				return Run{}, ErrServiceConnection // placement would select a different or full run.
			}
			return f.ResolveService(ctx, service)
		},
		Pair: f.PrepareConnectorPeerPair, RenewPair: f.RenewConnectorPeerPair, RebindPair: f.RebindConnectorPeerPair, Permission: f.VisitorPermission, Close: f.Close,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := f.config
	config.Control = control
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, config, f.device)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.mu.Lock()
	changed, runID := p.changed, p.run.ServiceRunID
	p.mu.Unlock()
	select {
	case <-changed:
	case <-time.After(4 * time.Second):
		t.Fatal("retained run was not renewed")
	}
	p.mu.Lock()
	kept := p.run.ServiceRunID == runID && p.run.ValidUntil.Equal(p.until) && p.ctx.Err() == nil
	p.mu.Unlock()
	if !kept || selections.Load() != 1 {
		t.Fatal("refresh re-ran placement or ended the retained run", kept, selections.Load())
	}
}

func TestConnectorPermissionMetadataRequiresCurrentServiceRevision(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	permission, err := f.VisitorPermission(t.Context(), f.run.ServiceID)
	if err != nil || validateConnectorPermissionMetadata(f.config, permission) != nil {
		t.Fatal("current service permission was rejected", err)
	}
	permission.ServiceTrustRevision = nil
	if err := validateConnectorPermissionMetadata(f.config, permission); !errors.Is(err, ErrServiceConnection) {
		t.Fatal("missing service revision was accepted", err)
	}
	revision := f.config.TrustRevision + 1
	permission.ServiceTrustRevision = &revision
	var reload *MetadataReloadError
	if err := validateConnectorPermissionMetadata(f.config, permission); !errors.As(err, &reload) || reload.SelectedRevision != revision {
		t.Fatal("stale service revision did not request metadata reload", err)
	}
	permission.Resource.Id = "svc_other"
	if err := validateConnectorPermissionMetadata(f.config, permission); !errors.Is(err, ErrServiceConnection) {
		t.Fatal("another service supplied a metadata revision", err)
	}
}

func TestConnectorRefreshReloadsChangedServiceRevision(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	control, err := NewControlWithConfig(ControlConfig{
		Signer: f.ConnectorSigner, Resolve: f.ResolveService, Pair: f.PrepareConnectorPeerPair, Permission: f.VisitorPermission, RebindPair: f.RebindConnectorPeerPair,
		RenewPair: func(ctx context.Context, service string, request controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
			renewal, err := f.RenewConnectorPeerPair(ctx, service, request)
			renewal.TrustRevision++
			renewal.VisitorPermission.ServiceTrustRevision = new(renewal.TrustRevision)
			return renewal, err
		}, Close: f.Close,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := f.config
	config.Control = control
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, config, f.device)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.mu.Lock()
	oldRun, oldPair, oldPermission, oldInstallation := p.run.ValidUntil, p.until, p.permission.VisitorToken, p.preparedUntil
	p.mu.Unlock()
	select {
	case <-p.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("coherent renewal accepted changed service trust without metadata reload")
	}
	var reload *MetadataReloadError
	if !errors.As(context.Cause(p.ctx), &reload) || reload.SelectedRevision != config.TrustRevision+1 {
		t.Fatal("changed service revision lost its metadata reload boundary", context.Cause(p.ctx))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.run.ValidUntil.Equal(oldRun) || !p.until.Equal(oldPair) || p.permission.VisitorToken != oldPermission || !p.preparedUntil.Equal(oldInstallation) {
		t.Fatal("changed service revision replaced the last confirmed authority")
	}
}

func TestConnectorRefreshRejectsAuthorityExpiredDuringSigning(t *testing.T) {
	for _, boundary := range []string{"run", "renewed run", "pair", "permission", "installation"} {
		t.Run(boundary, func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			var armed, blocked atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			resume := sync.OnceFunc(func() { close(release) })
			var once sync.Once
			var deadline time.Time
			recovering := make(chan struct{})
			var recoveringOnce sync.Once
			signer := f.device
			signer.Sign = func(message []byte) []byte {
				if blocked.Load() {
					once.Do(func() { close(entered) })
					<-release
				}
				return f.device.Sign(message)
			}
			control, err := NewControlWithConfig(ControlConfig{
				Signer:  f.ConnectorSigner,
				Resolve: f.ResolveService, Pair: f.PrepareConnectorPeerPair, Permission: f.VisitorPermission,
				RebindPair: func(ctx context.Context, _, _ string, _ controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
					recoveringOnce.Do(func() { close(recovering) })
					<-ctx.Done()
					return controlv1.ConnectorPeerPairRebindState{}, context.Cause(ctx)
				},
				RenewPair: func(ctx context.Context, service string, request controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
					renewal, err := f.RenewConnectorPeerPair(ctx, service, request)
					if armed.Load() {
						deadline = time.Now().Add(200 * time.Millisecond)
						if boundary == "renewed run" {
							renewal.RunValidUntil = deadline
						}
						if boundary == "pair" {
							renewal.Pair.ExpiresAt = deadline
							renewal.Pair.PublisherPreparedUntil = new(deadline)
							renewal.VisitorPermission.ExpiresAt = deadline
						}
						if boundary == "installation" {
							renewal.Pair.PublisherPreparedUntil = new(deadline)
						}
						if boundary == "permission" {
							renewal.VisitorPermission.ExpiresAt = deadline
						}
						blocked.Store(true)
					}
					return renewal, err
				}, Close: f.Close,
			})
			if err != nil {
				t.Fatal(err)
			}
			config := f.config
			config.Control = control
			setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, config, signer)
			stop()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			defer resume()
			p.mu.Lock()
			oldRun, oldPair, oldPermission, oldInstallation := p.run.ValidUntil, p.until, p.permission.ExpiresAt, p.preparedUntil
			p.mu.Unlock()
			armed.Store(true)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("refresh did not reach background signing")
			}
			if boundary == "run" {
				// expire the last confirmed run while signing is paused.
				p.mu.Lock()
				deadline = time.Now().Add(200 * time.Millisecond)
				p.run.ValidUntil = deadline
				oldRun = deadline
				p.notifyLocked()
				p.mu.Unlock()
			}
			<-time.After(time.Until(deadline))
			resume()
			if boundary == "installation" {
				select {
				case <-recovering:
				case <-time.After(time.Second):
					t.Fatal("expired installation did not request a replacement binding")
				}
				p.mu.Lock()
				retained := p.ownerCurrentLocked() && !p.currentLocked() && p.recoveryState == connectorRebinding && len(p.openings) == 0 && !p.preparedUntil.After(time.Now())
				p.mu.Unlock()
				if !retained {
					t.Fatal("late installation signing either revived packet delivery or retired valid owner authority")
				}
				return
			}
			select {
			case <-p.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("expired replacement authority was published")
			}
			p.mu.Lock()
			unchanged := p.run.ValidUntil.Equal(oldRun) && p.until.Equal(oldPair) && p.permission.ExpiresAt.Equal(oldPermission) && p.preparedUntil.Equal(oldInstallation)
			p.mu.Unlock()
			if !unchanged {
				t.Fatal("late signing replaced the last confirmed authority")
			}
		})
	}
}

func TestConnectorPreparationKeepsOriginalStartupDeadline(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	ownerSetup, stopOwner := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopOwner()
	p, err := prepareConnectorConnection(t.Context(), ownerSetup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// prepare the real inner transport before starting this stream's fixed
	// budget, so scheduling other test packages cannot spend it in fixture setup.
	p.mu.Lock()
	entry, run := p.openings[0].entry, p.run
	p.mu.Unlock()
	gate := &fixtureTLSGate{entered: make(chan struct{}), release: make(chan struct{})}
	f.mu.Lock()
	f.tlsGate = gate
	f.mu.Unlock()
	defer close(gate.release)
	setup, stop := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer stop()
	deadline, _ := setup.Deadline()
	done := make(chan error, 1)
	go func() {
		prepared, err := PrepareConnector(p.ctx, setup, p.session, run, entry)
		if prepared != nil {
			_ = prepared.Close()
		}
		done <- err
	}()
	select {
	case <-gate.entered:
	case err := <-done:
		t.Fatal("did not reach retained TCP preparation", err)
	case <-time.After(time.Second):
		t.Fatal("did not reach retained TCP preparation")
	}
	select {
	case err := <-done:
		// a socket deadline can fire before the context timer runs. the fixed
		// absolute deadline, not that goroutine's scheduling, is the assertion.
		if err == nil || time.Now().Before(deadline) {
			t.Fatal("retained preparation escaped the startup deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retained TCP preparation reset the original startup budget")
	}
}

func TestConnectorPreparationPromotesStreamToOwnerLifetime(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if state := p.connection.ConnectionState().TLS; state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("inner connector connection negotiated TLS %x with %s", state.Version, state.CurveID)
	}
	local, app := net.Pipe()
	defer app.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	_ = app.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(app, "promoted"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("promoted"))
	if _, err := io.ReadFull(app, got); err != nil || string(got) != "promoted" {
		t.Fatal("startup cancellation closed the promoted stream", err)
	}
	_ = app.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("promoted stream did not join")
	}
}

func TestConnectorRevokedOwnerDoesNotCloseSiblingOwner(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	healthy := f.local(t)
	check := func(c net.Conn, message string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(c, message); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != message {
			t.Fatal("owner lost its stream", err)
		}
	}
	check(healthy, "before")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, revoked := net.Pipe()
	defer revoked.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	check(revoked, "revoked")
	f.mu.Lock()
	session := f.peers[p.pair.PairId].session
	f.mu.Unlock()
	_ = session.Close()
	if _, err := revoked.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked owner retained its active stream")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("revocation only timed out the stream")
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoked owner did not join its stream")
	}
	check(healthy, "after")
	if f.opened.Load() != 2 {
		t.Fatal("owner replacement replayed a stream", f.opened.Load())
	}
}

func TestConnectorInstallationDeadlineStopsOwnerBeforePairExpiry(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, app := net.Pipe()
	defer app.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	_ = app.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(app, "ready"); err != nil {
		t.Fatal(err)
	}
	var b [5]byte
	if _, err := io.ReadFull(app, b[:]); err != nil || string(b[:]) != "ready" {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.preparedUntil = time.Now().Add(100 * time.Millisecond)
	if !p.until.After(p.preparedUntil.Add(time.Second)) {
		p.mu.Unlock()
		t.Fatal("fixture pair does not outlive its installation")
	}
	p.notifyLocked()
	p.mu.Unlock()
	if _, err := app.Read(b[:]); err == nil {
		t.Fatal("expired installation retained the local socket")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("installation waited for the pair or QUIC idle timeout", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("installation expiry did not join forwarding")
	}
}
