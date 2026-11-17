package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestHTTPAdmissionRestoredHundredCommitDrainRaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for iteration := range 100 {
			// each race owns a fresh run. the pointer captured while pending is
			// deliberately stale if capacity commits before drain selection.
			bound := newHTTPAdmissionTestRun(t, 1)
			wire := &httpAdmissionTestConn{}
			a, client := openHTTPAdmissionTest(t, bound, 0, wire)
			defer a.retire()
			defer client.Close()
			if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
				t.Fatal(err)
			}
			bound.mu.Lock()
			snapshot := a
			wasPending := snapshot.pendingLocked()
			bound.mu.Unlock()
			if !wasPending {
				t.Fatal("race did not capture a pending visitor")
			}
			start := make(chan struct{})
			committed, drained := make(chan error, 1), make(chan error, 1)
			var exchanges atomic.Int32
			go func() {
				<-start
				committed <- a.reserveCapacity(t.Context(), func(context.Context) error {
					exchanges.Add(1)
					return nil
				})
			}()
			until := time.Now().Add(5 * time.Second)
			go func() { <-start; drained <- bound.startDrain(until) }()
			close(start)
			err := <-committed
			if drainErr := <-drained; drainErr != nil {
				t.Fatal(drainErr)
			}
			bound.mu.Lock()
			pending := snapshot.pendingLocked()
			_, retiring := snapshot.state.(retiringHTTPAdmission)
			bound.mu.Unlock()
			if err == nil {
				if pending || retiring || wire.closes.Load() != 0 || exchanges.Load() != 1 {
					t.Fatal("drain selected a committed visitor through its stale pending snapshot", iteration, pending, retiring)
				}
				assertHTTPAdmissionCharges(t, a, 0, 0, 1)
			} else {
				if !errors.Is(err, ErrPrivateStream) || !pending || !retiring || exchanges.Load() != 0 || wire.closes.Load() != 1 {
					t.Fatal("drain retained or promoted an uncommitted setup", iteration, err, pending, retiring)
				}
				assertHTTPAdmissionCharges(t, a, 1, 1, 0)
			}
			_ = a.retire()
			_ = client.Close()
			if err := bound.joinDrain(); err != nil {
				t.Fatal("race did not join within its original drain bound", err)
			}
			assertHTTPAdmissionCharges(t, a, 0, 0, 0)
		}
	})
}

func TestHTTPAdmissionRestoredCancellationCloseAndDrainJoinPhysicalCleanup(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		for _, action := range []string{"cancel", "close", "drain"} {
			t.Run(fmt.Sprintf("admitted=%v/%s", admitted, action), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					bound := newHTTPAdmissionTestRun(t, 1)
					owner, cancelOwner := context.WithCancel(t.Context())
					defer cancelOwner()
					released := make(chan struct{})
					release := sync.OnceFunc(func() { close(released) })
					defer release()
					client, server := net.Pipe()
					defer client.Close()
					wire := &httpAdmissionTestConn{Conn: server, entered: make(chan struct{}), release: released}
					ref := bound.prepared.connectionRef(bound.connections[0])
					header := privateHeader(t, ref)
					header.PublicService.DestinationPort = 443
					visitor, code := bound.reserveHTTP(owner, ref, wire, header)
					if visitor == nil {
						t.Fatal(code)
					}
					a := visitor.http
					defer func() { release(); _ = a.retire() }()
					if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
						t.Fatal(err)
					}
					pending, sources, final := 1, 1, 0
					if admitted {
						if err := a.reserveCapacity(t.Context(), func(context.Context) error { return nil }); err != nil {
							t.Fatal(err)
						}
						pending, sources, final = 0, 0, 1
					}
					// observe entry before sync.Once contention; a held physical
					// close makes mutex waiters unsuitable for synctest.Wait.
					closing := make(chan struct{}, 8)
					cancel := a.cancel
					a.cancel = func() { cancel(); closing <- struct{}{} }
					stopped := make(chan error, 1)
					switch action {
					case "cancel":
						cancelOwner()
						go func() { <-a.ownerDone; stopped <- nil }()
					case "close":
						go func() { stopped <- visitor.Close() }()
					case "drain":
						go func() { stopped <- bound.startDrain(time.Now().Add(5 * time.Second)) }()
						if admitted {
							// drain retains ready visitors; their actual owner
							// closes independently rather than faking expiry.
							if err := <-stopped; err != nil {
								t.Fatal(err)
							}
							go func() { stopped <- visitor.Close() }()
						}
					}
					<-wire.entered
					<-closing
					concurrent := make(chan error, 1)
					retired := make(chan error, 1)
					go func() { concurrent <- visitor.Close() }()
					go func() { retired <- a.retire() }()
					<-closing
					<-closing
					if err := a.reserveCapacity(t.Context(), func(context.Context) error {
						t.Error("retiring visitor entered another ingress exchange")
						return nil
					}); err == nil {
						t.Fatal("capacity committed after physical close started")
					}
					assertHTTPAdmissionCharges(t, a, pending, sources, final)
					for _, result := range []<-chan error{stopped, concurrent, retired} {
						select {
						case <-result:
							t.Fatal("close/retirement returned before actual physical cleanup")
						default:
						}
					}
					select {
					case <-a.completed:
						t.Fatal("held physical cleanup released its permit")
					default:
					}
					release()
					for _, result := range []<-chan error{stopped, concurrent, retired} {
						if err := <-result; !httpAdmissionRoutineError(err) {
							t.Fatal("joined physical cleanup failed", err)
						}
					}
					if wire.closes.Load() != 1 {
						t.Fatal("concurrent retirement closed the physical visitor more than once")
					}
					assertHTTPAdmissionCharges(t, a, 0, 0, 0)
				})
			})
		}
	}
}

func TestHTTPAdmissionRestoredExpiredAndHundredMillisecondDrainFence(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("admitted=%v/expired=%v", admitted, expired), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					bound := newHTTPAdmissionTestRun(t, 1)
					released := make(chan struct{})
					release := sync.OnceFunc(func() { close(released) })
					defer release()
					wire := &httpAdmissionTestConn{release: released}
					a, client := openHTTPAdmissionTest(t, bound, 0, wire)
					defer client.Close()
					defer func() { release(); _ = a.retire() }()
					if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
						t.Fatal(err)
					}
					pending, sources, final := 1, 1, 0
					if admitted {
						if err := a.reserveCapacity(t.Context(), func(context.Context) error { return nil }); err != nil {
							t.Fatal(err)
						}
						pending, sources, final = 0, 0, 1
					}
					until := time.Now().Add(100 * time.Millisecond)
					if expired {
						until = time.Now().Add(-time.Second)
					}
					started := make(chan error, 1)
					go func() { started <- bound.startDrain(until) }()
					if admitted {
						if err := <-started; err != nil {
							t.Fatal(err)
						}
						go func() { started <- a.close() }()
					}
					<-wire.entered
					joined := make(chan error, 1)
					go func() { joined <- bound.joinDrain() }()
					// spend the original deadline, not a fresh timeout per phase.
					// these are fake-clock sleeps, not 100 real race sleeps.
					if !expired {
						time.Sleep(100 * time.Millisecond)
					}
					// advance the clock before introducing a sync.Once mutex
					// waiter; a held mutex cannot establish bubble quiescence.
					synctest.Wait()
					closing := make(chan struct{}, 2)
					cancel := a.cancel
					a.cancel = func() { cancel(); closing <- struct{}{} }
					concurrent := make(chan error, 1)
					go func() { concurrent <- a.visitor.Close() }()
					<-closing
					assertHTTPAdmissionCharges(t, a, pending, sources, final)
					for _, result := range []<-chan error{started, joined, concurrent} {
						select {
						case <-result:
							t.Fatal("deadline or concurrent close skipped held physical cleanup")
						default:
						}
					}
					if !bound.drainUntil.Equal(until) {
						t.Fatal("held cleanup restarted the fixed drain deadline")
					}
					release()
					if err := <-started; err != nil {
						t.Fatal(err)
					}
					if err := <-concurrent; err != nil {
						t.Fatal(err)
					}
					_ = a.retire()
					if err := <-joined; !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("joined drain lost its original expired/100ms fence", err)
					}
					assertHTTPAdmissionCharges(t, a, 0, 0, 0)
				})
			})
		}
	}
}

func TestServiceHTTPRestoredDrainJoinsAdmittedTLSClose(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	v := f.mustOpen(t, 0, pendingHTTPSource(0))
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	defer release()
	v.wire.holdCleanup(released)
	pendingHTTPResponse(t, v.request(t, "/"), http.StatusNoContent)
	// a reserved response on the same TLS socket joins the application guard.
	pendingHTTPResponse(t, v.request(t, "/__tnl/tls-close-barrier"), http.StatusNotFound)
	if err := v.secure.Close(); err != nil {
		t.Fatal("real visitor TLS close failed", err)
	}
	claimedAwait(t, v.wire.entered)
	until := time.Now().Add(100 * time.Millisecond)
	if err := f.source.bound.startDrain(until); err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- f.source.bound.joinDrain() }()
	// this real timer observes the original 100ms drain fence. it is not a
	// readiness sleep and cannot turn a canceled wait into a cleanup release.
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	<-timer.C
	assertHTTPAdmissionCharges(t, v.admission, 0, 0, 1)
	select {
	case <-joined:
		t.Fatal("drain returned before admitted TLS physical cleanup joined")
	case <-v.admission.completed:
		t.Fatal("TLS close released its unjoined visitor-connection permit")
	default:
	}
	release()
	v.join(t)
	if err := claimedAwait(t, joined); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("real TLS drain lost its original bound", err)
	}
	assertHTTPAdmissionCharges(t, v.admission, 0, 0, 0)
	if v.wire.physical.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("TLS close repeated physical close or authenticated ingress capacity")
	}
}

func TestServiceHTTPRestoredRetirementJoinsEnteredRequestHandler(t *testing.T) {
	entered, canceled, released, returned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	defer release()
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-released
		w.WriteHeader(http.StatusNoContent)
	}))
	v := f.mustOpen(t, 0, pendingHTTPSource(0))
	if err := v.handshake(t, false); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(f.ctx, http.MethodGet, "https://"+f.source.prepared.managedHostname+"/held", nil)
	request.Header.Set("Authorization", "Bearer unchanged-application")
	requested := make(chan error, 1)
	go func() {
		err := request.Write(v.secure)
		if err == nil {
			var response *http.Response
			response, err = http.ReadResponse(v.reader, request)
			if response != nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
		}
		requested <- err
	}()
	t.Cleanup(func() { release(); v.close(); claimedAwait(t, requested) })
	claimedAwait(t, entered)
	f.current[0].cancel()
	claimedAwait(t, canceled)
	claimedAwait(t, v.wire.done)
	assertHTTPAdmissionCharges(t, v.admission, 0, 0, 1)
	select {
	case <-v.admission.completed:
		t.Fatal("visitor connection retired while its entered request handler remained active")
	case <-returned:
		t.Fatal("fixture did not actually hold request-handler cleanup")
	default:
	}
	if f.capacity.Load() != 1 {
		t.Fatal("held handler did not own authenticated connection capacity")
	}
	release()
	claimedAwait(t, returned)
	v.join(t)
	assertHTTPAdmissionCharges(t, v.admission, 0, 0, 0)
}

func TestServiceHTTPRestoredEightPermissionsOneConnectionCapacity(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(httpaccess.VisitorTokenHeader) != "" {
					t.Error("per-request visitor permission reached the application")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			update := f.source.update
			update.Anonymous = false
			update.View.VisitorPolicyRevision++
			now := time.Now()
			update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
			if err := f.source.prepared.policy.Apply(f.source.prepared.policy.Begin(), update); err != nil {
				t.Fatal(err)
			}
			token := sourcePolicyPermission(t, f)
			var checks atomic.Int32
			visitor := f.source.prepared.managedVisitor
			f.source.prepared.managedVisitor = func(header tunnelv1.ServiceForwardingHeader, source netip.AddrPort, reserve func(context.Context) error) servicestream.Authentication {
				// retain the configured public frontend, including its real policy
				// authorizer. only add the old per-request admission observation.
				public, ok := visitor(header, source, reserve).(servicestream.HTTPVisitor)
				if !ok {
					t.Error("eight-request fixture lost its public HTTP visitor")
					return nil
				}
				frontend, ok := public.Frontend.(HTTP)
				if !ok {
					t.Error("eight-request fixture lost its configured service HTTP frontend")
					return nil
				}
				frontend.AdmitRequest = func(*http.Request) error { checks.Add(1); return nil }
				public.Frontend = frontend
				return public
			}
			v := f.mustOpen(t, 0, pendingHTTPSource(0))
			if _, err := v.raw.Write(f.metadata(t, v.header, v.source, false)); err != nil {
				t.Fatal(err)
			}
			verification := f.source.verification.Clone()
			verification.NextProtos = []string{"http/1.1"}
			if h2 {
				verification.NextProtos = []string{"h2"}
			}
			v.secure = tls.Client(v.raw, verification)
			if err := v.secure.HandshakeContext(f.ctx); err != nil {
				t.Fatal(err)
			}
			protocol := verification.NextProtos[0]
			if v.secure.ConnectionState().NegotiatedProtocol != protocol {
				t.Fatal("eight-request workload negotiated the wrong HTTP protocol")
			}
			v.reader = bufio.NewReader(v.secure)
			var roundTrip func(*http.Request) (*http.Response, error)
			if h2 {
				client := compositionHTTP2Connection(t, f.ctx, v.secure, f.source.prepared.managedHostname)
				defer func() { v.close(); _ = client.Close() }()
				roundTrip = client.RoundTrip
			} else {
				roundTrip = func(request *http.Request) (*http.Response, error) {
					if err := request.Write(v.secure); err != nil {
						return nil, err
					}
					return http.ReadResponse(v.reader, request)
				}
			}
			before := f.current[0].wire.openings.Load()
			results := make(chan error, 8)
			visit := func(index int) {
				request, err := http.NewRequestWithContext(f.ctx, http.MethodGet,
					fmt.Sprintf("https://%s/%d", f.source.prepared.managedHostname, index), nil)
				if err == nil {
					request.Header.Set("Authorization", "Bearer unchanged-application")
					request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
					var response *http.Response
					response, err = roundTrip(request)
					if response != nil {
						_, readErr := io.Copy(io.Discard, response.Body)
						err = errors.Join(err, readErr, response.Body.Close())
						if response.StatusCode != http.StatusNoContent {
							err = errors.Join(err, fmt.Errorf("request %d: status %d", index, response.StatusCode))
						}
					}
				}
				results <- err
			}
			for index := range 8 {
				if h2 {
					go visit(index)
				} else {
					visit(index)
				}
			}
			for range 8 {
				if err := claimedAwait(t, results); err != nil {
					t.Fatal("connection capacity was charged per request", err)
				}
			}
			assertHTTPAdmissionCharges(t, v.admission, 0, 0, 1)
			if checks.Load() != 8 || f.calls.Load() != 8 || f.capacity.Load() != 1 ||
				f.current[0].wire.openings.Load()-before != 1 {
				t.Fatal("connection capacity cached request admission or repeated the authenticated exchange",
					checks.Load(), f.calls.Load(), f.capacity.Load(), f.current[0].wire.openings.Load()-before)
			}
			extra := f.mustOpen(t, 1, netip.MustParseAddr("198.51.100.1"))
			if err := extra.handshake(t, false); err != nil {
				t.Fatal(err)
			}
			pendingHTTPResponse(t, sourcePolicyRequest(t, extra, "/overflow", token), http.StatusServiceUnavailable)
			extra.close()
			extra.join(t)
			assertHTTPAdmissionCharges(t, v.admission, 0, 0, 1)
			if f.calls.Load() != 8 || f.capacity.Load() != 1 {
				t.Fatal("idle admitted connection surrendered capacity to another visitor")
			}
			// the admitted socket is not a cached permission: a ninth request
			// on that same connection must still fail local authorization.
			request, _ := http.NewRequestWithContext(f.ctx, http.MethodGet,
				"https://"+f.source.prepared.managedHostname+"/invalid-permission", nil)
			request.Header.Set("Authorization", "Bearer unchanged-application")
			request.Header.Set(httpaccess.VisitorTokenHeader, "invalid")
			response, err := roundTrip(request)
			if err != nil {
				t.Fatal("same-connection permission probe did not receive a denial", err)
			}
			pendingHTTPResponse(t, response, http.StatusForbidden)
			if f.calls.Load() != 8 || f.capacity.Load() != 1 {
				t.Fatal("connection capacity bypassed a later request's permission check")
			}
			v.close()
			v.join(t)
			assertHTTPAdmissionCharges(t, v.admission, 0, 0, 0)
		})
	}
}
