package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type connectorGuardAdmission struct {
	until   time.Time
	err     error
	checked chan struct{}
	once    sync.Once
}

func (a *connectorGuardAdmission) CheckUse(ctx context.Context) (time.Time, error) {
	a.once.Do(func() { close(a.checked) })
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return a.until, a.err
}

func (*connectorGuardAdmission) SetupDeadline() time.Time { return time.Now().Add(time.Second) }
func (*connectorGuardAdmission) FinishSetup() error       { return nil }
func (*connectorGuardAdmission) Stop()                    {}

func TestConnectorVisitorGuardChecksCurrentAdmissionBeforeCachedDeadline(t *testing.T) {
	for _, test := range []struct {
		name            string
		current, cached time.Duration
		err             error
		live            bool
	}{
		{"renewed admission", time.Minute, -time.Second, nil, true},
		{"expired admission", -time.Second, time.Minute, nil, false},
		{"revoked admission", time.Minute, time.Minute, ErrEndpoint, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			admission := &connectorGuardAdmission{until: now.Add(test.current), err: test.err, checked: make(chan struct{})}
			stream := ServiceStream{Visitor: ConnectorVisitor{Admission: admission}}
			client, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				defer close(done)
				stream.guardVisitor(ctx, client, nil, tls.ConnectionState{}, ServiceVisitorDecision{Allowed: true, ValidUntil: now.Add(test.cached)})
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("visitor guard did not join")
				}
			})
			select {
			case <-admission.checked:
			case <-done:
				select {
				case <-admission.checked:
				default:
					t.Fatal("cached deadline closed the stream without checking current admission")
				}
			case <-time.After(time.Second):
				t.Fatal("visitor guard did not check current admission")
			}
			if test.live {
				select {
				case <-done:
					t.Fatal("cached deadline stopped a renewed admission")
				default:
				}
			} else {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("current admission denial did not stop the stream")
				}
			}
		})
	}
}

func TestCertificateVisitorGuardKeepsExpiredDecisionFence(t *testing.T) {
	var checks atomic.Int64
	stream := ServiceStream{Visitor: CertificateVisitor{Check: func(context.Context, *x509.Certificate) (ServiceVisitorDecision, error) {
		checks.Add(1)
		return ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
	}}}
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream.guardVisitor(t.Context(), client, nil, tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}, ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(-time.Second)})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("certificate visitor outlived its last confirmed deadline")
	}
	if checks.Load() != 0 {
		t.Fatal("certificate visitor refreshed an already expired decision")
	}
}

type delayedConnectorGuardAdmission struct {
	mu      sync.Mutex
	until   time.Time
	err     error
	checked chan struct{}
	release chan struct{}
	first   sync.Once
	checks  atomic.Int64
}

func (a *delayedConnectorGuardAdmission) CheckUse(context.Context) (time.Time, error) {
	a.checks.Add(1)
	a.mu.Lock()
	until, err := a.until, a.err
	a.mu.Unlock()
	a.first.Do(func() { close(a.checked); <-a.release })
	return until, err
}
func (*delayedConnectorGuardAdmission) SetupDeadline() time.Time { return time.Now().Add(time.Second) }
func (*delayedConnectorGuardAdmission) FinishSetup() error       { return nil }
func (*delayedConnectorGuardAdmission) Stop()                    {}

func TestConnectorVisitorGuardRechecksDeadlineSupersededDuringObservation(t *testing.T) {
	for _, state := range []string{"renewed", "expired", "revoked"} {
		t.Run(state, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				admission := &delayedConnectorGuardAdmission{until: time.Now().Add(time.Second), checked: make(chan struct{}), release: make(chan struct{})}
				stream := ServiceStream{Visitor: ConnectorVisitor{Admission: admission}}
				client, peer := net.Pipe()
				defer peer.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan struct{})
				go func() {
					defer close(done)
					stream.guardVisitor(ctx, client, nil, tls.ConnectionState{}, ServiceVisitorDecision{})
				}()
				<-admission.checked
				// pause after the admission was checked, then let renewal or revocation
				// overtake that observation before the guard consumes its deadline.
				admission.mu.Lock()
				if state != "expired" {
					admission.until = time.Now().Add(time.Minute)
				}
				if state == "revoked" {
					admission.err = ErrEndpoint
				}
				admission.mu.Unlock()
				time.Sleep(2 * time.Second)
				close(admission.release)
				synctest.Wait()
				if admission.checks.Load() != 2 {
					t.Fatal("elapsed observation was not rechecked exactly once")
				}
				if state == "renewed" {
					select {
					case <-done:
						t.Fatal("superseded observation closed a renewed admission")
					default:
					}
					// retaining the stream must not turn its next current denial into
					// another cached permission or lend it a sibling's authority.
					admission.mu.Lock()
					admission.err = ErrEndpoint
					admission.mu.Unlock()
					time.Sleep(30 * time.Second)
					synctest.Wait()
				}
				select {
				case <-done:
				default:
					t.Fatal("current denial or unchanged expiry did not close the stream")
				}
			})
		})
	}
}
