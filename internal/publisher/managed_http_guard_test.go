package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type httpGuardControl struct {
	ManagedHTTPControl
	check func(context.Context) (controlv1.ServiceClientCertificateDecision, error)
}

func TestManagedHTTPGuardOnlyToleratesStructuredUnavailability(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		keep bool
	}{
		{"unavailable", controlclient.ErrUnavailable, true},
		{"unauthenticated", controlclient.ErrUnauthenticated, false},
		{"forbidden", &controlclient.ProblemError{Status: 403}, false},
		{"invalid response", errors.New("invalid authority response"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := newManagedHTTPGuard(ManagedHTTP{Control: httpGuardControl{check: func(context.Context) (controlv1.ServiceClientCertificateDecision, error) {
				return controlv1.ServiceClientCertificateDecision{}, test.err
			}}}, nil)
			until := time.Now().Add(time.Minute)
			g.update(controlv1.ManagedHTTPCredential{Kind: "browser"}, controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: until})
			if got := g.recheck(t.Context(), g.credential, g.revision); got != test.keep {
				t.Fatalf("keep=%t, want %t", got, test.keep)
			}
			if !g.decision.ValidUntil.Equal(until) {
				t.Fatal("failure moved the last successful deadline")
			}
		})
	}
}

func TestManagedHTTPGuardRotationDiscardsOldInFlightDeadline(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	var calls atomic.Int32
	until := time.Now().Add(2 * time.Second)
	control := httpGuardControl{check: func(ctx context.Context) (controlv1.ServiceClientCertificateDecision, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return controlv1.ServiceClientCertificateDecision{}, context.Cause(ctx)
		}
		return controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: until}, nil
	}}
	g := newManagedHTTPGuard(ManagedHTTP{Control: control}, tls.Server(raw, &tls.Config{}))
	oldExpiry := time.Now().Add(150 * time.Millisecond)
	g.update(controlv1.ManagedHTTPCredential{Kind: "workload", Secret: new("old")}, controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: oldExpiry})
	done := make(chan struct{})
	go func() { defer close(done); g.run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("guard did not recheck old credential")
	}
	g.update(controlv1.ManagedHTTPCredential{Kind: "workload", Secret: new("new")}, controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: until})
	_ = peer.SetReadDeadline(oldExpiry.Add(100 * time.Millisecond))
	var one [1]byte
	_, err := peer.Read(one[:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("old in-flight deadline closed a rotated connection", err)
	}
}

func (c httpGuardControl) AuthorizeManagedHTTPVisitor(ctx context.Context, _, _ string, _ credentials.PublishRunToken, _ controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return c.check(ctx)
}

func TestManagedHTTPGuardClosesIdleConnectionAndNeverExtendsOnFailure(t *testing.T) {
	for _, mode := range []string{"revoked", "unavailable", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			peer, raw := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control := httpGuardControl{check: func(ctx context.Context) (controlv1.ServiceClientCertificateDecision, error) {
				if mode == "revoked" {
					return controlv1.ServiceClientCertificateDecision{}, nil
				}
				if mode == "blocked" {
					<-ctx.Done()
				}
				return controlv1.ServiceClientCertificateDecision{}, controlclient.ErrUnavailable
			}}
			g := newManagedHTTPGuard(ManagedHTTP{Control: control}, tls.Server(raw, &tls.Config{}))
			expiry := time.Now().Add(150 * time.Millisecond)
			g.update(controlv1.ManagedHTTPCredential{Kind: "certificate", Certificate: new([]byte("workload certificate"))}, controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: expiry})
			done := make(chan struct{})
			go func() { defer close(done); g.run(ctx) }()
			defer func() { cancel(); <-done }()
			_ = peer.SetReadDeadline(expiry.Add(time.Second))
			if _, err := io.Copy(io.Discard, peer); err != nil {
				t.Fatal("idle guard did not close by saved deadline", err)
			}
			if time.Now().After(expiry.Add(100 * time.Millisecond)) {
				t.Fatal("failed authorization extended expiry")
			}
		})
	}
}

func TestManagedHTTPGuardQueuedRotationKeepsCancellationAndSavedDeadline(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	var calls atomic.Int32
	control := httpGuardControl{check: func(ctx context.Context) (controlv1.ServiceClientCertificateDecision, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-ctx.Done()
		return controlv1.ServiceClientCertificateDecision{}, context.Cause(ctx)
	}}
	g := newManagedHTTPGuard(ManagedHTTP{Control: control}, tls.Server(raw, &tls.Config{}))
	expiry := time.Now().Add(300 * time.Millisecond)
	g.update(controlv1.ManagedHTTPCredential{Kind: "workload", Secret: new("old")}, controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: expiry})
	done := make(chan struct{})
	go func() { defer close(done); g.run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background request did not start")
	}
	check, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	defer stop()
	if _, err := g.authorize(check, controlv1.ManagedHTTPCredential{Kind: "workload", Secret: new("new")}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("queued foreground authorization ignored cancellation", err)
	}
	if calls.Load() != 1 {
		t.Fatal("foreground control call overlapped a background mutation")
	}
	_ = peer.SetReadDeadline(expiry.Add(time.Second))
	if _, err := io.Copy(io.Discard, peer); err != nil {
		t.Fatal("queued rotation kept an unauthorized connection open", err)
	}
	if time.Now().After(expiry.Add(100 * time.Millisecond)) {
		t.Fatal("serialization extended the saved deadline")
	}
}
