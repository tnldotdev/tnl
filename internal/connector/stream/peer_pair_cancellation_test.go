package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorPairRenewalPreservesContextAtResponseValidation(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	pair, _, _, _, err := prepareConnectorPair(t.Context(), f, f.device, f.run, "renewal-owner")
	if err != nil {
		t.Fatal(err)
	}
	body, err := connectorPairRequest(f.device, f.run, "renewal-owner", &pair)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := f.RenewConnectorPeerPair(t.Context(), f.run.ServiceID, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				control := renewalControl{renew: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
					if !deadline {
						cancel()
					}
					<-ctx.Done()
					return reply, nil
				}}
				renewed, until, err := renewConnectorPair(ctx, control, f.device, f.run, "renewal-owner", pair)
				want := context.Canceled
				if deadline {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) || !until.IsZero() || !reflect.DeepEqual(renewed, controlv1.ConnectorPeerPairRenewal{}) {
					t.Fatal("late response lost its context or returned authority", err)
				}
				if deadline && !connectorTemporary(err) {
					t.Fatal("call deadline became terminal while retained authority was live", err)
				}
			})
		})
	}
}

func TestConnectorRefreshLateResponseRetainsAuthorityAndApplication(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			var calls atomic.Int64
			second, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			config := f.config
			config.Control = renewalControl{Control: f, renew: func(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
				switch calls.Add(1) {
				case 1:
					reply, err := f.RenewConnectorPeerPair(ctx, service, body)
					<-ctx.Done()
					return reply, err
				case 2:
					close(second)
					select {
					case <-release:
					case <-ctx.Done():
						return controlv1.ConnectorPeerPairRenewal{}, context.Cause(ctx)
					}
				}
				return f.RenewConnectorPeerPair(ctx, service, body)
			}}
			setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
			defer stop()
			p, err := prepareConnectorConnection(t.Context(), setup, config, f.device)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			local, app := net.Pipe()
			defer app.Close()
			joined := make(chan struct{})
			go func() { defer close(joined); _ = p.Forward(t.Context(), local) }()
			defer func() { _ = app.Close(); p.Close(); <-joined }()
			exchange := func(message string) {
				t.Helper()
				_ = app.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.WriteString(app, message); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(message))
				if _, err := io.ReadFull(app, got); err != nil || string(got) != message {
					t.Fatal("late renewal changed the retained stream", err)
				}
			}
			exchange("before")
			inner, endpoint, permissions, owner, opened := p.connection, p.endpoint, p.permissions, p.owner, f.opened.Load()
			p.mu.Lock()
			until, prepared, run, permission, changed := p.until, p.preparedUntil, p.run.ValidUntil, p.permission.ExpiresAt, p.changed
			p.mu.Unlock()
			select {
			case <-second:
			case <-p.ctx.Done():
				t.Fatal("late pair response terminated current authority", context.Cause(p.ctx))
			case <-time.After(6 * time.Second):
				t.Fatal("refresh did not continue after the call deadline")
			}
			p.mu.Lock()
			unchanged := until.Equal(p.until) && prepared.Equal(p.preparedUntil) && run.Equal(p.run.ValidUntil) && permission.Equal(p.permission.ExpiresAt)
			p.mu.Unlock()
			if !unchanged {
				t.Fatal("late response changed the original authority deadlines")
			}
			exchange("after-late-response")
			unblock()
			select {
			case <-changed:
			case <-p.ctx.Done():
				t.Fatal("current renewal failed", context.Cause(p.ctx))
			case <-time.After(3 * time.Second):
				t.Fatal("current renewal did not install")
			}
			exchange("after-recovery")
			if p.connection != inner || p.endpoint != endpoint || p.permissions != permissions || p.owner != owner || f.opened.Load() != opened {
				t.Fatal("renewal replaced inner ownership or the application stream")
			}
		})
	}
}
