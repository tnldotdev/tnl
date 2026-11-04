package stream

import (
	"context"
	"io"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type renewalControl struct {
	Control
	renew func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error)
}

func (c renewalControl) RenewConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
	return c.renew(ctx, service, body)
}

func TestConnectorRefreshRenewsPinnedPairWithoutReselectionOrPermissionRPC(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	var selections, permissions, renewals atomic.Int64
	control, err := NewControlWithConfig(ControlConfig{Signer: f.ConnectorSigner, Pair: f.PrepareConnectorPeerPair,
		Resolve: func(ctx context.Context, service string) (Run, error) {
			if selections.Add(1) != 1 {
				return Run{}, ErrServiceConnection
			}
			return f.ResolveService(ctx, service)
		},
		Permission: func(ctx context.Context, service string) (controlv1.VisitorTokenResponse, error) {
			if permissions.Add(1) != 1 {
				return controlv1.VisitorTokenResponse{}, ErrServiceConnection
			}
			return f.VisitorPermission(ctx, service)
		},
		RenewPair: func(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
			renewals.Add(1)
			return f.RenewConnectorPeerPair(ctx, service, body)
		}, Close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	config := f.config
	config.Control = control
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareConnectorConnection(t.Context(), setup, config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.mu.Lock()
	// the same publisher report must not recover time already spent by its
	// first observation, even when the later control reply has less transit.
	p.preparedUntil = p.preparedUntil.Add(-time.Second)
	installation, pair, changed := p.preparedUntil, p.pair, p.changed
	p.mu.Unlock()
	select {
	case <-changed:
	case <-p.ctx.Done():
		t.Fatal("renewal required a separate selection or permission RPC", context.Cause(p.ctx))
	case <-time.After(3 * time.Second):
		t.Fatal("pair renewal did not publish its coherent authority")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if selections.Load() != 1 || permissions.Load() != 1 || renewals.Load() != 1 || p.pair.PairId != pair.PairId || p.pair.Key != pair.Key {
		t.Fatal("refresh reselected authority or changed the pinned pair")
	}
	if p.preparedUntil.After(installation) {
		t.Fatal("pair renewal extended an unchanged publisher installation report")
	}
}

func TestConnectorPairRenewalRepeatsExactProofAndSpendsTransit(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	pair, _, _, _, err := prepareConnectorPair(t.Context(), f, f.device, f.run, "renewal-owner")
	if err != nil {
		t.Fatal(err)
	}
	var first controlv1.ConnectorPeerPairRequest
	var calls int
	var reply controlv1.ConnectorPeerPairRenewal
	var lastCall time.Time
	control := renewalControl{renew: func(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
		calls++
		if calls == 1 {
			first = body
			reply, err = f.RenewConnectorPeerPair(ctx, service, body)
			if err != nil {
				return reply, err
			}
			return controlv1.ConnectorPeerPairRenewal{}, io.ErrUnexpectedEOF
		}
		if !reflect.DeepEqual(first, body) {
			t.Fatal("uncertain renewal re-signed or changed its original request")
		}
		lastCall = time.Now()
		return reply, nil
	}}
	_, until, err := renewConnectorPair(t.Context(), control, f.device, f.run, "renewal-owner", pair)
	if err != nil || calls != 2 {
		t.Fatal("uncertain renewal did not recover its committed result", err)
	}
	interval := reply.Pair.ExpiresAt.Sub(reply.Pair.ObservedAt)
	if until.After(lastCall.Add(interval - 90*time.Millisecond)) {
		t.Fatal("renewal retry recovered transit time instead of spending the original interval")
	}
}

func TestConnectorPairRenewalUsesShiftedAuthorityClock(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	pair, _, _, _, err := prepareConnectorPair(t.Context(), f, f.device, f.run, "renewal-owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, shift := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(shift.String(), func(t *testing.T) {
			var reply controlv1.ConnectorPeerPairRenewal
			control := renewalControl{renew: func(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
				reply, err = f.RenewConnectorPeerPair(ctx, service, body)
				if err != nil {
					return reply, err
				}
				reply.Pair.ObservedAt = time.Now().Add(shift)
				reply.Pair.ExpiresAt = reply.Pair.ObservedAt.Add(time.Minute)
				reply.Pair.PublisherPreparedUntil = new(reply.Pair.ObservedAt.Add(50 * time.Second))
				reply.RunValidUntil = reply.Pair.ObservedAt.Add(40 * time.Second)
				reply.VisitorPermission.ExpiresAt = reply.Pair.ObservedAt.Add(30 * time.Second)
				return reply, nil
			}}
			before := time.Now()
			renewed, until, err := renewConnectorPair(t.Context(), control, f.device, f.run, "renewal-owner", pair)
			if err != nil {
				t.Fatal("live authority interval was compared with the local wall clock", err)
			}
			if !reflect.DeepEqual(renewed, reply) {
				t.Fatal("deadline validation changed the authority response or signed token bytes")
			}
			permissionUntil := until.Add(renewed.VisitorPermission.ExpiresAt.Sub(renewed.Pair.ExpiresAt))
			if !permissionUntil.After(before.Add(29*time.Second)) || permissionUntil.After(time.Now().Add(30*time.Second)) {
				t.Fatal("renewal did not anchor the permission interval to local request start")
			}
		})
	}
}

func TestConnectorPairRenewalRejectsPermissionIntervalSpentInTransit(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	pair, _, _, _, err := prepareConnectorPair(t.Context(), f, f.device, f.run, "renewal-owner")
	if err != nil {
		t.Fatal(err)
	}
	control := renewalControl{renew: func(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
		reply, err := f.RenewConnectorPeerPair(ctx, service, body)
		reply.Pair.ObservedAt = time.Now().Add(time.Hour)
		reply.Pair.ExpiresAt = reply.Pair.ObservedAt.Add(time.Minute)
		reply.Pair.PublisherPreparedUntil = nil
		reply.RunValidUntil = reply.Pair.ExpiresAt
		reply.VisitorPermission.ExpiresAt = reply.Pair.ObservedAt.Add(100 * time.Millisecond)
		timer := time.NewTimer(150 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return controlv1.ConnectorPeerPairRenewal{}, context.Cause(ctx)
		case <-timer.C:
			return reply, err
		}
	}}
	if _, _, err := renewConnectorPair(t.Context(), control, f.device, f.run, "renewal-owner", pair); err == nil {
		t.Fatal("future authority timestamp revived a permission interval already spent in transit")
	}
}

func TestConnectorPairRenewalRejectsChangedBindingAndExpiredAuthority(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	pair, _, _, _, err := prepareConnectorPair(t.Context(), f, f.device, f.run, "renewal-owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []string{"service", "run", "run number", "publisher", "subject", "pair", "delivery", "generation", "key", "relay", "run expiry", "permission scope", "permission revision missing", "permission revision zero", "permission revision mismatch", "permission expiry", "permission extension", "installation extension"} {
		t.Run(boundary, func(t *testing.T) {
			control := renewalControl{renew: func(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
				reply, err := f.RenewConnectorPeerPair(ctx, service, body)
				reply.Pair.Relays = append([]controlv1.ConnectorPeerPairRelay(nil), reply.Pair.Relays...)
				switch boundary {
				case "service":
					reply.Pair.ServiceId = "different"
				case "run":
					reply.Pair.ServiceRunId = "different"
				case "run number":
					reply.Pair.RunNumber++
				case "publisher":
					reply.Pair.PublisherIdentityId = "different"
				case "subject":
					reply.Pair.Subject.DeviceId = new("different")
				case "pair":
					reply.Pair.PairId = "different"
				case "delivery":
					reply.Pair.DeliveryId = "AgICAgICAgICAgICAgICAg"
				case "generation":
					reply.Pair.DeliveryGeneration++
				case "key":
					reply.Pair.Key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
				case "relay":
					reply.Pair.Relays[0].AssignmentRevision++
				case "run expiry":
					reply.RunValidUntil = reply.Pair.ObservedAt
				case "permission scope":
					reply.VisitorPermission.Resource.Id = "different"
				case "permission revision missing":
					reply.VisitorPermission.ServiceTrustRevision = nil
				case "permission revision zero":
					reply.VisitorPermission.ServiceTrustRevision = new(int64(0))
				case "permission revision mismatch":
					reply.VisitorPermission.ServiceTrustRevision = new(reply.TrustRevision + 1)
				case "permission expiry":
					reply.VisitorPermission.ExpiresAt = reply.Pair.ObservedAt
				case "permission extension":
					reply.VisitorPermission.ExpiresAt = reply.Pair.ExpiresAt.Add(time.Second)
				case "installation extension":
					reply.Pair.PublisherPreparedUntil = new(reply.Pair.ExpiresAt.Add(time.Second))
				}
				return reply, err
			}}
			if _, _, err := renewConnectorPair(t.Context(), control, f.device, f.run, "renewal-owner", pair); err == nil {
				t.Fatal("renewal accepted changed or expired authority")
			}
		})
	}
}
