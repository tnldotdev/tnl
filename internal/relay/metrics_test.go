package relay

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func assertRelayOperation(t *testing.T, metrics *observability.Metrics, operation, outcome string, want uint64) {
	t.Helper()
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, family := range families {
		if family.GetName() != "tnl_relay_operation_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			labels := make(map[string]string)
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["tnl_operation"] == operation && labels["tnl_outcome"] == outcome {
				count += metric.GetHistogram().GetSampleCount()
			}
		}
	}
	if count != want {
		t.Fatalf("%s/%s count=%d want=%d", operation, outcome, count, want)
	}
}

type failingMetricControl struct{ ControlClient }

func (failingMetricControl) RegisterRelay(ctx context.Context, _ relayv1.RelayRegistration) (relayv1.RelayLease, error) {
	return relayv1.RelayLease{}, ctx.Err()
}

func (failingMetricControl) RenewRelay(context.Context, relayv1.RelayID, relayv1.RelayRenewal) (relayv1.RelayLease, error) {
	return relayv1.RelayLease{}, context.DeadlineExceeded
}

func TestRelayControlMetricsRecordCanceledAndTimedOutCalls(t *testing.T) {
	metrics := observability.New("relay")
	controller := &Controller{client: failingMetricControl{}, observer: metrics, now: time.Now, load: func() (int64, int64) { return 0, 0 }}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := controller.register(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("register: %v", err)
	}
	if err := controller.renew(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("renew: %v", err)
	}
	assertRelayOperation(t, metrics, "RelayRegister", "canceled", 1)
	assertRelayOperation(t, metrics, "RelayRenewLease", "timeout", 1)
	// unknown or dynamic names must not create cardinality from user input.
	metrics.ObserveOperationContext(t.Context(), observability.ServerOperation(255), nil, time.Second)
	assertRelayOperation(t, metrics, "route-private-id", "success", 0)
}

func TestForwardingAcceptorReportsStreamCapacity(t *testing.T) {
	secrets, err := serverhttp.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	var deltas []int
	rejections := 0
	acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{
		ServiceRegistry: NewServiceRegistry(), CurrentLease: func() relayv1.RelayLease { return relayv1.RelayLease{} },
		ClusterSecrets: secrets, StreamCapacity: 1,
		StreamsDelta:     func(delta int) { deltas = append(deltas, delta) },
		CapacityRejected: func() { rejections++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !acceptor.acquireStream() || acceptor.acquireStream() {
		t.Fatal("stream capacity admission did not enforce its limit")
	}
	acceptor.releaseStream()
	if len(deltas) != 2 || deltas[0] != 1 || deltas[1] != -1 || rejections != 1 {
		t.Fatalf("stream metrics: deltas=%v rejections=%d", deltas, rejections)
	}
}

func TestPublisherAcceptorReportsConnectionCapacity(t *testing.T) {
	for _, code := range []relayv1.ProblemCode{relayv1.RelayConnectionCapacityExhausted, relayv1.StaleConnectionAssignment} {
		client := &privateClaimControlStub{claimErr: &serverhttp.ProblemError{Status: 409, Type: "https://tnl.dev/p/claim", Code: string(code)}}
		rejections := 0
		acceptor, hello, _ := serviceAcceptorFixture(t, client, func(config *PublisherAcceptorConfig) {
			config.CapacityRejected = func() { rejections++ }
		})
		session, done, err := dialPrivateClaim(t, acceptor.Accept, hello)
		if session != nil || err == nil {
			t.Fatal("control rejection was accepted")
		}
		relayAwait(t, done)
		want := 0
		if code == relayv1.RelayConnectionCapacityExhausted {
			want = 1
		}
		if rejections != want {
			t.Fatalf("%s: capacity rejections=%d want=%d", code, rejections, want)
		}
	}
}

func TestPublisherAcceptorPreservesControlErrorBehindProtocolCode(t *testing.T) {
	cause := errors.New("control request failed")
	client := &privateClaimControlStub{claimErr: cause}
	acceptor, hello, _ := serviceAcceptorFixture(t, client, nil)
	_, done, err := dialPrivateClaim(t, acceptor.Accept, hello)
	if err == nil {
		t.Fatal("failed control call was accepted")
	}
	err = relayAwait(t, done)
	var protocolError *tunnel.ProtocolError
	if !errors.Is(err, cause) || !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.Unavailable {
		t.Fatalf("control error = %v", err)
	}
}

func TestRegisteredPublisherGaugeTracksReplacementAndClose(t *testing.T) {
	metrics := observability.New("relay")
	registry := NewServiceRegistry()
	registry.Instrument(metrics)
	t.Cleanup(func() { _ = registry.Close() })
	assertRegistered := func(want float64) {
		t.Helper()
		families, err := metrics.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() == "tnl_relay_publisher_connections_registered" {
				if got := family.Metric[0].GetGauge().GetValue(); got != want {
					t.Fatalf("registered=%g, want %g", got, want)
				}
				return
			}
		}
		t.Fatal("missing registered-connection gauge")
	}
	header := privateLifecycleHeader()
	first, _ := serviceConnectionFixture(t, header)
	header.PublisherConnectionID = "pc_bbbbbbbbbbbbbbbbbbbbbb"
	header.ConnectionAssignmentRevision++
	second, _ := serviceConnectionFixture(t, header)
	if err := registry.insert(first); err != nil {
		t.Fatal(err)
	}
	assertRegistered(1)
	if err := registry.insert(second); err != nil {
		t.Fatal(err)
	}
	assertRegistered(1) // replacing one slot never creates a second registration.
	if err := registry.remove(first); err != nil {
		t.Fatal(err)
	}
	if candidate, ok := registry.candidate(header, second.lease, time.Now()); !ok || candidate != second {
		t.Fatal("old publisher connection removed the replacement")
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	_ = registry.remove(second)
	assertRegistered(0)
}
