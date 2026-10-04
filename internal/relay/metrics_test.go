package relay

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
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
			if labels["operation"] == operation && labels["outcome"] == outcome {
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
	controller := &Controller{client: failingMetricControl{}, observer: metrics, load: func() (int64, int64) { return 0, 0 }}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := controller.register(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("register: %v", err)
	}
	if err := controller.renew(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("renew: %v", err)
	}
	assertRelayOperation(t, metrics, "RelayRegister", "canceled", 1)
	assertRelayOperation(t, metrics, "RelayRenewLease", "deadline_exceeded", 1)
	// unknown or dynamic names must not create cardinality from user input.
	metrics.ObserveOperation("route-private-id", nil, time.Second)
	assertRelayOperation(t, metrics, "route-private-id", "success", 0)
}

func TestForwardingAcceptorReportsStreamCapacity(t *testing.T) {
	secrets, err := serviceapi.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	var deltas []int
	rejections := 0
	acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{
		Registry: NewRegistry(), CurrentLease: func() relayv1.RelayLease { return relayv1.RelayLease{} },
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
	rejections := 0
	acceptor := &PublisherAcceptor{capacity: func() { rejections++ }}
	code := acceptor.controlErrorCode(&ControlProblemError{Problem: &relayv1.Problem{
		Code: relayv1.RelayConnectionCapacityExhausted,
	}})
	if code != tunnelv1.CapacityExceeded || rejections != 1 {
		t.Fatalf("capacity error: code=%s rejections=%d", code, rejections)
	}
	code = acceptor.controlErrorCode(&ControlProblemError{Problem: &relayv1.Problem{
		Code: relayv1.StaleConnectionAssignment,
	}})
	if code != tunnelv1.StaleConnectionAssignment || rejections != 1 {
		t.Fatalf("non-capacity error: code=%s rejections=%d", code, rejections)
	}
}

func TestPublisherAcceptorPreservesControlErrorBehindProtocolCode(t *testing.T) {
	cause := errors.New("control request failed")
	acceptor := &PublisherAcceptor{capacity: func() {}}
	err := acceptor.controlError(cause)
	var protocolError *tunnel.ProtocolError
	if !errors.Is(err, cause) || !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.Internal {
		t.Fatalf("control error = %v", err)
	}
}

func TestRegisteredPublisherGaugeTracksReplacementAndClose(t *testing.T) {
	metrics := observability.New("relay")
	registry := NewRegistry()
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
	first, _ := publisherFixture(t, "connection_1", 3)
	second, _ := publisherFixture(t, "connection_2", 4)
	if err := registry.Insert(first); err != nil {
		t.Fatal(err)
	}
	assertRegistered(1)
	if err := registry.Insert(second); err != nil {
		t.Fatal(err)
	}
	assertRegistered(1) // replacing one slot never creates a second registration.
	if registry.Remove(first) {
		t.Fatal("old publisher connection removed the replacement")
	}
	if !registry.Remove(second) {
		t.Fatal("replacement not removed")
	}
	assertRegistered(0)
}
