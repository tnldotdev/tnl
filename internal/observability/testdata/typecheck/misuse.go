package misuse

import (
	"context"

	"github.com/tnldotdev/tnl/internal/observability"
	"go.opentelemetry.io/otel/attribute"
)

func misuse(input string, status int) {
	key := observability.Component
	key = "tnl.request_id"                                                    // want compile error
	_ = key + input                                                           // want compile error
	_ = observability.Key("tnl.arbitrary").String(input)                      // want compile error
	_ = observability.HTTPStatus.String(input)                                // want compile error
	_ = observability.RequestID.Int(status)                                   // want compile error
	_ = observability.TLSResumed.String(input)                                // want compile error
	_ = observability.HTTPStatus.Bool(true)                                   // want compile error
	_ = observability.ServiceProtocol.Value(input)                            // want compile error
	_ = observability.Transport.Value(observability.ProtocolHTTP)             // want compile error
	_ = observability.OutcomeKey.Value(observability.StateReady)              // want compile error
	_ = observability.RoleKey.Value(input)                                    // want compile error
	_ = observability.Event.Value(observability.StateReady)                   // want compile error
	_ = observability.Fields{ServiceProtocol: input}                          // want compile error
	_ = observability.Protocol(input)                                         // want compile error
	_ = observability.TransportValue(input)                                   // want compile error
	_ = observability.Outcome(input)                                          // want compile error
	_ = observability.Role(input)                                             // want compile error
	_ = observability.RequestID.Dimension(input)                              // want compile error
	_ = observability.MetricOverflow.Dimension(true)                          // want compile error
	_ = []observability.MetricKey{observability.RequestID}                    // want compile error
	_ = []observability.MetricKey{observability.ServiceInstanceID}            // want compile error
	var _ observability.Dimension = attribute.String("tnl.request_id", input) // want compile error
	_, _ = observability.Start(context.Background(), input)                   // want compile error
	_ = observability.Operation.Value(input)                                  // want compile error
	_ = observability.InstrumentDefinition{Kind: "counter"}                   // want compile error
	_ = observability.AttributeDefinition{DimensionPolicy: "bounded"}         // want compile error
	var m *observability.Metrics
	_ = observability.InstrumentDefinition{Kind: observability.PolicyBounded} // want compile error
	m.ObserveDatabaseQuery(input, nil, 0)                                     // want compile error
}
