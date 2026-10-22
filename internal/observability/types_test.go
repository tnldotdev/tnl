package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// one compiler invocation checks misuse from outside the package. assertions are
// tied to every marked source line, not merely to the command's failure status.
func TestAttributeTypeBoundaryRejectsMisuse(t *testing.T) {
	const fixture = "testdata/typecheck/misuse.go"
	source, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-gcflags=github.com/tnldotdev/tnl/internal/observability/testdata/typecheck=-e", "./testdata/typecheck")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("invalid telemetry programs compiled")
	}
	for line, text := range strings.Split(string(source), "\n") {
		if strings.Contains(text, "// want compile error") && !bytes.Contains(output, fmt.Appendf(nil, "misuse.go:%d:", line+1)) {
			t.Errorf("missing compiler rejection at line %d:\n%s", line+1, output)
		}
	}
}

func TestTypedCatalogGenerationMatchesCommittedContract(t *testing.T) {
	want, err := os.ReadFile("../../api/observability/v1/vocabulary.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(SharedVocabulary(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Fatal("shared vocabulary differs; regenerate the owned contract")
	}
}

func TestTypedDimensionsRetainValuesAndRejectWrongInstrument(t *testing.T) {
	m := New("standalone")
	defer m.Shutdown(context.Background())
	counter := newCounter(m.meter, "tnl_type_boundary_total", "Type boundary fixture.", ServiceProtocol, Transport, OutcomeKey, HTTPStatus, TLSResumed)
	counter.With(ServiceProtocol.Dimension(ProtocolHTTP), Transport.Dimension(TransportQUIC), resultDimension("not_admitted"), HTTPStatus.Dimension(403), TLSResumed.Dimension(true)).Inc()
	text := metricsText(t, m)
	for _, want := range []string{`tnl_service_protocol="http"`, `tnl_transport="quic"`, `tnl_outcome="rejected"`, `tnl_reason="not_admitted"`, `http_response_status_code="403"`, `tls_resumed="true"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s: %s", want, text)
		}
	}
	for name, values := range map[string][]Dimension{
		"undeclared": {TeamID.Dimension("team")},
		"duplicate":  {OutcomeKey.Dimension(Success), OutcomeKey.Dimension(Error)},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid binding did not fail")
				}
			}()
			counter.With(values...).Inc()
		})
	}
}

func TestDynamicBoundariesRejectUnknownValuesBeforeNarrowing(t *testing.T) {
	for _, value := range []string{"", "HTTP", "secret", "http\nsecret"} {
		if protocol, ok := ParseProtocol(value); ok || protocol != 0 {
			t.Fatal(value, protocol)
		}
	}
	if value, ok := ParseTransport("tcp"); ok || value != 0 {
		t.Fatal("unapproved transport narrowed")
	}
	if value, ok := ParseRole("worker"); ok || value != 0 {
		t.Fatal("unapproved role narrowed")
	}
	if value, ok := ParseState("secret"); ok || value != 0 {
		t.Fatal("unapproved state narrowed")
	}
	if value, ok := ParseEvent("secret"); ok || value != 0 {
		t.Fatal("unapproved event narrowed")
	}
	if operationID("plausible_secret_operation") != "operational_failure" {
		t.Fatal("arbitrary log operation narrowed")
	}
	if _, ok := controlOperationName("plausible_secret_operation"); ok {
		t.Fatal("arbitrary control operation narrowed")
	}
	if got := databaseFixtureOperations.Lookup("plausible_secret_query"); got.String() != "unknown" {
		t.Fatal(got)
	}
	if got := databaseFixtureOperations.Lookup("begin"); got.String() != "begin" {
		t.Fatal(got)
	}
	m := New("publisher")
	defer m.Shutdown(context.Background())
	counter := newCounter(m.meter, "tnl_publisher_type_boundary_total", "Type boundary fixture.", HTTPStatus, TLSResumed, ServiceProtocol, OutcomeKey, State)
	counter.instrument.Add(t.Context(), 1, metric.WithAttributes(
		attribute.String(string(HTTPStatus.Key()), "200"), attribute.Int(string(TLSResumed.Key()), 1),
		ServiceProtocol.Value(Protocol(255)), OutcomeKey.Value(Outcome(255)), State.Value(LifecycleState(255)),
	))
	if text := metricsText(t, m); strings.Contains(text, `tnl_service_protocol=`) || strings.Contains(text, `tnl_outcome=`) || strings.Contains(text, `http_response_status_code=`) || strings.Contains(text, `tls_resumed=`) || strings.Contains(text, `tnl_state=`) {
		t.Fatal("invalid values escaped the SDK filter", text)
	}
}
