package operatorlog

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
)

func TestFormatDoesNotExposeCauseOrMultilineContext(t *testing.T) {
	cause := errors.New("Authorization: Bearer secret-do-not-log")
	err := failure.Wrap("read client session", failure.ClientStateUnavailable, cause)
	if !errors.Is(err, cause) {
		t.Fatal("failure lost its original cause")
	}
	got := Format("read client session", failure.ClientStateUnavailable, "request_1\nspoofed")
	if strings.Contains(got, "secret-do-not-log") || strings.ContainsRune(got, '\n') ||
		!strings.Contains(got, "reason=TNL_CLIENT_STATE_UNAVAILABLE") || !strings.Contains(got, "request_id=request_1?spoofed") {
		t.Fatalf("operator log = %q", got)
	}
}

func TestReportContextExportsMachineOperationAndExactOwnedCode(t *testing.T) {
	received := make(chan *collectorlogs.ExportLogsServiceRequest, 1)
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var request collectorlogs.ExportLogsServiceRequest
		if err := proto.Unmarshal(data, &request); err != nil {
			t.Error(err)
			return
		}
		received <- &request
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer receiver.Close()
	path := filepath.Join(t.TempDir(), "collector.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", receiver.URL+"/v1/logs")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE", path)
	ctx, m, err := observability.StartProcess(t.Context(), "control")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	cause := failure.Wrap("unrelated cause operation", failure.TargetUnavailable, errors.New("secret provider response"))
	ReportContext(ctx, "renew private publisher", failure.Unexpected, "request-owned", cause)
	if err := m.ForceFlush(t.Context()); err != nil {
		t.Fatal(err)
	}
	request := <-received
	if strings.Contains(request.String(), "secret") {
		t.Fatal("operator cause escaped")
	}
	record := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	attrs := map[string]string{}
	for _, a := range record.Attributes {
		attrs[a.Key] = a.Value.GetStringValue()
	}
	if attrs[string(observability.Operation.Key())] != "renew_private_publisher" || attrs[string(observability.Event.Key())] != "operational_failure" || attrs[string(observability.ErrorType.Key())] != string(failure.TargetUnavailable) {
		t.Fatal("actual operator log lost its owned machine fields", attrs)
	}
	for _, definition := range observability.VocabularyAttributes() {
		if definition.Key == observability.ErrorType.Key() && !slices.Contains(definition.Values, string(failure.TargetUnavailable)) {
			t.Fatal("actual TNL code is not approved by generated vocabulary")
		}
	}
}

func TestSafeCauseFieldsOnlyIncludeTypedFailureData(t *testing.T) {
	cause := &pgconn.PgError{Code: "23505", Message: "customer token=secret-do-not-log"}
	if got := safeCauseFields(cause); got != " sqlstate=23505" {
		t.Fatalf("postgres failure fields = %q", got)
	}
	if got := safeCauseFields(&pgconn.PgError{Code: "23505\nsecret"}); got != "" {
		t.Fatalf("invalid PostgreSQL code escaped: %q", got)
	}
}
