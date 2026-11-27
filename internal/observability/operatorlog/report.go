// Package operatorlog presents typed failures in compact one-line tnld logs.
package operatorlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

// Format includes only owned operation names, reason IDs, and authored copy.
// a provider or database error must remain in its wrapped cause.
func Format(operation failure.Operation, reason failure.Reason, requestID string) string {
	definition, ok := failure.DefinitionFor(reason)
	if !ok {
		reason = failure.Unexpected
		definition, _ = failure.DefinitionFor(reason)
	}
	context := ""
	if requestID != "" {
		context = " request_id=" + safeLine(requestID)
	}
	return fmt.Sprintf("%s reason=%s%s: %s; %s", safeLine(string(operation)), reason, context,
		definition.Message, definition.Action)
}

func Report(operation failure.Operation, reason failure.Reason, requestID string, cause error) {
	ReportContext(context.Background(), operation, reason, requestID, cause)
}

// ReportContext preserves the one-line format and adds owned trace correlation
// and optional safe OTLP log export through the process context.
func ReportContext(ctx context.Context, operation failure.Operation, reason failure.Reason, requestID string, cause error) {
	ReportFields(ctx, operation, reason, requestID, cause)
}

// ReportFields appends owner-validated identifiers, counts and fixed labels.
func ReportFields(ctx context.Context, operation failure.Operation, reason failure.Reason, requestID string, cause error, fields ...slog.Attr) {
	if cause != nil {
		if specific, ok := failure.ReasonOf(cause); ok {
			reason = specific
		}
		Line(ctx, Format(operation, reason, requestID)+safeCauseFields(cause), fields...)
		observability.OperationalFailure(ctx, operation, reason, requestID, cause)
	}
}

// Line prints an authored event and owner-validated fields without reporting
// a second failure to telemetry.
func Line(ctx context.Context, event string, fields ...slog.Attr) {
	var line strings.Builder
	line.WriteString(safeLine(event))
	line.WriteString(observability.Correlation(ctx))
	if len(fields) > 0 {
		fmt.Fprintf(&line, " at_unix_ms=%d", time.Now().UnixMilli())
	}
	for _, f := range fields {
		line.WriteByte(' ')
		line.WriteString(safeLine(f.String()))
	}
	log.Print(line.String())
}

// CauseClass reports what the local operation observed, without inferring
// which peer originated a reset or formatting an external error.
func CauseClass(err error) string {
	var network net.Error
	var postgres *pgconn.PgError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &network) && network.Timeout():
		return "timeout"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return "closed"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.As(err, &postgres):
		return "postgres"
	default:
		return "error"
	}
}

func safeCauseFields(cause error) string {
	var postgres *pgconn.PgError
	if errors.As(cause, &postgres) && validSQLState(postgres.Code) {
		return " sqlstate=" + postgres.Code
	}
	if errors.Is(cause, os.ErrPermission) {
		return " permission_denied=true"
	}
	var network net.Error
	if errors.Is(cause, context.DeadlineExceeded) || errors.As(cause, &network) && network.Timeout() {
		return " timeout=true"
	}
	return ""
}

func validSQLState(value string) bool {
	if len(value) != 5 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}

func safeLine(value string) string {
	return strings.Map(func(character rune) rune {
		if character < ' ' || character == 0x7f {
			return '?'
		}
		return character
	}, value)
}
