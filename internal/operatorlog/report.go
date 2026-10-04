// Package operatorlog presents typed failures in compact one-line tnld logs.
package operatorlog

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/failure"
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
	if cause != nil {
		if specific, ok := failure.ReasonOf(cause); ok {
			reason = specific
		}
		log.Print(Format(operation, reason, requestID) + safeCauseFields(cause))
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
