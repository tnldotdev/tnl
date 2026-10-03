// Package operatorlog presents typed failures in compact one-line tnld logs.
package operatorlog

import (
	"fmt"
	"log"
	"strings"

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
		log.Print(Format(operation, reason, requestID))
	}
}

func safeLine(value string) string {
	return strings.Map(func(character rune) rune {
		if character < ' ' || character == 0x7f {
			return '?'
		}
		return character
	}, value)
}
