package tnldruntime

import (
	"log"

	"github.com/tnldotdev/tnl/internal/failure"
)

// logOperationalError emits only authored, bounded error content. raw network,
// provider, database, and visitor errors stay in the wrapped cause.
func logOperationalError(operation failure.Operation, reason failure.Reason, cause error) {
	if cause == nil {
		return
	}
	if specific, ok := failure.ReasonOf(cause); ok {
		reason = specific
	}
	err := failure.Wrap(operation, reason, cause)
	_, definition, _ := failure.Describe(err)
	log.Printf("%s reason=%s: %s; %s", operation, reason, definition.Message, definition.Action)
}
