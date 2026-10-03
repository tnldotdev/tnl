package tnldruntime

import (
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/operatorlog"
)

// logOperationalError emits only authored, bounded error content. raw network,
// provider, database, and visitor errors stay in the wrapped cause.
func logOperationalError(operation failure.Operation, reason failure.Reason, cause error) {
	if cause == nil {
		return
	}
	operatorlog.Report(operation, reason, "", cause)
}
