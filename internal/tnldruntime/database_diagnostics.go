package tnldruntime

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
)

func databaseMetricsSource(database *controlstate.Database) func(time.Time) observability.DatabaseSnapshot {
	return func(now time.Time) observability.DatabaseSnapshot {
		local := database.Metrics(now)
		result := observability.DatabaseSnapshot{
			Pool: local.Pool, OperationsOmitted: local.OperationsOmitted,
			Connections:      make(map[string]observability.DatabaseConnectionSnapshot, len(local.Connections)),
			ActiveOperations: make([]observability.DatabaseOperationSnapshot, len(local.ActiveOperations)),
		}
		for purpose, counts := range local.Connections {
			result.Connections[purpose] = observability.DatabaseConnectionSnapshot{
				Open: counts.Open, Connecting: counts.Connecting, Opened: counts.Opened,
				Closed: counts.Closed, Failed: counts.Failed,
			}
		}
		for index, operation := range local.ActiveOperations {
			result.ActiveOperations[index] = observability.DatabaseOperationSnapshot{
				Operation: operation.Operation, ElapsedSeconds: operation.ElapsedSeconds,
			}
		}
		return result
	}
}

// Database activity is served only on the private observability listener.
func withDatabaseDiagnostics(handler http.Handler, database *controlstate.Database) http.Handler {
	if database == nil {
		return handler
	}
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.HandleFunc("GET /debug/database", func(w http.ResponseWriter, r *http.Request) {
		snapshot, _ := database.Diagnostics(r.Context())
		w.Header().Set("Content-Type", "application/json")
		// Local activity remains useful even when the upstream snapshot failed.
		_ = json.NewEncoder(w).Encode(snapshot)
	})
	return mux
}
