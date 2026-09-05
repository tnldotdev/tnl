package tnldruntime

import (
	"encoding/json"
	"net/http"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

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
