package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/observability"
)

func runController(ctx context.Context, address, token string) error {
	metrics := observability.New("edge")
	metrics.SetRoutes("active", 0)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("GET /metrics", metrics.Handler())
	mux.Handle("PUT /v1/demand", authorize(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Routes int `json:"routes"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || request.Routes < 0 || request.Routes > 100_000 {
			http.Error(w, "routes must be between 0 and 100000", http.StatusBadRequest)
			return
		}
		metrics.SetRoutes("active", request.Routes)
		writeJSON(w, request)
	})))
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return serveHTTP(ctx, server)
}

func authorize(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, provided, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || scheme != "Bearer" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func serveHTTP(ctx context.Context, server *http.Server) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", errors.Join(err, server.Close()))
	}
	err := <-serveErr
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
