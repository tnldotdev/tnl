package observability

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// ControlRequests records matched route patterns, never URLs or route IDs.
func (m *Metrics) ControlRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := r.Pattern
		if operation == "" {
			operation = "unmatched"
		}
		started := time.Now()
		response := &controlResponseWriter{ResponseWriter: w, status: http.StatusOK}
		m.controlInFlight.WithLabelValues(operation).Inc()
		defer func() {
			m.controlInFlight.WithLabelValues(operation).Dec()
			outcome := "success"
			switch {
			case r.Context().Err() != nil:
				outcome = "canceled"
			case response.status >= 500:
				outcome = "server_error"
			case response.status >= 400:
				outcome = "client_error"
			}
			m.ObserveControlRequest(operation, outcome, time.Since(started))
		}()
		next.ServeHTTP(response, r)
	})
}

type controlResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *controlResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *controlResponseWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = status, status >= 200
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *controlResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// RegisterDatabasePool exposes in-memory statistics; scraping never acquires a
// database connection, including when the application's pool is exhausted.
func (m *Metrics) RegisterDatabasePool(stats func() *pgxpool.Stat) {
	for _, metric := range []struct {
		name, help string
		value      func(*pgxpool.Stat) float64
	}{
		{"max_connections", "Configured connection limit.", func(s *pgxpool.Stat) float64 { return float64(s.MaxConns()) }},
		{"acquired_connections", "Connections currently in use.", func(s *pgxpool.Stat) float64 { return float64(s.AcquiredConns()) }},
		{"idle_connections", "Connections available for acquisition.", func(s *pgxpool.Stat) float64 { return float64(s.IdleConns()) }},
		{"total_connections", "Total pool connections, including those being constructed.", func(s *pgxpool.Stat) float64 { return float64(s.TotalConns()) }},
	} {
		m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "tnl_database_pool_" + metric.name, Help: metric.help,
		}, func() float64 { return metric.value(stats()) }))
	}
	for _, metric := range []struct {
		name, help string
		value      func(*pgxpool.Stat) float64
	}{
		{"acquires_total", "Successful connection acquisitions.", func(s *pgxpool.Stat) float64 { return float64(s.AcquireCount()) }},
		{"waited_acquires_total", "Successful acquisitions that waited for an available connection.", func(s *pgxpool.Stat) float64 { return float64(s.EmptyAcquireCount()) }},
		{"acquire_wait_seconds_total", "Time spent waiting on successful acquisitions from an empty pool.", func(s *pgxpool.Stat) float64 { return s.EmptyAcquireWaitTime().Seconds() }},
		{"canceled_acquires_total", "Connection acquisitions canceled before completion.", func(s *pgxpool.Stat) float64 { return float64(s.CanceledAcquireCount()) }},
	} {
		m.registry.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "tnl_database_pool_" + metric.name, Help: metric.help,
		}, func() float64 { return metric.value(stats()) }))
	}
}
