package observability

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"
)

// ProcessHandler serves private process health, readiness, and metrics.
func ProcessHandler(metrics http.Handler, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /ready", func(response http.ResponseWriter, _ *http.Request) {
		if ready == nil || !ready() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("GET /metrics", metrics)
	// CPU profiling is on demand, confined to the private process listener and
	// bounded so a request cannot leave profiling enabled indefinitely.
	mux.HandleFunc("GET /debug/pprof/profile", func(response http.ResponseWriter, request *http.Request) {
		seconds := request.URL.Query()["seconds"]
		if len(seconds) > 1 {
			http.Error(response, "invalid profile duration", http.StatusBadRequest)
			return
		}
		if len(seconds) == 1 {
			value, err := strconv.Atoi(seconds[0])
			if err != nil || value < 1 || value > 30 {
				http.Error(response, "profile duration must be 1-30 seconds", http.StatusBadRequest)
				return
			}
		} else {
			request = request.Clone(request.Context())
			query := request.URL.Query()
			query.Set("seconds", "30")
			request.URL.RawQuery = query.Encode()
		}
		pprof.Profile(response, request)
	})
	return mux
}

// Server is a running metrics listener.
type Server struct {
	listener net.Listener
	server   *http.Server
	done     chan error
}

// Listen starts serving metrics at address.
func Listen(address string, handler http.Handler) (*Server, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	running := &Server{listener: listener, server: server, done: make(chan error, 1)}
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		running.done <- err
		close(running.done)
	}()
	return running, nil
}

// Addr returns the bound listener address.
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Done reports when the listener exits.
func (s *Server) Done() <-chan error {
	return s.done
}

// Shutdown gracefully stops the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.server.Shutdown(ctx); err != nil {
		return errors.Join(err, s.server.Close())
	}
	return nil
}
