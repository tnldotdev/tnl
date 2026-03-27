package observability

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Server is a running private metrics listener.
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
	return s.server.Shutdown(ctx)
}
