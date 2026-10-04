// package demo serves a small local HTTP app for trying a public URL.
package demo

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

//go:embed page.html
var page []byte

//go:embed fonts/fira-code-latin-wght-normal.woff2
var latinFont []byte

//go:embed fonts/fira-code-symbols2-wght-normal.woff2
var symbolsFont []byte

type State struct {
	PublicURL    string `json:"public_url"`
	Stamp        string `json:"stamp"`
	RequestCount uint64 `json:"request_count"`
	GeneratedAt  string `json:"generated_at,omitempty"`
}

type Server struct {
	listener net.Listener
	server   *http.Server
	done     chan error
	mu       sync.Mutex
	state    State
	onPing   func(State) error
}

// Start binds the demo only to loopback and returns a ready local HTTP server.
func Start(onPing func(State) error) (*Server, error) {
	stamp := make([]byte, 4)
	if _, err := rand.Read(stamp); err != nil {
		return nil, fmt.Errorf("create demo stamp: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for local demo: %w", err)
	}
	demo := &Server{
		listener: listener,
		done:     make(chan error, 1),
		state:    State{Stamp: hex.EncodeToString(stamp)},
		onPing:   onPing,
	}
	demo.server = &http.Server{Handler: demo, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() { demo.done <- demo.server.Serve(listener) }()
	return demo, nil
}

func (d *Server) Target() string { return "http://" + d.listener.Addr().String() }

func (d *Server) Stamp() string { return d.state.Stamp }

// SetPublicURL uses the hostname confirmed by the publisher when it becomes ready.
func (d *Server) SetPublicURL(value string) {
	d.mu.Lock()
	d.state.PublicURL = value
	d.mu.Unlock()
}

func (d *Server) Close(ctx context.Context) error {
	err := d.server.Shutdown(ctx)
	select {
	case serveErr := <-d.done:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
	case <-ctx.Done():
		err = errors.Join(err, ctx.Err())
	}
	return err
}

func (d *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	case r.URL.Path == "/fonts/fira-code-latin-wght-normal.woff2" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "font/woff2")
		_, _ = w.Write(latinFont)
	case r.URL.Path == "/fonts/fira-code-symbols2-wght-normal.woff2" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "font/woff2")
		_, _ = w.Write(symbolsFont)
	case r.URL.Path == "/state" && r.Method == http.MethodGet:
		d.mu.Lock()
		state := d.state
		d.mu.Unlock()
		writeState(w, state)
	case r.URL.Path == "/ping" && r.Method == http.MethodPost:
		if r.ContentLength != 0 {
			http.Error(w, "ping takes no body", http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		if d.state.PublicURL == "" {
			d.mu.Unlock()
			http.Error(w, "public URL is not ready", http.StatusServiceUnavailable)
			return
		}
		d.state.RequestCount++
		state := d.state
		if d.onPing != nil {
			if err := d.onPing(state); err != nil {
				d.mu.Unlock()
				http.Error(w, "could not print ping in terminal", http.StatusInternalServerError)
				return
			}
		}
		d.state.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
		state.GeneratedAt = d.state.GeneratedAt
		d.mu.Unlock()
		writeState(w, state)
	default:
		http.NotFound(w, r)
	}
}

func writeState(w http.ResponseWriter, state State) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(state)
}
