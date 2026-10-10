// package tnl publishes an application-owned HTTP handler through one ad-hoc URL.
package tnl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/adhoc"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type RateLimit struct {
	Requests int
	Per      time.Duration
}

type Limits struct {
	Requests    int
	Rate        RateLimit
	Concurrency int
}

type Options struct {
	Credential  string
	ServerURL   string
	StateDir    string
	HTTPClient  *http.Client
	AllowIP     []string
	AllowAllIPs bool
	Limits      Limits
}

// Tunnel owns its local listener, publish run, and temporary public URL.
type Tunnel struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	url    string
	id     string
	err    error
	close  sync.Once
}

// Open binds an HTTP handler and returns after its allocated public URL is routable.
func Open(ctx context.Context, handler http.Handler, options Options) (*Tunnel, error) {
	if handler == nil {
		return nil, errors.New("an HTTP handler is required")
	}
	credential := options.Credential
	if credential == "" {
		credential = os.Getenv("TNL_CREDENTIAL")
	}
	if _, _, _, err := credentials.ParseEphemeralCredential(credentials.EphemeralCredential(credential)); err != nil {
		return nil, err
	}
	limits := publisher.ApplicationLimits{Requests: options.Limits.Requests, RateRequests: options.Limits.Rate.Requests,
		RatePer: options.Limits.Rate.Per, Concurrency: options.Limits.Concurrency}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	serverURL := options.ServerURL
	if serverURL == "" {
		serverURL = os.Getenv("TNL_SERVER")
	}
	if serverURL == "" {
		serverURL = "https://control.tnl.dev"
	}
	serverURL, err := clientstate.CanonicalServer(serverURL)
	if err != nil {
		return nil, err
	}
	stateDir := options.StateDir
	if stateDir == "" {
		stateDir = os.Getenv("TNL_STATE_DIR")
	}
	if stateDir == "" {
		stateDir, err = clientstate.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	state, err := clientstate.Open(ctx, stateDir)
	if err != nil {
		return nil, err
	}
	profile, err := state.Server(ctx, serverURL)
	if err != nil {
		_ = state.Close()
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = state.Close()
		return nil, fmt.Errorf("listen for local HTTP requests: %w", err)
	}
	invocationID, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		_ = listener.Close()
		_ = state.Close()
		return nil, err
	}
	local := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	runCtx, cancel := context.WithCancel(ctx)
	tunnel := &Tunnel{cancel: cancel, done: make(chan struct{})}
	serveError := make(chan error, 1)
	go func() {
		if err := local.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveError <- err
			cancel()
		}
	}()
	ready := make(chan publisher.Event, 1)
	go func() {
		result := adhoc.Run(runCtx, adhoc.Options{
			ControlURL: serverURL, HTTPClient: options.HTTPClient, State: profile,
			Credential: credentials.EphemeralCredential(credential), InvocationID: invocationID,
			Target: "http://" + listener.Addr().String(), AllowIP: slices.Clone(options.AllowIP),
			AllowAllIPs: options.AllowAllIPs, Limits: limits,
			OnAllocated: func(route controlv1.PublicURL) error {
				tunnel.mu.Lock()
				tunnel.id, tunnel.url = route.Id, "https://"+route.CanonicalHostname
				tunnel.mu.Unlock()
				return nil
			},
			Observe: func(event publisher.Event) error {
				if event.Type == publisher.EventReady {
					select {
					case ready <- event:
					default:
					}
				}
				return nil
			},
		})
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := local.Shutdown(shutdownCtx)
		stop()
		select {
		case serveErr := <-serveError:
			result = errors.Join(result, serveErr)
		default:
		}
		result = errors.Join(result, shutdownErr, state.Close())
		tunnel.mu.Lock()
		tunnel.err = result
		tunnel.mu.Unlock()
		close(tunnel.done)
	}()
	select {
	case event := <-ready:
		tunnel.mu.Lock()
		valid := event.PublicURLID == tunnel.id && event.PublicURL == tunnel.url && event.PublishRunNumber > 0
		tunnel.mu.Unlock()
		if valid {
			return tunnel, nil
		}
		tunnel.Close()
		return nil, errors.New("ready publish run does not match the ad-hoc allocation")
	case <-tunnel.done:
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err := tunnel.Wait(); err != nil {
			return nil, err
		}
		return nil, errors.New("ad-hoc publication stopped before it was ready")
	case <-ctx.Done():
		tunnel.Close()
		return nil, ctx.Err()
	}
}

func (t *Tunnel) URL() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.url
}

// Close drains publication and removes the public URL. repeated calls are safe.
func (t *Tunnel) Close() error {
	if t == nil {
		return nil
	}
	t.close.Do(t.cancel)
	return t.Wait()
}

// Wait returns when the publish run and its local listener have stopped.
// exhausting the total request budget is a normal completion.
func (t *Tunnel) Wait() error {
	if t == nil {
		return nil
	}
	<-t.done
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}
