// package tnl publishes an application-owned HTTP handler through one ad-hoc URL.
package tnl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/adhoc"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	RequirePostQuantum      bool
	EnrollmentKey           string
	PublisherIdentityID     string
	PublisherCredentialFile string
	PublisherIdentity       *PublisherIdentity
	ServerURL               string
	StateDir                string
	HTTPClient              *http.Client
	AccessMode              controlv1.VisitorAccessMode
	IP                      []string
	Limits                  Limits
	StateProtection         StateProtection
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
	limits := publisher.ApplicationLimits{Requests: options.Limits.Requests, RateRequests: options.Limits.Rate.Requests,
		RatePer: options.Limits.Rate.Per, Concurrency: options.Limits.Concurrency}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	state, profile, serverURL, native, err := preparePublisher(ctx, options)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("listen for local HTTP requests: %w", err), state.Close())
	}
	invocationID, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return nil, errors.Join(err, listener.Close(), state.Close())
	}
	local := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	runCtx, cancel := context.WithCancel(ctx)
	tunnel := &Tunnel{cancel: cancel, done: make(chan struct{})}
	serveDone := make(chan error, 1)
	go func() {
		err := local.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveDone <- err
		if err != nil {
			cancel()
		}
	}()
	ready := make(chan publisher.Event, 1)
	go func() {
		result := adhoc.Run(runCtx, adhoc.Options{
			RequirePostQuantum: options.RequirePostQuantum,
			ControlURL:         serverURL, HTTPClient: options.HTTPClient, State: profile,
			Publisher: native, InvocationID: invocationID,
			Target: "http://" + listener.Addr().String(), AccessMode: options.AccessMode, IP: slices.Clone(options.IP), Limits: limits,
			OnAllocated: func(publicURL controlv1.PublicURL) error {
				tunnel.mu.Lock()
				tunnel.id, tunnel.url = publicURL.Id, "https://"+publicURL.CanonicalHostname
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
		shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		shutdownErr := shutdownHTTP(shutdownCtx, local, serveDone)
		stop()
		result = errors.Join(result, shutdownErr, state.Close())
		tunnel.mu.Lock()
		tunnel.err = result
		tunnel.mu.Unlock()
		close(tunnel.done)
	}()
	select {
	case event := <-ready:
		if ctx.Err() != nil {
			return nil, errors.Join(context.Cause(ctx), tunnel.Close())
		}
		tunnel.mu.Lock()
		valid := event.PublicURLID == tunnel.id && event.PublicURL == tunnel.url && event.PublishRunNumber > 0
		tunnel.mu.Unlock()
		if valid {
			return tunnel, nil
		}
		return nil, errors.Join(errors.New("ready publish run does not match the ad-hoc allocation"), tunnel.Close())
	case <-tunnel.done:
		if ctx.Err() != nil {
			return nil, errors.Join(context.Cause(ctx), tunnel.Wait())
		}
		if err := tunnel.Wait(); err != nil {
			return nil, err
		}
		return nil, errors.New("ad-hoc publication stopped before it was ready")
	case <-ctx.Done():
		return nil, errors.Join(context.Cause(ctx), tunnel.Close())
	}
}

// shutdownHTTP bounds graceful shutdown, closes remaining connections on timeout,
// and joins the serving loop before the tunnel releases its other resources.
func shutdownHTTP(ctx context.Context, server *http.Server, served <-chan error) error {
	err := server.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, server.Close())
	}
	return errors.Join(err, <-served)
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
