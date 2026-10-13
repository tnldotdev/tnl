// package tnl publishes an application-owned HTTP handler through one ad-hoc URL.
package tnl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

type RateLimit struct {
	Count int
	Per   time.Duration
	Burst int
}

type WorkLimits struct {
	Total       int
	Rate        RateLimit
	Concurrency int
}

type Limits struct {
	HTTP    WorkLimits
	Traffic TrafficLimits
}

type TrafficLimits struct {
	Connections int
	Rate        RateLimit
	Upload      string
	Download    string
}

type Options struct {
	ServerURL             string
	StateDir              string
	Directory             string
	PublisherBinary       string
	PublisherEndpointFile string
	AllowIP               []string
	AllowAllIPs           bool
	Limits                Limits
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
	if options.AllowAllIPs && len(options.AllowIP) != 0 {
		return nil, errors.New("choose visitor IP prefixes or allow all IPs")
	}
	limits := publisher.ApplicationLimits{Requests: options.Limits.HTTP.Total, RateRequests: options.Limits.HTTP.Rate.Count,
		RatePer: options.Limits.HTTP.Rate.Per, RateBurst: options.Limits.HTTP.Rate.Burst, Concurrency: options.Limits.HTTP.Concurrency}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	traffic := trafficlimits.Selection{}
	if input := options.Limits.Traffic; input.Connections != 0 {
		traffic.Connections = &input.Connections
	}
	if input := options.Limits.Traffic.Rate; input.Count != 0 {
		traffic.Rate = &input.Count
	}
	if input := options.Limits.Traffic.Rate; input.Per != 0 {
		period := input.Per.String()
		traffic.RatePer = &period
	}
	if input := options.Limits.Traffic.Rate; input.Burst != 0 {
		traffic.Burst = &input.Burst
	}
	if options.Limits.Traffic.Upload != "" {
		rate, parseErr := trafficlimits.ParseByteRate(options.Limits.Traffic.Upload)
		if parseErr != nil {
			return nil, parseErr
		}
		traffic.UploadBytes = &rate
	}
	if options.Limits.Traffic.Download != "" {
		rate, parseErr := trafficlimits.ParseByteRate(options.Limits.Traffic.Download)
		if parseErr != nil {
			return nil, parseErr
		}
		traffic.DownloadBytes = &rate
	}
	runtime, err := newNativeRuntime(options)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for local HTTP requests: %w", err)
	}
	invocationID, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		_ = listener.Close()
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
	ready := make(chan privateprotocol.AdHocStatus, 1)
	register := privateprotocol.AdHocRegister{Version: privateprotocol.Version,
		RegistrationID: invocationID, Owner: hex.EncodeToString(entropy[:]), PID: os.Getpid(),
		Target: "http://" + listener.Addr().String(), ServerURL: options.ServerURL,
		AllowIP: slices.Clone(options.AllowIP), AllowAllIPs: options.AllowAllIPs,
		Limits: privateAdHocLimits(options.Limits, traffic)}
	if setting := os.Getenv("TNL_NO_TELEMETRY"); setting == "1" || setting == "true" {
		register.TelemetryDisabled = true
	}
	go func() {
		result := runtime.follow(runCtx, register, func(status privateprotocol.AdHocStatus) {
			tunnel.mu.Lock()
			tunnel.id, tunnel.url = status.PublicURLID, status.PublicURL
			tunnel.mu.Unlock()
			select {
			case ready <- status:
			default:
			}
		})
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := local.Shutdown(shutdownCtx)
		stop()
		select {
		case serveErr := <-serveError:
			result = errors.Join(result, serveErr)
		default:
		}
		result = errors.Join(result, shutdownErr)
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
