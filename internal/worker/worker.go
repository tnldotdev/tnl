package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/0xcadams/tnl/internal/tailtransport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var (
	ErrAtCapacity      = errors.New("worker: at capacity")
	ErrDraining        = errors.New("worker: draining")
	ErrStaleAssignment = errors.New("worker: stale assignment")
	ErrNotReady        = errors.New("worker: route not ready")
)

type RouteRef struct {
	RouteID    string `json:"route_id"`
	Generation uint64 `json:"generation"`
}

type Assignment struct {
	RouteRef
	Endpoint tailtransport.Endpoint
	Key      key.NodePrivate
}

type Capacity struct {
	Active   int
	Limit    int
	Draining bool
}

type RouteBackend interface {
	Open(context.Context) (net.Conn, error)
}

type OwnedRoute interface {
	RouteBackend
	Drain(context.Context) error
	Close() error
}

type RouteOwner interface {
	Attach(context.Context, Assignment) (OwnedRoute, error)
	Capacity() Capacity
	Drain(context.Context) error
	Close() error
}

type EngineConfig struct {
	Capacity         int
	Profiles         map[string]*tailcfg.DERPRegion
	Logf             logger.Logf
	OnTailcatFailure func(operation, reason string)
}

type leaseDialer interface {
	Start(context.Context) error
	Open(context.Context) (net.Conn, error)
	Drain(context.Context) error
	Close() error
}

type Engine struct {
	capacity         int
	profiles         map[string]*tailcfg.DERPRegion
	logf             logger.Logf
	onTailcatFailure func(operation, reason string)

	mu       sync.Mutex
	routes   map[string]*ownedRoute
	draining bool
	closed   bool

	newDialer func(tailtransport.DialerConfig) (leaseDialer, error)
}

func NewEngine(config EngineConfig) (*Engine, error) {
	if config.Capacity <= 0 {
		return nil, errors.New("worker: capacity must be positive")
	}
	if len(config.Profiles) == 0 {
		return nil, errors.New("worker: relay profiles are required")
	}
	return &Engine{
		capacity:         config.Capacity,
		profiles:         cloneProfiles(config.Profiles),
		logf:             config.Logf,
		onTailcatFailure: config.OnTailcatFailure,
		routes:           make(map[string]*ownedRoute),
		newDialer: func(config tailtransport.DialerConfig) (leaseDialer, error) {
			return tailtransport.NewDialer(config)
		},
	}, nil
}

func (e *Engine) Attach(ctx context.Context, assignment Assignment) (OwnedRoute, error) {
	if err := validateAssignment(assignment); err != nil {
		return nil, err
	}
	dialer, err := e.newDialer(tailtransport.DialerConfig{
		Endpoint: assignment.Endpoint,
		Profiles: e.profiles,
		Key:      assignment.Key,
		Logf:     e.logf,
	})
	if err != nil {
		wrappedErr := fmt.Errorf("worker: create route dialer: %w", err)
		e.reportTailcatFailure("create", assignment.RouteRef, wrappedErr)
		return nil, wrappedErr
	}
	route := &ownedRoute{engine: e, ref: assignment.RouteRef, dialer: dialer}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		_ = dialer.Close()
		return nil, net.ErrClosed
	}
	if e.draining {
		e.mu.Unlock()
		_ = dialer.Close()
		return nil, ErrDraining
	}
	previous := e.routes[assignment.RouteID]
	if previous != nil && previous.ref.Generation >= assignment.Generation {
		e.mu.Unlock()
		_ = dialer.Close()
		if previous.ref.Generation == assignment.Generation {
			return previous, nil
		}
		return nil, ErrStaleAssignment
	}
	if previous == nil && len(e.routes) >= e.capacity {
		e.mu.Unlock()
		_ = dialer.Close()
		return nil, ErrAtCapacity
	}
	// Install first to fence the prior generation while Start runs unlocked.
	e.routes[assignment.RouteID] = route
	e.mu.Unlock()

	if previous != nil {
		_ = previous.Close()
	}
	if err := dialer.Start(ctx); err != nil {
		route.remove()
		_ = dialer.Close()
		wrappedErr := fmt.Errorf("worker: start route dialer: %w", err)
		e.reportTailcatFailure("start", assignment.RouteRef, wrappedErr)
		return nil, wrappedErr
	}
	// Startup may race replacement or drain; only the current route becomes ready.
	e.mu.Lock()
	if e.routes[assignment.RouteID] != route || e.closed || e.draining {
		e.mu.Unlock()
		_ = dialer.Close()
		if e.closed {
			return nil, net.ErrClosed
		}
		return nil, ErrDraining
	}
	route.ready = true
	e.mu.Unlock()
	return route, nil
}

func (e *Engine) Capacity() Capacity {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Capacity{Active: len(e.routes), Limit: e.capacity, Draining: e.draining || e.closed}
}

func (e *Engine) Drain(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return net.ErrClosed
	}
	e.draining = true
	routes := e.snapshotLocked()
	e.mu.Unlock()

	errorsByRoute := make(chan error, len(routes))
	var group sync.WaitGroup
	for _, route := range routes {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := route.Drain(ctx); err != nil {
				errorsByRoute <- err
			}
		}()
	}
	group.Wait()
	close(errorsByRoute)
	var result error
	for err := range errorsByRoute {
		result = errors.Join(result, err)
	}
	return result
}

func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.draining = true
	routes := e.snapshotLocked()
	clear(e.routes)
	e.mu.Unlock()
	var result error
	for _, route := range routes {
		result = errors.Join(result, route.dialer.Close())
	}
	return result
}

func (e *Engine) snapshotLocked() []*ownedRoute {
	routes := make([]*ownedRoute, 0, len(e.routes))
	for _, route := range e.routes {
		routes = append(routes, route)
	}
	return routes
}

func (e *Engine) reportTailcatFailure(operation string, ref RouteRef, err error) {
	reason := tailcatFailureReason(err)
	capacity := e.Capacity()
	if e.logf != nil {
		e.logf(
			"tailcat failure: operation=%s reason=%s route_id=%q generation=%d active=%d limit=%d err=%q",
			operation, reason, ref.RouteID, ref.Generation, capacity.Active, capacity.Limit, err,
		)
	}
	if e.onTailcatFailure != nil {
		e.onTailcatFailure(operation, reason)
	}
}

func tailcatFailureReason(err error) string {
	switch {
	case errors.Is(err, syscall.EMFILE):
		return "process_file_limit"
	case errors.Is(err, syscall.ENFILE):
		return "system_file_limit"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return "network"
	}
	return "other"
}

type ownedRoute struct {
	engine *Engine
	ref    RouteRef
	dialer leaseDialer
	ready  bool
	once   sync.Once
}

func (r *ownedRoute) Open(ctx context.Context) (net.Conn, error) {
	r.engine.mu.Lock()
	current := r.engine.routes[r.ref.RouteID]
	ready := current == r && r.ready && !r.engine.draining && !r.engine.closed
	r.engine.mu.Unlock()
	if !ready {
		if current != r {
			return nil, ErrStaleAssignment
		}
		if r.engine.closed {
			return nil, net.ErrClosed
		}
		if r.engine.draining {
			return nil, ErrDraining
		}
		return nil, ErrNotReady
	}
	return r.dialer.Open(ctx)
}

func (r *ownedRoute) Drain(ctx context.Context) error {
	return r.dialer.Drain(ctx)
}

func (r *ownedRoute) Close() error {
	var err error
	r.once.Do(func() {
		r.remove()
		err = r.dialer.Close()
	})
	return err
}

func (r *ownedRoute) remove() {
	r.engine.mu.Lock()
	if r.engine.routes[r.ref.RouteID] == r {
		delete(r.engine.routes, r.ref.RouteID)
	}
	r.engine.mu.Unlock()
}

func validateAssignment(assignment Assignment) error {
	if strings.TrimSpace(assignment.RouteID) == "" || assignment.Generation == 0 {
		return errors.New("worker: route ID and generation are required")
	}
	if assignment.Key.IsZero() {
		return errors.New("worker: Tailcat key is required")
	}
	return nil
}

func cloneProfiles(profiles map[string]*tailcfg.DERPRegion) map[string]*tailcfg.DERPRegion {
	cloned := make(map[string]*tailcfg.DERPRegion, len(profiles))
	for name, region := range profiles {
		if region != nil {
			cloned[name] = region.Clone()
		}
	}
	return cloned
}
