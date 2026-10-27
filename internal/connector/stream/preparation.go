package stream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// preparedSelection belongs to one service connector. socket setup reads its
// immutable snapshot; only the joined background owner can replace it.
type preparedSelection struct {
	mu          sync.Mutex
	config      Config
	run         Run
	peerOwner   *peerPreparation
	peer        *preparedPeer
	pendingPeer *controlv1.NativePeerPairRequest
	createKey   string
	peerFenced  bool
	until       time.Time
	timer       *time.Timer
	stop        context.CancelCauseFunc
	cancel      context.CancelFunc
	done        chan struct{}
	closed      bool
	once        sync.Once
}

func (*preparedSelection) String() string   { return "prepared service selection" }
func (*preparedSelection) GoString() string { return "prepared service selection" }

// ErrSelectionExpired closes the old runner when its last confirmed permission
// expires. the owner may revalidate the service before starting a new runner.
var ErrSelectionExpired = fmt.Errorf("%w: prepared selection expired", ErrServiceConnection)

func prepareSelection(ctx context.Context, config Config, stop context.CancelCauseFunc, peer ...*peerPreparation) (*preparedSelection, error) {
	p := &preparedSelection{config: config, stop: stop, done: make(chan struct{})}
	if len(peer) > 0 {
		p.peerOwner = peer[0]
	}
	startup, finishStartup := context.WithTimeout(ctx, 10*time.Second)
	defer finishStartup()
	for {
		err := p.refresh(startup)
		if err == nil {
			break
		}
		if !selectionRetryable(err) {
			return nil, err
		}
		if startup.Err() != nil {
			return nil, context.Cause(startup)
		}
		// no socket is served until a complete current selection is installed.
		// retry only transient control failures within the startup budget.
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
			return nil, context.Cause(startup)
		case <-timer.C:
		}
	}
	life, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-ticker.C:
				if err := p.refresh(life); err != nil && life.Err() == nil && !selectionRetryable(err) {
					p.mu.Lock()
					closed := p.closed
					p.until = time.Time{}
					p.peerFenced = true
					p.timer.Stop()
					p.mu.Unlock()
					if closed {
						return
					}
					p.stop(err)
					return
				}
			}
		}
	}()
	return p, nil
}

func (p *preparedSelection) refresh(ctx context.Context) (result error) {
	defer func() {
		if result != nil && p.peerOwner != nil {
			p.mu.Lock()
			p.peerFenced = true
			p.mu.Unlock()
		}
	}()
	started := time.Now()
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	call, finish := observability.Start(call, "connector.prepare_service")
	defer func() { finish(result) }()
	run, err := p.config.Control.ResolveService(call, p.config.ServiceID)
	if err != nil {
		return err
	}
	if err := call.Err(); err != nil {
		return err
	}
	if run.ServiceID != p.config.ServiceID || !opaqueid.Valid(run.ServiceRunID, opaqueid.ServiceRunPrefix) || run.RunNumber == 0 ||
		run.Endpoint == nil || !run.ValidUntil.After(time.Now()) || !validProtocol(run.Protocol) || run.TrustRevision < 1 {
		return ErrServiceConnection
	}
	if run.Protocol != p.config.Protocol || run.TrustRevision != p.config.TrustRevision || !sameEndpoint(run.Endpoint, p.config.Endpoint) {
		return metadataReload(p.config.ServiceID, p.config.TrustRevision, run.TrustRevision)
	}
	permission := run.Permission
	if permission.Resource.Kind != "service" || permission.Resource.Id != run.ServiceID || permission.Hostname != run.Endpoint.Hostname || permission.Port != run.Endpoint.Port ||
		permission.VisitorPolicyRevision < 1 || len(permission.VisitorToken) == 0 || len(permission.VisitorToken) > visitortoken.MaxTokenBytes || !permission.ExpiresAt.After(time.Now()) {
		return ErrServiceConnection
	}
	if p.peerOwner != nil {
		if err := p.refreshPeer(call, run); err != nil {
			return err
		}
	}
	run.ServiceTLS = p.config.ServiceTLS
	endpoint := *run.Endpoint
	run.Endpoint = &endpoint
	until := minSelectionTime(minSelectionTime(run.ValidUntil, permission.ExpiresAt), started.Add(10*time.Second))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !until.After(time.Now()) || !p.until.IsZero() && !p.until.After(time.Now()) {
		return ErrServiceConnection
	}
	p.run, p.until = run, until
	p.peerFenced = false
	if p.peerOwner != nil {
		until = minSelectionTime(until, p.peer.until)
	}
	if p.timer == nil {
		p.timer = time.AfterFunc(time.Until(until), p.expire)
	} else {
		p.timer.Reset(time.Until(until))
	}
	return nil
}

func (p *preparedSelection) current() (Run, error) {
	p.mu.Lock()
	expired := p.closed || !p.until.After(time.Now())
	// this read feeds openPrivate's ingress path. a prepared peer does not
	// authorize that path, even while its own background snapshot is healthy.
	if expired || p.peerOwner != nil {
		p.mu.Unlock()
		if expired {
			p.stop(ErrSelectionExpired)
		}
		return Run{}, ErrServiceConnection
	}
	run := p.run
	endpoint := *run.Endpoint
	run.Endpoint = &endpoint
	p.mu.Unlock()
	return run, nil
}

func (p *preparedSelection) expire() {
	p.mu.Lock()
	expired := !p.closed && (!p.until.After(time.Now()) || p.peerOwner != nil && p.peer != nil && !p.peer.until.After(time.Now()))
	p.mu.Unlock()
	if expired {
		p.stop(ErrSelectionExpired)
	}
}

func (p *preparedSelection) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.timer.Stop()
		p.mu.Unlock()
		p.cancel()
		<-p.done
	})
}

func selectionRetryable(err error) bool {
	if reason, known := failure.ReasonOf(err); known && reason == failure.ServerResponseInvalid {
		return false
	}
	var network net.Error
	return errors.Is(err, clientcontrol.ErrUnavailable) || errors.Is(err, clientcontrol.ErrRateLimited) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network)
}

func minSelectionTime(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}
