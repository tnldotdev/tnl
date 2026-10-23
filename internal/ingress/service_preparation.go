package ingress

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (p *Connector) reportPreparation(err error) {
	if err == nil || p.config.Report == nil {
		return
	}
	p.mu.Lock()
	if time.Since(p.lastPreparationReport) < 2*time.Second {
		p.mu.Unlock()
		return
	}
	p.lastPreparationReport = time.Now()
	p.mu.Unlock()
	p.config.Report(err)
}

// ServiceRoute reads the locally prepared service/run only. neither an absent
// projection nor an expired policy can cause a serving operation to fetch state.
func (p *Connector) ServiceRoute(service, run string, number int64, now time.Time) (ingressv1.ServiceProjection, bool) {
	if _, err := p.lease(now); err != nil {
		return ingressv1.ServiceProjection{}, false
	}
	p.mu.Lock()
	prepared := p.prepared[run]
	p.mu.Unlock()
	if prepared == nil {
		return ingressv1.ServiceProjection{}, false
	}
	view, enabled, _ := prepared.policy.lease.Current()
	if !enabled || view.Scope.ID != service {
		return ingressv1.ServiceProjection{}, false
	}
	return p.config.Routing.Lookup(service, run, number, now)
}

func (p *Connector) servicePolicyReady(service string) bool {
	p.mu.Lock()
	runs := make([]*preparedVisitorRun, 0, len(p.prepared))
	for _, run := range p.prepared {
		runs = append(runs, run)
	}
	p.mu.Unlock()
	for _, run := range runs {
		view, enabled, _ := run.policy.lease.Current()
		if enabled && view.Scope.ID == service {
			return true
		}
	}
	return false
}

// Run prepares routing, policy and delegated capacity without visitor-triggered
// work. the daemon owns cancellation and joins this lifetime on shutdown.
func (p *Connector) Run(ctx context.Context) error {
	if p.config.VisitorControl == nil {
		return ErrServiceAdmission
	}
	return runUntilEitherStops(ctx, p.runServiceRouting, p.runServiceVisitors)
}

func (p *Connector) runServiceRouting(ctx context.Context) error {
	defer p.config.Routing.Clear()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		lease, err := p.lease(time.Now())
		fetching := err == nil
		if err == nil {
			call, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = p.refreshRouting(call, lease)
			cancel()
		}
		if err != nil {
			p.config.Routing.Clear()
			if fetching && ctx.Err() == nil {
				p.reportPreparation(err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (p *Connector) runServiceVisitors(ctx context.Context) error {
	defer func() {
		p.mu.Lock()
		runs := p.prepared
		p.prepared = make(map[string]*preparedVisitorRun)
		p.mu.Unlock()
		for _, run := range runs {
			run.close(ctx)
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		owner, err := p.lease(time.Now())
		if err != nil {
			continue
		}
		p.config.Routing.mu.RLock()
		current := make(map[string]serviceRunUpsert)
		for _, entry := range p.config.Routing.services {
			if entry.expiresAt.After(time.Now()) {
				current[entry.key.runID] = entry
			}
		}
		p.config.Routing.mu.RUnlock()
		p.mu.Lock()
		var retired []*preparedVisitorRun
		for id, run := range p.prepared {
			_, live := current[id]
			if !samePrivateLease(run.capacity.owner, owner) || !live && !run.active() {
				delete(p.prepared, id)
				retired = append(retired, run)
			}
		}
		p.mu.Unlock()
		for _, run := range retired {
			run.close(ctx)
		}
		for id, entry := range current {
			p.mu.Lock()
			run := p.prepared[id]
			full := len(p.prepared) >= 4096
			p.mu.Unlock()
			if run != nil {
				run.expand(ctx, p.reportPreparation)
				continue
			}
			if full {
				continue
			}
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: entry.key.serviceID}
			capacity, err := prepareStreamCapacity(ctx, p.config.VisitorControl, owner, ingressv1.StreamCapacityRequest{
				Resource: controlv1.VisitorResourceScope{Kind: "service", Id: scope.ID}, RunId: id, RunNumber: entry.number, Capacity: max(1, p.config.MaxServiceStreams/4)}, p.reportPreparation)
			if err != nil {
				if ctx.Err() == nil {
					p.reportPreparation(err)
				}
				continue
			}
			policy, err := prepareVisitorPolicy(ctx, p.config.VisitorControl, scope, p.config.CurrentLease, p.reportPreparation)
			if err != nil {
				if ctx.Err() == nil {
					p.reportPreparation(err)
				}
				_ = capacity.Close(ctx)
				continue
			}
			p.mu.Lock()
			p.prepared[id] = &preparedVisitorRun{policy: policy, capacity: capacity, limit: p.config.MaxServiceStreams}
			p.mu.Unlock()
		}
	}
}
