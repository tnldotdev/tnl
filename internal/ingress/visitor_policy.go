package ingress

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type visitorPolicyClient interface {
	ReadIngressVisitorPolicy(context.Context, string, ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error)
}

func (c *HTTPControlClient) ReadIngressVisitorPolicy(ctx context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	response, err := c.client.ReadIngressVisitorPolicyWithResponse(ctx, id, body)
	if err != nil {
		return controlv1.VisitorPolicyUpdate{}, err
	}
	if response == nil {
		return controlv1.VisitorPolicyUpdate{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return controlv1.VisitorPolicyUpdate{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

// each run owns preparation and renewal, independent of requests and siblings.
// the controller cancels and joins these owners before replacing a process run.
type publicRunPolicy struct {
	request   ingressv1.IngressVisitorPolicyRequest
	ingressID string
	hostname  string
	policy    *visitorlease.Lease
	cancel    context.CancelFunc
	done      chan struct{}
}

func (r *publicRunPolicy) matches(entry ingressv1.IngressRoutingTableEntry, process ingressv1.IngressLease) bool {
	return r.ingressID == process.IngressId && r.request.IngressRunId == process.IngressRunId && r.request.IngressLeaseRevision == process.IngressLeaseRevision &&
		r.request.Resource.Id == entry.PublicUrlId && r.request.PublishRunId == entry.PublishRunId && r.request.PublishRunNumber == entry.PublishRunNumber &&
		r.hostname == entry.CanonicalHostname && r.request.PolicyRevision == entry.PolicyRevision
}

func (c *Controller) installedPublicPolicy(entry ingressv1.IngressRoutingTableEntry, process ingressv1.IngressLease, now time.Time) (time.Time, bool) {
	c.mu.RLock()
	run := c.publicPolicies[entry.PublishRunId]
	c.mu.RUnlock()
	if run == nil || !run.matches(entry, process) {
		return time.Time{}, false
	}
	view, enabled, _ := run.policy.Current()
	if !enabled || !now.Before(view.ValidUntil) || view.Scope.ID != entry.PublicUrlId || view.Hostname != entry.CanonicalHostname || view.Port != 443 ||
		!entry.PublicUrlExpiresAt.After(view.AuthorityTime(now)) || !process.LeaseExpiresAt.After(view.AuthorityTime(now)) {
		return time.Time{}, false
	}
	return view.AuthorityTime(view.ValidUntil), true
}

func (c *Controller) preparePublicPolicy(ctx context.Context, entry ingressv1.IngressRoutingTableEntry, owner ingressv1.IngressLease) (*publicRunPolicy, error) {
	policy, err := visitorlease.New(visitorscope.Scope{Kind: visitorscope.PublicURL, ID: entry.PublicUrlId}, c.now)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	run := &publicRunPolicy{ingressID: owner.IngressId, hostname: entry.CanonicalHostname, policy: policy, cancel: cancel, done: make(chan struct{}),
		request: ingressv1.IngressVisitorPolicyRequest{IngressRunId: owner.IngressRunId, IngressLeaseRevision: owner.IngressLeaseRevision,
			Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: entry.PublicUrlId}, PublishRunId: entry.PublishRunId,
			PublishRunNumber: entry.PublishRunNumber, PolicyRevision: entry.PolicyRevision}}
	refresh := func() error {
		call, stop := context.WithTimeout(life, 2*time.Second)
		defer stop()
		request := policy.Begin()
		deadline, _ := call.Deadline()
		// contexts use wall time; the controller may supply an offset local clock.
		// spend only the remaining request budget in either clock.
		request.Deadline = request.StartedAt.Add(time.Until(deadline))
		if err := call.Err(); err != nil {
			return context.Cause(call)
		}
		after := request.AfterRevision
		if request.Snapshot {
			after = 0
		}
		body := run.request
		body.AfterRevision = after
		response, err := c.client.ReadIngressVisitorPolicy(call, run.ingressID, body)
		if err := call.Err(); err != nil {
			return err
		}
		if err != nil {
			return c.responseError("prepare ingress visitor policy", err)
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		update, err := visitorlease.Decode(response)
		if err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		return policy.Apply(request, update)
	}
	if err := refresh(); err != nil {
		cancel()
		policy.Close()
		return nil, err
	}
	go func() {
		defer close(run.done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-ticker.C:
				if err := refresh(); err != nil {
					if life.Err() == nil {
						c.report(err)
					}
				} else {
					c.ServingStateChanged()
				}
			}
		}
	}()
	return run, nil
}

func (r *publicRunPolicy) close() {
	r.cancel()
	<-r.done
	r.policy.Close()
}

func (c *Controller) publicPolicyLoop(ctx context.Context) error {
	defer func() {
		c.mu.Lock()
		runs := c.publicPolicies
		c.publicPolicies = make(map[string]*publicRunPolicy)
		c.mu.Unlock()
		// cancel every owner before joining any blocked policy request.
		for _, run := range runs {
			run.cancel()
		}
		for _, run := range runs {
			run.close()
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	cursor := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		owner := c.Lease()
		if owner.IngressLeaseRevision == 0 || owner.Draining || !owner.LeaseExpiresAt.After(c.now()) {
			continue
		}
		c.routingTable.mu.RLock()
		current := make(map[string]ingressv1.IngressRoutingTableEntry)
		for _, stored := range c.routingTable.routes {
			entry := stored.entry
			if !stored.tombstone && entry.PublicUrlExpiresAt.After(c.now()) &&
				(entry.IngressPoolId == nil || *entry.IngressPoolId == c.registration.IngressPoolId) {
				current[entry.PublishRunId] = entry
			}
		}
		c.routingTable.mu.RUnlock()
		c.mu.Lock()
		var retired []*publicRunPolicy
		for id, run := range c.publicPolicies {
			entry, exists := current[id]
			if !exists || !run.matches(entry, owner) {
				delete(c.publicPolicies, id)
				retired = append(retired, run)
			}
		}
		var pending []string
		for id := range current {
			if c.publicPolicies[id] == nil {
				pending = append(pending, id)
			}
		}
		c.mu.Unlock()
		for _, run := range retired {
			run.cancel()
		}
		for _, run := range retired {
			run.close()
		}
		if len(pending) == 0 {
			continue
		}
		slices.Sort(pending)
		start := cursor % len(pending)
		count := min(8, len(pending))
		cursor = start + max(1, count)
		var workers sync.WaitGroup
		for offset := range count {
			entry := current[pending[(start+offset)%len(pending)]]
			workers.Go(func() {
				run, err := c.preparePublicPolicy(ctx, entry, owner)
				if err != nil {
					if ctx.Err() == nil {
						c.report(err)
					}
					return
				}
				c.mu.Lock()
				c.publicPolicies[entry.PublishRunId] = run
				c.mu.Unlock()
				c.ServingStateChanged()
			})
		}
		workers.Wait()
	}
}
