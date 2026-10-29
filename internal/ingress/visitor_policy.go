package ingress

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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
	source    atomic.Pointer[publicRunSource]
	sequence  *atomic.Uint64
}

type publicRunSource struct {
	key       [32]byte
	authority tunnelv1.VisitorSourceAuthority
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
	source := run.source.Load()
	if source == nil || source.authority.VisitorPolicyRevision != view.VisitorPolicyRevision || source.authority.ValidUntil <= view.AuthorityTime(now).Unix() {
		return time.Time{}, false
	}
	until := view.AuthorityTime(view.ValidUntil)
	if delegated := time.Unix(source.authority.ValidUntil, 0); delegated.Before(until) {
		until = delegated
	}
	return until, true
}

func (c *Controller) preparePublicPolicy(ctx context.Context, entry ingressv1.IngressRoutingTableEntry, owner ingressv1.IngressLease) (*publicRunPolicy, error) {
	policy, err := visitorlease.New(visitorscope.Scope{Kind: visitorscope.PublicURL, ID: entry.PublicUrlId}, c.now)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	if c.sourceSequences == nil {
		c.sourceSequences = make(map[string]*atomic.Uint64)
	}
	sequence := c.sourceSequences[entry.PublishRunId]
	if sequence == nil {
		sequence = new(atomic.Uint64)
		c.sourceSequences[entry.PublishRunId] = sequence
	}
	c.mu.Unlock()
	run := &publicRunPolicy{ingressID: owner.IngressId, hostname: entry.CanonicalHostname, policy: policy, cancel: cancel, done: make(chan struct{}),
		sequence: sequence,
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
		if response.VisitorSourceKey == nil || len(*response.VisitorSourceKey) != 32 || response.VisitorSourceAuthority == nil {
			return visitortoken.ErrVisitorSource
		}
		authority, err := tunnelv1.ReadVisitorSourceAuthority(*response.VisitorSourceAuthority)
		if err != nil || authority.PublicURLID != body.Resource.Id || authority.PublishRunID != body.PublishRunId || authority.PublishRunNumber != uint64(body.PublishRunNumber) ||
			authority.IngressID != run.ingressID || authority.IngressRunID != body.IngressRunId || authority.IngressLeaseRevision != uint64(body.IngressLeaseRevision) ||
			authority.VisitorPolicyRevision != response.Policy.VisitorPolicyRevision || authority.ValidUntil > response.Policy.ValidUntil.Unix() || authority.ValidUntil <= response.Policy.ObservedAt.Unix() {
			return visitortoken.ErrVisitorSource
		}
		source := &publicRunSource{key: [32]byte(*response.VisitorSourceKey), authority: authority}
		if source.key == ([32]byte{}) {
			return visitortoken.ErrVisitorSource
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		if err := policy.Apply(request, update); err != nil {
			return err
		}
		run.source.Store(source)
		return nil
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

func (c *Controller) SignVisitorSource(entry ingressv1.IngressRoutingTableEntry, visitorID string, source, destination netip.AddrPort) (string, error) {
	owner, now := c.Lease(), c.now()
	if owner.Draining || owner.IngressLeaseRevision <= 0 {
		return "", visitortoken.ErrVisitorSource
	}
	if _, ok := c.installedPublicPolicy(entry, owner, now); !ok {
		return "", visitortoken.ErrVisitorSource
	}
	c.mu.RLock()
	run := c.publicPolicies[entry.PublishRunId]
	c.mu.RUnlock()
	if run == nil || !run.matches(entry, owner) {
		return "", visitortoken.ErrVisitorSource
	}
	state := run.source.Load()
	view, enabled, _ := run.policy.Current()
	if state == nil || !enabled || state.authority.VisitorPolicyRevision != view.VisitorPolicyRevision {
		return "", visitortoken.ErrVisitorSource
	}
	proof, err := visitortoken.SignVisitorSource(state.key, state.authority, run.sequence.Add(1), tunnelv1.VisitorSourceBinding{
		PublicURLID: entry.PublicUrlId, PublishRunID: entry.PublishRunId, PublishRunNumber: uint64(entry.PublishRunNumber),
		VisitorID: visitorID, Source: source, Destination: destination,
	}, view.AuthorityTime(now))
	if err != nil {
		return "", err
	}
	wire, err := proof.MarshalBinary()
	return string(wire), err
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
		c.sourceSequences = nil
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
		for id := range c.sourceSequences {
			if _, exists := current[id]; !exists {
				delete(c.sourceSequences, id)
			}
		}
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
