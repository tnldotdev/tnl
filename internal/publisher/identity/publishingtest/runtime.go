package publishingtest

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Runtime verifies the actual native owner's signed lifecycle requests. service
// publication still uses the fixture's HTTP client and existing publisher engine.
type Runtime struct {
	fixture     *Fixture
	mu          sync.Mutex
	owners      map[string]runtimeOwner
	requests    []controlv1.PublisherRuntimeRequest
	renewErrors map[string]error
	replays     map[string]bool
}

type runtimeOwner struct {
	epoch  int64
	run    string
	active bool
}

func (f *Fixture) Runtime() *Runtime {
	return &Runtime{fixture: f, owners: map[string]runtimeOwner{}, renewErrors: map[string]error{}, replays: map[string]bool{}}
}

func (c *Runtime) FailRenewal(identity string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.renewErrors[identity] = err
}

func (c *Runtime) Requests() []controlv1.PublisherRuntimeRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]controlv1.PublisherRuntimeRequest(nil), c.requests...)
}

func (c *Runtime) PublisherRuntime(ctx context.Context, request controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	if err := ctx.Err(); err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	f := c.fixture
	f.mu.Lock()
	enrolled := f.grants[request.ScopeId]
	if enrolled == nil || enrolled.result.ClientId != request.PublisherIdentityId || len(enrolled.public) != ed25519.PublicKeySize {
		f.mu.Unlock()
		return controlv1.PublisherRuntimeResponse{}, publisherproof.ErrProof
	}
	public, key := append(ed25519.PublicKey(nil), enrolled.public...), enrolled.result.KeyId
	f.mu.Unlock()
	if request.Deployment != nil || request.ProcessRunId == "" {
		return controlv1.PublisherRuntimeResponse{}, publisherproof.ErrProof
	}
	proof, err := publisherproof.Verify(request.Assertion, request.PublisherIdentityId, key,
		publisherproof.RuntimeScope(request.ScopeId, string(request.Action), request.ProcessRunId, request.ExpectedEpoch, ""),
		f.URL+"/v1/publisher/runtimes/"+request.PublisherIdentityId+"/"+string(request.Action), public, time.Now())
	if err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.replays[proof.ID] {
		return controlv1.PublisherRuntimeResponse{}, publisherproof.ErrProof
	}
	c.replays[proof.ID] = true
	c.requests = append(c.requests, request)
	owner := c.owners[request.PublisherIdentityId]
	conflict := func() (controlv1.PublisherRuntimeResponse, error) {
		return controlv1.PublisherRuntimeResponse{}, failure.Wrap("verify fixture runtime epoch", failure.ServerConflict, publisherproof.ErrProof)
	}
	switch request.Action {
	case controlv1.RuntimeInspect:
		if request.ExpectedEpoch != 0 {
			return conflict()
		}
	case controlv1.RuntimeStart:
		if request.ExpectedEpoch != owner.epoch || owner.active {
			return conflict()
		}
		owner.epoch++
		owner.run, owner.active = request.ProcessRunId, true
	case controlv1.RuntimeRenew, controlv1.RuntimeStop:
		if request.ExpectedEpoch != owner.epoch || !owner.active || request.ProcessRunId != owner.run {
			return conflict()
		}
		if request.Action == controlv1.RuntimeRenew {
			if err := c.renewErrors[request.PublisherIdentityId]; err != nil {
				return controlv1.PublisherRuntimeResponse{}, err
			}
		} else {
			owner.active = false
		}
	default:
		return controlv1.PublisherRuntimeResponse{}, publisherproof.ErrProof
	}
	c.owners[request.PublisherIdentityId] = owner
	return controlv1.PublisherRuntimeResponse{Epoch: owner.epoch, LeaseExpiresAt: new(time.Now().Add(2 * time.Minute))}, nil
}
