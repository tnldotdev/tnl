// package publisherruntime owns one explicitly deployed publisher's process
// identity. existing runtime loops call Renew; it creates no background worker.
package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Control interface {
	PublisherRuntime(context.Context, controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error)
}

type Owner struct {
	mu                          sync.Mutex
	control                     Control
	server, id, key, scope, run string
	private                     ed25519.PrivateKey
	stage                       publisherRuntimeStage
	deployment                  *controlv1.PublisherDeploymentReport
}

// the epoch belongs to the inspected process run. only a confirmed start owns
// a lease; stop is terminal for this Owner even if another process starts later.
type publisherRuntimeStage interface{ publisherRuntimeStage() }
type runtimeInspected struct{ epoch int64 }
type runtimeRunning struct {
	epoch        int64
	leaseExpires time.Time
}
type runtimeStopped struct{}

func (runtimeInspected) publisherRuntimeStage() {}
func (runtimeRunning) publisherRuntimeStage()   {}
func (runtimeStopped) publisherRuntimeStage()   {}

func (o *Owner) expectedEpochLocked() int64 {
	switch stage := o.stage.(type) {
	case runtimeInspected:
		return stage.epoch
	case runtimeRunning:
		return stage.epoch
	default:
		return 0
	}
}

func (*Owner) String() string   { return "publisher runtime" }
func (*Owner) GoString() string { return "publisher runtime" }

func New(control Control, server, id, key, scope string, private ed25519.PrivateKey, deployment ...*controlv1.PublisherDeploymentReport) (*Owner, error) {
	if control == nil || server == "" || id == "" || key == "" || scope == "" || len(private) != ed25519.PrivateKeySize {
		return nil, publisherproof.ErrProof
	}
	var report *controlv1.PublisherDeploymentReport
	if len(deployment) > 1 {
		return nil, publisherprovenance.ErrInvalid
	}
	if len(deployment) == 1 && deployment[0] != nil {
		if err := publisherprovenance.Validate(deployment[0]); err != nil {
			return nil, err
		}
		copy := *deployment[0]
		report = &copy
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &Owner{control: control, server: strings.TrimSuffix(server, "/"), id: id, key: key, scope: scope, private: append(ed25519.PrivateKey(nil), private...), run: hex.EncodeToString(nonce[:]), deployment: report}, nil
}

func (o *Owner) call(ctx context.Context, action controlv1.PublisherRuntimeRequestAction) (controlv1.PublisherRuntimeResponse, error) {
	epoch := o.expectedEpochLocked()
	proof, err := publisherproof.Sign(o.id, o.key, publisherproof.RuntimeScope(o.scope, string(action), o.run, epoch, publisherprovenance.Digest(o.deployment)), o.server+"/v1/publisher-runtime", o.private, time.Now())
	if err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var report *controlv1.PublisherDeploymentReport
	if o.deployment != nil {
		copy := *o.deployment
		report = &copy
	}
	return o.control.PublisherRuntime(call, controlv1.PublisherRuntimeRequest{PublisherIdentityId: o.id, ScopeId: o.scope, ProcessRunId: o.run, ExpectedEpoch: epoch, Action: action, Assertion: proof, Deployment: report})
}

func (o *Owner) Renew(ctx context.Context) (controlv1.PublisherRuntimeResponse, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, stopped := o.stage.(runtimeStopped); stopped {
		return controlv1.PublisherRuntimeResponse{}, failure.Wrap("renew stopped publisher runtime", failure.ServerConflict, errors.New("publisher runtime stopped"))
	}
	if o.stage == nil {
		r, err := o.call(ctx, controlv1.RuntimeInspect)
		if err != nil {
			return r, err
		}
		if r.Epoch < 0 || r.Epoch == math.MaxInt64 {
			return r, failure.Wrap("read publisher runtime epoch", failure.ServerResponseInvalid, publisherproof.ErrProof)
		}
		o.stage = runtimeInspected{epoch: r.Epoch}
	}
	action := controlv1.RuntimeRenew
	_, starting := o.stage.(runtimeInspected)
	if starting {
		action = controlv1.RuntimeStart
	}
	r, err := o.call(ctx, action)
	if err != nil {
		return r, err
	}
	expected := o.expectedEpochLocked()
	if starting {
		expected++
	}
	if r.Epoch != expected || r.LeaseExpiresAt == nil || !r.LeaseExpiresAt.After(time.Now()) {
		return r, failure.Wrap("read publisher runtime lease", failure.ServerResponseInvalid, publisherproof.ErrProof)
	}
	o.stage = runtimeRunning{epoch: r.Epoch, leaseExpires: *r.LeaseExpiresAt}
	return r, nil
}

// ObservabilityContext binds only this accepted runtime's immutable, validated
// deployment report. report fields never choose tenant, service, or group scope.
// callers supply the enrolled member's authenticated team and group identifiers.
func (o *Owner) ObservabilityContext(ctx context.Context, teamID, groupID string) context.Context {
	o.mu.Lock()
	defer o.mu.Unlock()
	id := observability.Identity{}
	if running, ok := o.stage.(runtimeRunning); ok && running.leaseExpires.After(time.Now()) && groupID == o.scope && teamID != "" {
		id.TeamID, id.PublisherGroupID, id.PublisherIdentityID = teamID, groupID, o.id
		if o.deployment != nil {
			id.DeploymentID, id.ReplicaKey = o.deployment.DeploymentId, o.deployment.ReplicaKey
		}
	}
	return observability.ReplaceIdentity(ctx, id)
}

func (o *Owner) Stop(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, running := o.stage.(runtimeRunning); !running {
		return nil
	}
	_, err := o.call(ctx, controlv1.RuntimeStop)
	if err == nil {
		o.stage = runtimeStopped{}
	}
	return err
}
