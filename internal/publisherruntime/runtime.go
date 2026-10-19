// package publisherruntime owns one explicitly deployed publisher's process
// identity. existing runtime loops call Renew; it creates no background worker.
package publisherruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type Control interface {
	PublisherRuntime(context.Context, controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error)
}

type Owner struct {
	mu                          sync.Mutex
	control                     Control
	server, id, key, scope, run string
	private                     ed25519.PrivateKey
	epoch                       int64
	prepared, started           bool
}

func (*Owner) String() string   { return "publisher runtime" }
func (*Owner) GoString() string { return "publisher runtime" }

func New(control Control, server, id, key, scope string, private ed25519.PrivateKey) (*Owner, error) {
	if control == nil || server == "" || id == "" || key == "" || scope == "" || len(private) != ed25519.PrivateKeySize {
		return nil, publisheridentity.ErrProof
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &Owner{control: control, server: strings.TrimSuffix(server, "/"), id: id, key: key, scope: scope, private: private, run: hex.EncodeToString(nonce[:])}, nil
}

func (o *Owner) call(ctx context.Context, action controlv1.PublisherRuntimeRequestAction) (controlv1.PublisherRuntimeResponse, error) {
	proof, err := publisheridentity.Sign(o.id, o.key, publisheridentity.RuntimeScope(o.scope, string(action), o.run, o.epoch), o.server+"/v1/publisher-runtime", o.private, time.Now())
	if err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return o.control.PublisherRuntime(call, controlv1.PublisherRuntimeRequest{PublisherIdentityId: o.id, ScopeId: o.scope, ProcessRunId: o.run, ExpectedEpoch: o.epoch, Action: action, Assertion: proof})
}

func (o *Owner) Renew(ctx context.Context) (controlv1.PublisherRuntimeResponse, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.prepared {
		r, err := o.call(ctx, controlv1.RuntimeInspect)
		if err != nil {
			return r, err
		}
		if r.Epoch < 0 || r.Epoch == math.MaxInt64 {
			return r, failure.Wrap("read publisher runtime epoch", failure.ServerResponseInvalid, publisheridentity.ErrProof)
		}
		o.epoch, o.prepared = r.Epoch, true
	}
	action := controlv1.RuntimeRenew
	if !o.started {
		action = controlv1.RuntimeStart
	}
	r, err := o.call(ctx, action)
	if err != nil {
		return r, err
	}
	expected := o.epoch
	if !o.started {
		expected++
	}
	if r.Epoch != expected || r.LeaseExpiresAt == nil {
		return r, failure.Wrap("read publisher runtime lease", failure.ServerResponseInvalid, publisheridentity.ErrProof)
	}
	o.epoch, o.started = r.Epoch, true
	return r, nil
}

func (o *Owner) Stop(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.started {
		return nil
	}
	_, err := o.call(ctx, controlv1.RuntimeStop)
	return err
}
