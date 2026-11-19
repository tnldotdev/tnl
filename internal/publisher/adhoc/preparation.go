package adhoc

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Prepared owns the original temporary allocation, not its caller's workers or
// client state. Service is independent of Config and the private cleanup facts.
// on a failed attempt, only Cleanup is usable; the owner is not hidden by error.
type Prepared struct {
	Service controlv1.Service
	Config  publisherservice.RunConfig
	mu      sync.Mutex
	native  *publisheridentity.Native
	request controlv1.AllocateServiceRequest
}

func (*Prepared) String() string   { return "temporary service preparation" }
func (*Prepared) GoString() string { return "temporary service preparation" }

// Publisher returns the actual allocation owner for caller-owned process
// coordination. it does not transfer cleanup ownership or start any workers.
func (p *Prepared) Publisher() *publisheridentity.Native { return p.native }

// Prepare selects the real allocation identity and allocates one HTTP service.
// it starts no publication workers. a non-nil result must be cleaned up even on
// error, after the caller's run has joined and before borrowed state is closed.
func Prepare(ctx context.Context, options Options) (*Prepared, error) {
	if options.State == nil || !opaqueid.Valid(options.InvocationID, opaqueid.InvocationPrefix) {
		return nil, errors.New("ad-hoc publisher requires client state and an invocation ID")
	}
	body, target, trust, err := allocationRequest(options)
	if err != nil {
		return nil, err
	}
	var control publisheridentity.NativeControl
	var authority publisheridentity.EnrollmentAuthority
	if options.Publisher == nil {
		client, err := clientcontrol.New(options.ControlURL, options.HTTPClient, "")
		if err != nil {
			return nil, err
		}
		authority, err = clientauthority.New(options.ControlURL, options.HTTPClient, "")
		if err != nil {
			return nil, err
		}
		control = publisheridentity.NativeControl{Services: client, Allocations: client}
	}
	native, err := publisheridentity.Resolve(ctx, options.State, control, authority, options.EnrollmentKey, options.PublisherIdentityID, options.Publisher)
	if err != nil {
		return nil, err
	}
	if err := native.AllocationScope(); err != nil {
		return nil, err
	}
	if native.ControlURL() != options.ControlURL {
		return nil, publisheridentity.ErrScope
	}
	// capture cleanup before the first attempt. Native retains observed or
	// uncertain ownership and is the only allocation recovery/deletion authority.
	native.WithShutdownDeadline(options.ShutdownDeadline)
	prepared := &Prepared{native: native, request: body}
	saved, err := allocateService(ctx, native, body)
	if err != nil {
		return prepared, err
	}
	if saved.RequirePostQuantum != options.RequirePostQuantum {
		return prepared, publisheridentity.ErrScope
	}
	if err := publisheridentity.MatchServiceDeclaration(saved, "http", trust); err != nil {
		return prepared, err
	}
	if saved.ExpiresAt != nil && !saved.ExpiresAt.After(time.Now()) ||
		body.ExpiresAt != nil && (saved.ExpiresAt == nil || saved.ExpiresAt.After(*body.ExpiresAt)) {
		return prepared, errors.New("allocated service did not retain its fixed expiration")
	}
	approved, err := requestlimit.ParseLimits(saved.HttpLimits)
	if err != nil {
		return prepared, err
	}
	// compare only explicit selections, not omitted defaults or server ceilings.
	requested := options.Limits
	if requested.Requests != 0 && approved.Requests != requested.Requests ||
		requested.Concurrency != 0 && approved.Concurrency != requested.Concurrency ||
		requested.RateRequests != 0 && (approved.RateRequests != requested.RateRequests || approved.RatePer != requested.RatePer) ||
		requested.RateBurst != 0 && approved.RateBurst != requested.RateBurst {
		return prepared, publisheridentity.ErrScope
	}
	// neither presentation callbacks nor caller snapshots may mutate the
	// publication metadata or the invocation used to recover cleanup ownership.
	encoded, err := json.Marshal(saved)
	if err != nil {
		return prepared, err
	}
	var publication controlv1.Service
	if err := json.Unmarshal(encoded, &publication); err != nil {
		return prepared, err
	}
	if err := json.Unmarshal(encoded, &prepared.Service); err != nil {
		return prepared, err
	}
	prepared.Config = publisherservice.RunConfig{
		Telemetry: options.Telemetry, Control: native, State: options.State, Access: native.Access,
		PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
		ServiceID: publication.Id, Target: target, Metadata: publisheridentity.ServiceMetadata(publication), Ready: options.Ready,
		ShutdownDeadline:    options.ShutdownDeadline,
		SuppliedCertificate: options.SuppliedCertificate,
	}
	return prepared, nil
}

// Cleanup retries only the native operation for the captured request. callers
// supply a bounded cleanup context independent of publication cancellation.
// failed cleanup retains ownership; confirmed native deletion is terminal.
func (p *Prepared) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cleanupAllocation(ctx, p.native, p.request)
}
