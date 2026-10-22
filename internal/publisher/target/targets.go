package target

import (
	"context"
	"errors"
	"sync"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

type TargetSnapshot struct {
	Address  string
	Identity string
	Revision uint64
}

type identityResolver interface {
	ResolveTargetIdentity(context.Context, clientproject.Project, string) (string, string, error)
}

// ResolveTargetSnapshot preserves identity when a replacement reuses an address.
func ResolveTargetSnapshot(ctx context.Context, project clientproject.Project, name string, resolver TargetResolver) (TargetSnapshot, error) {
	service, found := project.Config.Services[name]
	if !found || config.TargetType(service) == "app" {
		return TargetSnapshot{}, errors.New("select a configured non-app target")
	}
	if config.TargetType(service) == "address" {
		resolved, err := project.ResolvePublish(name, "")
		if err != nil {
			return TargetSnapshot{}, err
		}
		return TargetSnapshot{Address: string(*resolved.Target), Identity: string(*resolved.Target)}, nil
	}
	identities, ok := resolver.(identityResolver)
	if !ok {
		return TargetSnapshot{}, errors.New("container resolver must return immutable target identity")
	}
	address, identity, err := identities.ResolveTargetIdentity(ctx, project, name)
	if err != nil {
		return TargetSnapshot{}, err
	}
	resolved, err := project.ResolvePublish(name, address)
	if err != nil {
		return TargetSnapshot{}, err
	}
	if identity == "" {
		return TargetSnapshot{}, errors.New("container resolver omitted target identity")
	}
	return TargetSnapshot{Address: string(*resolved.Target), Identity: identity}, nil
}

// TargetBinding belongs to one registration, not a publication run. capture it
// for every admitted request/connection and before a public readiness check.
// Current must pass again before accepting that check's observation. existing
// streams retain their capture and finish without a resolver or worker restart.
type TargetBinding struct {
	Resolve  func(context.Context) (TargetSnapshot, error)
	Changed  func()
	mu       sync.Mutex
	current  TargetSnapshot
	hadValue bool
	revision uint64
}

func (b *TargetBinding) Capture(ctx context.Context) (TargetSnapshot, error) {
	// serialize discoveries so a slow old inspect cannot replace a newer capture.
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Resolve == nil {
		return TargetSnapshot{}, errors.New("target resolver is required")
	}
	next, err := b.Resolve(ctx)
	if err == nil && (next.Address == "" || next.Identity == "") {
		err = errors.New("target resolver returned an incomplete identity")
	}
	if err != nil {
		if b.hadValue {
			b.revision++
			b.current, b.hadValue = TargetSnapshot{}, false
			if b.Changed != nil {
				b.Changed()
			}
		}
		return TargetSnapshot{}, err
	}
	if !b.hadValue || b.current.Address != next.Address || b.current.Identity != next.Identity {
		b.revision++
		if b.hadValue && b.Changed != nil {
			b.Changed()
		}
	}
	next.Revision = b.revision
	b.current, b.hadValue = next, true
	return next, nil
}

func (b *TargetBinding) Current(ctx context.Context, captured TargetSnapshot) bool {
	next, err := b.Capture(ctx)
	return err == nil && next == captured
}
