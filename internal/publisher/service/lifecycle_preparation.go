package service

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// runPreparation owns one invocation from its first uncertain mutation through
// exact-run closure. losing a response never selects another invocation or starts
// traffic during cleanup. an unavailable recovery retains the original expiry.
type runPreparation struct {
	config      RunConfig
	approved    controlv1.Service
	key         string
	declaration controlv1.ServiceRunDeclaration
	preparation controlv1.ServiceRunPreparation
	attempted   bool
	known       bool
	uncertain   bool
}

var errPreparationCleanupCanceled = errors.New("service run cleanup was canceled before completion")

func (r *runPreparation) validBinding(p controlv1.ServiceRunPreparation) bool {
	return p.ServiceId == r.config.ServiceID && p.IdempotencyKey == r.key &&
		p.PublisherIdentityId == r.config.PublisherIdentityID &&
		p.PublisherGrantId == r.config.PublisherGrantID && p.PublisherKeyId == r.config.PublisherKeyID &&
		p.TeamId == r.approved.TeamId && p.GuestId == r.approved.GuestId &&
		opaqueid.Valid(p.ServiceRunId, opaqueid.ServiceRunPrefix) && p.RunNumber > 0 &&
		p.RunToken != "" && len(p.RunToken) <= 4096
}

func (r *runPreparation) attempt(ctx context.Context) error {
	access, err := r.config.Access(ctx)
	if err != nil {
		return err
	}
	if access == "" {
		return ErrPrivateStream
	}
	// only invoking the mutation creates an uncertain outcome. access failure
	// before this boundary must not create a reservation during shutdown.
	r.attempted = true
	preparation, err := r.config.Control.PrepareServiceRun(ctx, r.config.ServiceID, r.key, access, r.declaration)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || transientControlError(err) {
			r.uncertain = true
		}
		return err
	}
	if !r.validBinding(preparation) {
		// do not close response-selected state. recover this same invocation
		// before cleanup trusts a malformed response's run reference or token.
		r.uncertain = true
		return ErrPrivateStream
	}
	r.preparation, r.known, r.uncertain = preparation, true, false
	return nil
}

func (r *runPreparation) prepare(ctx context.Context) (controlv1.ServiceRunPreparation, error) {
	err := recoverControlResponse(ctx, time.Time{}, r.attempt)
	return r.preparation, err
}

func (r *runPreparation) close(ctx context.Context) (result error) {
	if !r.attempted || !r.known && !r.uncertain {
		return nil
	}
	// recovery and closure share one budget. cleanup can recover only the
	// original preparation; it never calls StartServiceRun or changes the key.
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	defer func() {
		// this context is detached from the caller. its own canceled recovery
		// or close is an independent failure, not a successful caller stop.
		if failure.Only(result, context.Canceled) {
			result = errors.Join(errPreparationCleanupCanceled, result)
		}
	}()
	if !r.known {
		if _, err := r.prepare(finish); err != nil {
			return err
		}
	}
	return r.config.Control.CloseServiceRun(finish, r.config.ServiceID, r.preparation.ServiceRunId,
		credentials.ServiceRunToken(r.preparation.RunToken))
}
