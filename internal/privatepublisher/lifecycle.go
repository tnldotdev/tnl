package privatepublisher

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// RunControl is the exact private service authority boundary. a person
// creates the saved service separately; only the scoped publisher assertion
// prepares and binds runs, and only the run token can renew or close one.
type RunControl interface {
	PreparePrivateServiceRun(context.Context, string, string, string) (controlv1.PrivateServiceRunPreparation, error)
	BindPrivateServiceRunKey(context.Context, string, string, string, controlv1.BindPrivateServiceRunKeyRequest) (controlv1.PrivateServiceRunSetup, error)
	HeartbeatPrivateServiceRun(context.Context, string, string, credentials.PublishRunToken) (controlv1.PrivateServiceRunState, error)
	ClosePrivateServiceRun(context.Context, string, string, credentials.PublishRunToken) error
}

type SlotSession interface {
	Serve(context.Context) error
	Close() error
}

type RunConfig struct {
	Control           RunControl
	Access            func(context.Context) (string, error)
	Identity          authorityv1.PublisherEnrollmentResult
	SigningKey        ed25519.PrivateKey
	PrivateServiceID  string
	Target            string
	TargetTLSMode     string
	HeartbeatInterval time.Duration
	Connect           func(context.Context, *Bound, uint8) (SlotSession, error)
	Ready             func() error
}

// Publish keeps the identity's run binding, two independently claimed relay
// slots and current control heartbeat together. a replaced assignment stops
// this run instead of admitting bytes on a stale slot or replaying a stream.
func Publish(ctx context.Context, config RunConfig) (result error) {
	if config.TargetTLSMode != "" {
		return ErrUnsupportedTargetTLS
	}
	if config.Control == nil || config.Access == nil || config.Identity.PrivateServiceId == nil ||
		config.Identity.Kind != authorityv1.PrivateService || *config.Identity.PrivateServiceId != config.PrivateServiceID ||
		len(config.SigningKey) != ed25519.PrivateKeySize {
		return ErrPrivateStream
	}
	if _, err := tcptarget.Normalize(config.Target); err != nil {
		return err
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 10 * time.Second
	}
	if config.HeartbeatInterval < time.Millisecond || config.HeartbeatInterval > 15*time.Second {
		return ErrPrivateStream
	}
	if config.Connect == nil {
		config.Connect = func(ctx context.Context, bound *Bound, slot uint8) (SlotSession, error) {
			return bound.ConnectSlot(ctx, slot)
		}
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	access, err := config.Access(ctx)
	if err != nil || access == "" {
		return errors.Join(ErrPrivateStream, err)
	}
	preparation, err := config.Control.PreparePrivateServiceRun(ctx, config.PrivateServiceID, key, access)
	if err != nil {
		return err
	}
	prepared, err := NewPrepared(preparation, config.Identity, config.SigningKey, config.Target, config.TargetTLSMode)
	if err != nil {
		return err
	}
	access, err = config.Access(ctx)
	if err != nil || access == "" {
		return errors.Join(ErrPrivateStream, err)
	}
	// a retry of a failed response sends the same public key and signature,
	// never a new key for the same prepared run.
	var setup controlv1.PrivateServiceRunSetup
	for attempt := range 2 {
		setup, err = config.Control.BindPrivateServiceRunKey(ctx, config.PrivateServiceID, preparation.PrivateRunId, access, prepared.Request)
		if err == nil || attempt == 1 || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return err
	}
	bound, err := prepared.Bind(setup)
	if err != nil {
		return err
	}
	runToken := credentials.PublishRunToken(setup.RunToken)
	defer func() {
		bound.Invalidate()
		finish, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = errors.Join(result, config.Control.ClosePrivateServiceRun(finish, config.PrivateServiceID, setup.PrivateRunId, runToken))
	}()
	state, err := config.Control.HeartbeatPrivateServiceRun(ctx, config.PrivateServiceID, setup.PrivateRunId, runToken)
	if err != nil || !bound.MatchesHeartbeat(state) {
		return errors.Join(ErrPrivateStream, err)
	}
	workerCtx, stop := context.WithCancel(ctx)
	var workers sync.WaitGroup
	var connected [2]atomic.Bool
	for slot := range uint8(2) {
		workers.Go(func() { keepSlot(workerCtx, bound, slot, config.Connect, &connected[slot]) })
	}
	defer func() { stop(); bound.Invalidate(); workers.Wait() }()
	ticker := time.NewTicker(config.HeartbeatInterval)
	defer ticker.Stop()
	ready := false
	heartbeatOK := true
	for {
		if heartbeatOK && state.State == controlv1.PrivateServiceRunStateState("ready") && !ready && connected[0].Load() && connected[1].Load() {
			if config.Ready != nil {
				if err := config.Ready(); err != nil {
					return err
				}
			}
			ready = true
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if !state.PublisherExpiresAt.After(time.Now()) {
				return ErrPrivateStream
			}
			next, err := config.Control.HeartbeatPrivateServiceRun(ctx, config.PrivateServiceID, setup.PrivateRunId, runToken)
			if err != nil {
				heartbeatOK = false
				if ctx.Err() != nil {
					return nil
				}
				// a surviving slot remains usable only until the last confirmed
				// publisher deadline; retry without reviving stale authority.
				continue
			}
			if !bound.MatchesHeartbeat(next) {
				return ErrPrivateStream
			}
			state = next
			heartbeatOK = true
		}
	}
}

func keepSlot(ctx context.Context, bound *Bound, slot uint8, connect func(context.Context, *Bound, uint8) (SlotSession, error), connected *atomic.Bool) {
	for ctx.Err() == nil {
		session, err := connect(ctx, bound, slot)
		if err == nil && session != nil {
			connected.Store(true)
			_ = session.Serve(ctx)
			connected.Store(false)
			_ = session.Close()
		}
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
