package privatepublisher

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type invalidSetupControl struct {
	*lifecycleControl
	closeErr error
	closed   bool
}

func (c *invalidSetupControl) StartManagedServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.PrivateServiceRunSetup, error) {
	setup, err := c.lifecycleControl.StartManagedServiceRun(ctx, service, run, access, number)
	if err == nil {
		setup.RunNumber++
	}
	return setup, err
}

func (c *invalidSetupControl) ClosePrivateServiceRun(_ context.Context, _, _ string, token credentials.ManagedRunToken) error {
	c.closed = token.String() == c.setup.RunToken
	return c.closeErr
}

func TestManagedRunInvalidSetupStillClosesAndPreservesCleanupFailure(t *testing.T) {
	config, control := lifecycleFixture(t)
	cleanup := errors.New("close failed")
	invalid := &invalidSetupControl{lifecycleControl: control, closeErr: cleanup}
	config.Control = invalid
	err := Publish(t.Context(), config)
	if !invalid.closed || !errors.Is(err, ErrPrivateStream) || !errors.Is(err, cleanup) {
		t.Fatal("invalid setup skipped its close or lost either error", err)
	}
}
