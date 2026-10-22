package service

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type invalidSetupControl struct {
	*lifecycleControl
	closeErr error
	closed   bool
}

func (c *invalidSetupControl) StartServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.ServiceRunSetup, error) {
	setup, err := c.lifecycleControl.StartServiceRun(ctx, service, run, access, number)
	if err == nil {
		setup.RunNumber++
	}
	return setup, err
}

func (c *invalidSetupControl) CloseServiceRun(_ context.Context, _, _ string, token credentials.ServiceRunToken) error {
	c.closed = token.String() == c.setup.RunToken
	return c.closeErr
}

func TestServiceRunInvalidSetupStillClosesAndPreservesCleanupFailure(t *testing.T) {
	config, control := lifecycleFixture(t)
	cleanup := errors.New("close failed")
	invalid := &invalidSetupControl{lifecycleControl: control, closeErr: cleanup}
	config.Control = invalid
	err := Publish(t.Context(), config)
	if !invalid.closed || !errors.Is(err, ErrPrivateStream) || !errors.Is(err, cleanup) {
		t.Fatal("invalid setup skipped its close or lost either error", err)
	}
}
