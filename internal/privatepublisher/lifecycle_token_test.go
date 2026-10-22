package privatepublisher

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type opaqueTokenControl struct {
	*lifecycleControl
	heartbeatErr   error
	heartbeatToken credentials.ManagedRunToken
	heartbeats     int
}

func (c *opaqueTokenControl) HeartbeatPrivateServiceRunHealth(_ context.Context, _, _ string, token credentials.ManagedRunToken, _ controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	c.heartbeatToken = token
	c.heartbeats++
	return controlv1.PrivateServiceRunState{}, c.heartbeatErr
}

func TestManagedRunPassesOpaqueTokenToControlAndCloses(t *testing.T) {
	for _, token := range []string{"opaque-server-run-token", ""} {
		name := "opaque"
		if token == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			config, control := lifecycleFixture(t)
			control.setup.RunToken = token
			boundary := errors.New("heartbeat boundary")
			opaque := &opaqueTokenControl{lifecycleControl: control, heartbeatErr: boundary}
			config.Control = opaque
			err := Publish(t.Context(), config)
			if token == "" {
				if !errors.Is(err, ErrPrivateStream) || opaque.heartbeats != 0 {
					t.Fatal("empty run token reached control heartbeat", err)
				}
			} else if !errors.Is(err, boundary) || opaque.heartbeats != 1 || opaque.heartbeatToken.String() != token {
				t.Fatal("publisher rejected or changed the server's opaque run token", err)
			}
			if control.closes != 1 || control.bad != nil {
				t.Fatal("publisher did not close the exact returned run and token", control.closes, control.bad)
			}
		})
	}
}
