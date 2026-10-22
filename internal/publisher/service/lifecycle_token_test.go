package service

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type opaqueTokenControl struct {
	*lifecycleControl
	heartbeatErr   error
	heartbeatToken credentials.ServiceRunToken
	heartbeats     int
}

func (c *opaqueTokenControl) HeartbeatServiceRunHealth(_ context.Context, _, _ string, token credentials.ServiceRunToken, _ controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	c.heartbeatToken = token
	c.heartbeats++
	return controlv1.ServiceRunState{}, c.heartbeatErr
}

func TestServiceRunPassesOpaqueTokenToControlAndCloses(t *testing.T) {
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
