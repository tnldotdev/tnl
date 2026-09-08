package controlstate_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestLoadCadence(t *testing.T) {
	controlstate.RunCadenceLoad(t, func(database *controlstate.Database, now func() time.Time, resnapshot <-chan struct{}) (ingress.ControlClient, error) {
		client, err := ingressapi.NewDirectClient(ingressapi.DirectConfig{
			Store: database, LeaseDuration: 30 * time.Second, Now: now,
		})
		if err != nil {
			return nil, err
		}
		return &cadenceIngressClient{ControlClient: client, resnapshot: resnapshot}, nil
	})
}

// Exercise the real controller's resnapshot path once during relay recovery.
// All ordinary calls use the production standalone adapter and service methods.
type cadenceIngressClient struct {
	ingress.ControlClient
	resnapshot <-chan struct{}
	requested  bool // Only the controller's serial routing loop accesses this.
}

func (c *cadenceIngressClient) GetIngressRoutingTableEvents(ctx context.Context, id ingressv1.IngressID, params ingressv1.GetIngressRoutingTableEventsParams) (ingressv1.IngressRoutingTablePage, error) {
	if !c.requested {
		select {
		case <-c.resnapshot:
			c.requested = true
			if os.Getenv("TNL_TEST_LOAD_RETENTION") != "" {
				// Restore an old consumer cursor against the real published floor.
				// The production API, not this wrapper, must require a resnapshot.
				params.After = 0
				return c.ControlClient.GetIngressRoutingTableEvents(ctx, id, params)
			}
			return ingressv1.IngressRoutingTablePage{}, serviceapi.NewProblemError(http.StatusConflict, "routing_table_resnapshot_required", "cadence recovery resnapshot")
		default:
		}
	}
	return c.ControlClient.GetIngressRoutingTableEvents(ctx, id, params)
}
