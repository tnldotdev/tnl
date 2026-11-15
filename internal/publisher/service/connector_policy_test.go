package service

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type sharedPolicyControl struct {
	*lifecycleControl
	reads atomic.Int32
}

func (c *sharedPolicyControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	c.reads.Add(1)
	return c.lifecycleControl.ReadPublisherVisitorPolicy(ctx, request, token)
}

func TestHTTPAndConnectorShareRunPolicyOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, base := lifecycleFixture(t)
		approved, err := base.GetPublisherService(t.Context(), cfg.ServiceID, "")
		if err != nil {
			t.Fatal(err)
		}
		approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
		base.approved = &approved
		control := &sharedPolicyControl{lifecycleControl: base}
		prepared, err := newManagedPrepared(base.prep, approved, cfg)
		if err != nil {
			t.Fatal(err)
		}
		bound, err := prepared.Activate(base.setup)
		if err != nil {
			t.Fatal(err)
		}
		defer bound.Invalidate()
		_, closeRun, err := configureServiceRun(t.Context(), cfg, prepared, base.setup, control, cfg.State, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer closeRun()
		if err := bound.PrepareConnectorPolicy(t.Context(), control, credentials.ServiceRunToken(base.setup.RunToken)); err != nil {
			t.Fatal(err)
		}
		frontend := prepared.connectorHTTP.(HTTP)
		if control.reads.Load() != 1 || prepared.policy != frontend.Policy {
			t.Fatal("HTTP and connector access prepared separate run policies", control.reads.Load())
		}
		if err := bound.PrepareConnectorPolicy(t.Context(), control, credentials.ServiceRunToken(base.setup.RunToken)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if control.reads.Load() != 2 {
			t.Fatal("connector preparation started another policy refresh worker", control.reads.Load())
		}
		bound.Invalidate()
		if _, enabled, _ := frontend.Policy.Current(); !enabled {
			t.Fatal("connector invalidation closed a policy owned by the HTTP run")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if control.reads.Load() != 3 {
			t.Fatal("connector invalidation stopped the HTTP run's policy refresh", control.reads.Load())
		}
		closeRun()
		if _, enabled, _ := prepared.policy.Current(); enabled {
			t.Fatal("run cleanup did not close the shared policy")
		}
	})
}
