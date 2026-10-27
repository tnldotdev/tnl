package identity

import (
	"context"
	"errors"
	"testing"

	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var _ publisherservice.RunControl = (*Native)(nil)

type serviceBoundaryControl struct {
	NativeControl
	serviceRunControl
	ServiceCertificateControl
	serviceHTTPControl
	token credentials.ServiceRunToken
	calls int
}

func (c *serviceBoundaryControl) HeartbeatServiceRunHealth(_ context.Context, _, _ string, token credentials.ServiceRunToken, _ controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	c.token, c.calls = token, c.calls+1
	return controlv1.ServiceRunState{}, nil
}

func (c *serviceBoundaryControl) RedeemServiceBrowserHandoff(_ context.Context, _, _ string, token credentials.ServiceRunToken, _ controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	c.token, c.calls = token, c.calls+1
	return controlv1.BrowserHandoffResponse{}, nil
}

func (c *serviceBoundaryControl) DeliverNativePeerPair(_ context.Context, _, _, _ string, _ int64, token credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	c.token, c.calls = token, c.calls+1
	return controlv1.NativePeerPairDelivery{}, nil
}

func TestServiceControlBindsRunTokenAndExactScope(t *testing.T) {
	n, _ := privateScopeFixture(t)
	c := &serviceBoundaryControl{}
	n.NativeControl = c
	token, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	service := n.identity.serviceID
	if _, err := n.HeartbeatServiceRunHealth(t.Context(), service, "run", token, controlv1.ServiceRunHeartbeat{}); err != nil || c.token != token || c.calls != 1 {
		t.Fatal("service heartbeat changed its run token", err)
	}
	if _, err := n.RedeemServiceBrowserHandoff(t.Context(), service, "run", token, controlv1.ServiceBrowserRequest{}); err != nil || c.token != token || c.calls != 2 {
		t.Fatal("service browser handoff changed its run token", err)
	}
	if _, err := n.RedeemServiceBrowserHandoff(t.Context(), "another-service", "run", token, controlv1.ServiceBrowserRequest{}); !errors.Is(err, ErrScope) || c.calls != 2 {
		t.Fatal("service control escaped its grant", err)
	}
	if _, err := n.DeliverNativePeerPair(t.Context(), service, "run", "pair", 1, token); err != nil || c.token != token || c.calls != 3 {
		t.Fatal("native peer delivery changed its run token", err)
	}
	if _, err := n.DeliverNativePeerPair(t.Context(), "another-service", "run", "pair", 1, token); !errors.Is(err, ErrScope) || c.calls != 3 {
		t.Fatal("native peer delivery escaped its service grant", err)
	}
}
