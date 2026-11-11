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
	unusedControl
	ServiceControl
	token  credentials.ServiceRunToken
	health controlv1.ServiceRunHeartbeat
	calls  int
}

func (c *serviceBoundaryControl) HeartbeatServiceRun(_ context.Context, _, _ string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	c.token, c.calls = token, c.calls+1
	c.health = health
	return controlv1.ServiceRunState{}, nil
}

func (c *serviceBoundaryControl) CheckServiceBrowserSession(_ context.Context, _, _ string, token credentials.ServiceRunToken, _ controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	c.token, c.calls = token, c.calls+1
	return controlv1.BrowserAccessResponse{}, nil
}

func TestServiceControlBindsRunTokenAndExactScope(t *testing.T) {
	n, _ := privateScopeFixture(t)
	c := &serviceBoundaryControl{}
	n.NativeControl = NativeControl{PublicURLControl: c, Services: c}
	token, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	service := n.identity.serviceID
	health := controlv1.ServiceRunHeartbeat{Healthy: false, StreamCapacity: 7, ActiveStreams: 3}
	if _, err := n.HeartbeatServiceRun(t.Context(), service, "run", token, health); err != nil || c.token != token || c.health != health || c.calls != 1 {
		t.Fatal("service heartbeat changed its run token or report", err)
	}
	if _, err := n.HeartbeatServiceRun(t.Context(), "another-service", "run", token, health); !errors.Is(err, ErrScope) || c.calls != 1 {
		t.Fatal("service heartbeat escaped its grant", err)
	}
	if _, err := n.CheckServiceBrowserSession(t.Context(), service, "run", token, controlv1.ServiceBrowserRequest{}); err != nil || c.token != token || c.calls != 2 {
		t.Fatal("service browser preparation changed its run token", err)
	}
	if _, err := n.CheckServiceBrowserSession(t.Context(), "another-service", "run", token, controlv1.ServiceBrowserRequest{}); !errors.Is(err, ErrScope) || c.calls != 2 {
		t.Fatal("service control escaped its grant", err)
	}
}
