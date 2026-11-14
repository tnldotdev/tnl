package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var _ publisherservice.RunControl = (*Native)(nil)

type serviceBoundaryControl struct {
	unusedControl
	ServiceControl
	token       credentials.ServiceRunToken
	health      controlv1.ServiceRunHeartbeat
	calls       int
	policy      controlv1.PublisherVisitorPolicyRequest
	refresh     controlv1.VisitorTokenRequest
	policyToken string
}

func (c *serviceBoundaryControl) ReadPublisherVisitorPolicy(_ context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	c.policy, c.policyToken, c.calls = request, token, c.calls+1
	return controlv1.VisitorPolicyUpdate{}, nil
}

func (c *serviceBoundaryControl) IssueVisitorToken(_ context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	c.refresh, c.calls = request, c.calls+1
	return controlv1.VisitorTokenResponse{}, nil
}

func TestServiceHTTPPolicyAndTokenRenewalNeedNoRetiredURLClient(t *testing.T) {
	native, _ := privateScopeFixture(t)
	control := &serviceBoundaryControl{}
	native.NativeControl = NativeControl{Services: control}
	run, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	scope := controlv1.VisitorResourceScope{Kind: "service", Id: native.selectedServiceID}
	request := controlv1.PublisherVisitorPolicyRequest{Resource: scope, RunId: run, RunNumber: 2, AfterRevision: 5}
	if _, err := native.ReadPublisherVisitorPolicy(t.Context(), request, "run-token"); err != nil ||
		control.policy != request || control.policyToken != "run-token" || control.calls != 1 {
		t.Fatal("service policy required the retired URL client or lost its run binding", err)
	}
	refresh := controlv1.VisitorTokenRequest{Resource: scope}
	if _, err := native.IssueVisitorToken(t.Context(), refresh); err != nil || control.refresh.Resource != scope || control.calls != 2 {
		t.Fatal("service token renewal required the retired URL client", err)
	}
	for _, invalid := range []controlv1.VisitorResourceScope{
		{Kind: "public_url", Id: scope.Id},
		{Kind: "service", Id: "another-service"},
	} {
		request.Resource, refresh.Resource = invalid, invalid
		if _, err := native.ReadPublisherVisitorPolicy(t.Context(), request, "run-token"); !errors.Is(err, ErrScope) {
			t.Fatal("policy refresh escaped the selected service", err)
		}
		if _, err := native.IssueVisitorToken(t.Context(), refresh); !errors.Is(err, ErrScope) {
			t.Fatal("token renewal escaped the selected service", err)
		}
	}
	request.Resource = scope
	request.RunId = "another-run"
	if _, err := native.ReadPublisherVisitorPolicy(t.Context(), request, "run-token"); !errors.Is(err, ErrScope) || control.calls != 2 {
		t.Fatal("invalid service policy reached the control client", err)
	}
}

func (*serviceBoundaryControl) ControlURL() string { return "https://control.example" }

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
