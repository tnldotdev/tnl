package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var _ publisherservice.RunControl = (*Native)(nil)

type serviceBoundaryControl struct {
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
	n.NativeControl = NativeControl{Services: c}
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

type serviceHTTPForwardingControl struct {
	ServiceControl
	ctx          context.Context
	service, run string
	token        credentials.ServiceRunToken
	share        controlv1.RedeemServiceShareRequest
	browser      controlv1.ServiceBrowserRequest
	operation    string
	calls        int
	err          error
	redemption   controlv1.ShareRedemption
	handoff      controlv1.BrowserHandoffResponse
	session      controlv1.BrowserAccessResponse
}

func (*serviceHTTPForwardingControl) ControlURL() string { return "https://control.example" }

func (c *serviceHTTPForwardingControl) capture(ctx context.Context, operation, service, run string, token credentials.ServiceRunToken) {
	c.ctx, c.operation, c.service, c.run, c.token = ctx, operation, service, run, token
	c.calls++
}

func (c *serviceHTTPForwardingControl) RedeemServiceShare(ctx context.Context, service, run string, body controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
	c.capture(ctx, "share", service, run, token)
	c.share = body
	return c.redemption, c.err
}

func (c *serviceHTTPForwardingControl) RedeemServiceBrowserHandoff(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	c.capture(ctx, "handoff", service, run, token)
	c.browser = body
	return c.handoff, c.err
}

func (c *serviceHTTPForwardingControl) CheckServiceBrowserSession(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	c.capture(ctx, "session", service, run, token)
	c.browser = body
	return c.session, c.err
}

func (c *serviceHTTPForwardingControl) RevokeServiceBrowserSession(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceBrowserRequest) error {
	c.capture(ctx, "revoke", service, run, token)
	c.browser = body
	return c.err
}

func TestServiceShareForwardingPreservesSelectedRunTokenAndBody(t *testing.T) {
	for _, mode := range []string{"link", "handoff"} {
		t.Run(mode, func(t *testing.T) {
			native, _ := privateScopeFixture(t)
			control := &serviceHTTPForwardingControl{}
			native.NativeControl = NativeControl{Services: control}
			run, err := opaqueid.New(opaqueid.ServiceRunPrefix)
			if err != nil {
				t.Fatal(err)
			}
			share, err := opaqueid.New(opaqueid.SharePrefix)
			if err != nil {
				t.Fatal(err)
			}
			other, err := opaqueid.New(opaqueid.ServicePrefix)
			if err != nil {
				t.Fatal(err)
			}
			token, _, err := credentials.NewServiceRunToken()
			if err != nil {
				t.Fatal(err)
			}
			secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			body := controlv1.RedeemServiceShareRequest{RunNumber: 7, ShareId: &share, Secret: &secret}
			if mode == "handoff" {
				body.ShareId, body.Secret, body.HandoffToken = nil, nil, &secret
			}
			expected := controlv1.RedeemServiceShareRequest{RunNumber: 7, ShareId: new(share), Secret: new(secret)}
			if mode == "handoff" {
				expected.ShareId, expected.Secret, expected.HandoffToken = nil, nil, new(secret)
			}
			service := native.selectedServiceID
			control.redemption = controlv1.ShareRedemption{ShareId: share, NextUrl: "https://service.example/", CookieSecret: secret,
				Bridge: true, SchemaVersion: 1, ExpiresAt: time.Now().Add(time.Minute),
				Permission: controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service},
					Hostname: "service.example", Port: 443, VisitorToken: "visitor-permission", VisitorPolicyRevision: 11}}
			result, err := native.RedeemServiceShare(t.Context(), service, run, body, token)
			if err != nil || !reflect.DeepEqual(result, control.redemption) || control.calls != 1 || control.ctx != t.Context() ||
				control.service != service || control.run != run || control.token != token ||
				!reflect.DeepEqual(control.share, expected) || !reflect.DeepEqual(body, expected) {
				t.Fatal("share forwarding changed selected service, run, token, body, or response", err)
			}
			if _, err := native.RedeemServiceShare(t.Context(), other, run, body, token); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("share forwarding escaped its selected service", err)
			}
			unselected := *native
			unselected.selectedServiceID = ""
			if _, err := unselected.RedeemServiceShare(t.Context(), service, run, body, token); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("unselected share forwarding reached a control client", err)
			}
			failed := errors.New("share backend failed")
			control.err = failed
			if _, err := native.RedeemServiceShare(t.Context(), service, run, body, token); !errors.Is(err, failed) || control.calls != 2 {
				t.Fatal("share forwarding hid the selected service backend failure", err)
			}
			native.Services = nil
			if _, err := native.RedeemServiceShare(t.Context(), service, run, body, token); !errors.Is(err, ErrScope) || control.calls != 2 {
				t.Fatal("missing service capability fell back to a retired client", err)
			}
			if _, err := (*Native)(nil).RedeemServiceShare(t.Context(), service, run, body, token); !errors.Is(err, ErrScope) {
				t.Fatal("nil native share forwarding was not rejected", err)
			}
		})
	}
}

func TestServiceBrowserForwardingPreservesSelectedRunTokenAndShareContext(t *testing.T) {
	for _, operation := range []string{"handoff", "session", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			native, _ := privateScopeFixture(t)
			control := &serviceHTTPForwardingControl{}
			native.NativeControl = NativeControl{Services: control}
			run, err := opaqueid.New(opaqueid.ServiceRunPrefix)
			if err != nil {
				t.Fatal(err)
			}
			share, err := opaqueid.New(opaqueid.SharePrefix)
			if err != nil {
				t.Fatal(err)
			}
			other, err := opaqueid.New(opaqueid.ServicePrefix)
			if err != nil {
				t.Fatal(err)
			}
			token, _, err := credentials.NewServiceRunToken()
			if err != nil {
				t.Fatal(err)
			}
			secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			body := controlv1.ServiceBrowserRequest{RunNumber: 7, Secret: secret, ShareId: &share, ShareCookieSecret: &secret}
			expected := controlv1.ServiceBrowserRequest{RunNumber: 7, Secret: secret, ShareId: new(share), ShareCookieSecret: new(secret)}
			service := native.selectedServiceID
			control.handoff = controlv1.BrowserHandoffResponse{CookieSecret: secret, ReturnPath: "/original", NextUrl: new("https://service.example/next"),
				Bridge: new(true), ExpiresAt: time.Now().Add(time.Minute),
				Permission: &controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service},
					Hostname: "service.example", Port: 443, VisitorToken: "visitor-permission", VisitorPolicyRevision: 11}}
			control.session = controlv1.BrowserAccessResponse{IdentityId: "owner", DisplayName: "fixture owner", TeamMember: true, VisitAllowed: true}
			call := func(service string) error {
				switch operation {
				case "handoff":
					response, err := native.RedeemServiceBrowserHandoff(t.Context(), service, run, token, body)
					if err == nil && !reflect.DeepEqual(response, control.handoff) {
						t.Error("browser handoff changed the backend response")
					}
					return err
				case "session":
					response, err := native.CheckServiceBrowserSession(t.Context(), service, run, token, body)
					if err == nil && !reflect.DeepEqual(response, control.session) {
						t.Error("browser session changed the backend response")
					}
					return err
				default:
					return native.RevokeServiceBrowserSession(t.Context(), service, run, token, body)
				}
			}
			if err := call(service); err != nil || control.calls != 1 || control.operation != operation || control.ctx != t.Context() ||
				control.service != service || control.run != run || control.token != token ||
				!reflect.DeepEqual(control.browser, expected) || !reflect.DeepEqual(body, expected) {
				t.Fatal("browser forwarding changed selected service, run, token, or share context", err)
			}
			if err := call(other); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("browser forwarding escaped the selected service", err)
			}
			native.selectedServiceID = ""
			if err := call(service); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("unselected browser forwarding reached a control client", err)
			}
			native.selectedServiceID = service
			failed := errors.New("browser backend failed")
			control.err = failed
			if err := call(service); !errors.Is(err, failed) || control.calls != 2 {
				t.Fatal("browser forwarding hid the selected service backend failure", err)
			}
			native.Services = nil
			if err := call(service); !errors.Is(err, ErrScope) || control.calls != 2 {
				t.Fatal("missing browser capability fell back to a retired client", err)
			}
			native = nil
			if err := call(service); !errors.Is(err, ErrScope) {
				t.Fatal("nil native browser forwarding was not rejected", err)
			}
		})
	}
}
