package deployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type handlerTestAuthority struct {
	approval controlv1.DeploymentCredential
	private  ed25519.PrivateKey
	calls    int
}

func (a *handlerTestAuthority) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != a.approval.ClientId || grant != a.approval.GrantId || key != a.approval.KeyId || !bytes.Equal(private, a.private) {
		return "", publisheridentity.ErrScope
	}
	a.calls++
	return "registered-deployment-access", nil
}

type handlerTestControl struct {
	HandlerControl
	t           *testing.T
	context     context.Context
	approval    controlv1.DeploymentCredential
	service     controlv1.Service
	requests    []controlv1.AllocateServiceRequest
	deletes     []string
	lookups     int
	lookupErr   error
	allocateErr error
	deleteErr   error
}

func (*handlerTestControl) ControlURL() string { return "https://control.example.test" }

func (c *handlerTestControl) DeploymentPublication(ctx context.Context, token, team, project, deployment, service string) (controlv1.Service, error) {
	if ctx != c.context || token != "registered-deployment-access" || team != c.approval.TeamId || project != c.approval.ProjectKey || deployment != "production" || service != "web" {
		c.t.Fatal("named preparation changed its context or credential selection")
	}
	c.lookups++
	return c.service, c.lookupErr
}

func (c *handlerTestControl) GetPublisherService(ctx context.Context, service, token string) (controlv1.Service, error) {
	if !c.service.Ephemeral && ctx != c.context || service != c.service.Id || token != "registered-deployment-access" {
		c.t.Fatal("service preparation changed its context or exact selection")
	}
	return c.service, c.lookupErr
}

func (c *handlerTestControl) AllocateDeploymentPublication(_ context.Context, token, team, project, deployment string, request controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if token != "registered-deployment-access" || team != c.approval.TeamId || project != c.approval.ProjectKey || deployment != "production" {
		c.t.Fatal("temporary preparation changed its registered credential")
	}
	c.requests = append(c.requests, request)
	return c.service, c.allocateErr
}

func (c *handlerTestControl) DeletePublisherService(_ context.Context, token, id string) error {
	if token != "registered-deployment-access" || id != c.service.Id {
		c.t.Fatal("cleanup selected another service or credential")
	}
	c.deletes = append(c.deletes, id)
	return c.deleteErr
}

func handlerFixture(t *testing.T) (HandlerOptions, *handlerTestControl) {
	t.Helper()
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approval := controlv1.DeploymentCredential{
		ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix),
		TeamId: id(opaqueid.TeamPrefix), ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour),
	}
	control := &handlerTestControl{t: t, context: t.Context(), approval: approval, service: controlv1.Service{
		Id: id(opaqueid.ServicePrefix), TeamId: approval.TeamId, Name: "web", Protocol: controlv1.ServiceProtocolHTTP,
		Enabled: true, TrustRevision: 1, EndpointRevision: 1, DomainId: new(id(opaqueid.DomainPrefix)),
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true},
	}}
	return HandlerOptions{Control: control, Authority: &handlerTestAuthority{approval: approval, private: private}, Approval: approval, Private: private,
		Deployment: "production", Service: "web", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}, control
}

func TestHandlerNamedPreparationKeepsServiceOwnerAndNeverDeletes(t *testing.T) {
	options, control := handlerFixture(t)
	prepared, err := PrepareHandler(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Config.Handler == nil || prepared.Config.Target != "" || prepared.Config.Control != prepared.native ||
		prepared.Config.PublisherIdentityID != options.Approval.ClientId || prepared.Config.PublisherGrantID != options.Approval.GrantId || prepared.Config.PublisherKeyID != options.Approval.KeyId ||
		prepared.Config.ServiceID != control.service.Id || control.lookups != 1 || len(control.requests) != 0 {
		t.Fatal("handler preparation replaced the scoped service run owner")
	}
	prepared.Service.Id = "mutated"
	prepared.Service.Endpoint.Hostname = "changed.example.test"
	if prepared.Config.ServiceID != control.service.Id || prepared.Config.Metadata.Protocol != controlv1.ServiceProtocolHTTP {
		t.Fatal("public preparation snapshot mutated serving configuration")
	}
	if err := prepared.Cleanup(t.Context()); err != nil || len(control.deletes) != 0 {
		t.Fatal("named handler deleted a retained service", err)
	}
}

func TestHandlerTemporaryPreparationFreezesAppAllocationAndCleanup(t *testing.T) {
	options, control := handlerFixture(t)
	options.Service = ""
	options.Temporary = &TemporaryHandlerOptions{AccessMode: controlv1.Anonymous, IP: []string{"192.0.2.3"}, RequirePostQuantum: true,
		Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(9), Concurrency: new(3)}}
	control.service.Ephemeral = true
	control.service.ExpiresAt = new(options.Approval.ExpiresAt)
	control.service.RequirePostQuantum = true
	control.service.HttpLimits = &controlv1.ProjectHTTPApplicationLimits{Total: new(9), Concurrency: new(3)}
	prepared, err := PrepareHandler(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	request := control.requests[0]
	if request.Configuration.Target != "app" || request.Configuration.TargetTls != nil || !*request.Configuration.Public ||
		!*request.Configuration.Ephemeral || request.ExpiresAt == nil || !request.ExpiresAt.Equal(options.Approval.ExpiresAt) ||
		!reflect.DeepEqual(*request.Configuration.Http.Access.Ip, []string{"192.0.2.3/32"}) || prepared.Config.Target != "" {
		t.Fatal("inline allocation used a dummy target or lost exact settings", request)
	}
	*options.Temporary.Limits.Total = 1
	options.Temporary.IP[0] = "203.0.113.1"
	prepared.Service = controlv1.Service{}
	failure := errors.New("durable delete unavailable")
	control.deleteErr = failure
	if err := prepared.Cleanup(t.Context()); !errors.Is(err, failure) {
		t.Fatal("cleanup hid independent allocation deletion failure", err)
	}
	control.deleteErr = nil
	if err := prepared.Cleanup(t.Context()); err != nil {
		t.Fatal("cleanup did not retain exact allocation for retry", err)
	}
	if err := prepared.Cleanup(t.Context()); err != nil || len(control.deletes) != 2 || control.deletes[0] != control.deletes[1] {
		t.Fatal("completed cleanup replayed deletion or changed allocation", err, control.deletes)
	}
	if *prepared.request.Configuration.Http.Limits.Total != 9 || (*prepared.request.Configuration.Http.Access.Ip)[0] != "192.0.2.3/32" {
		t.Fatal("caller mutated cleanup declaration")
	}
}

func TestHandlerTemporaryLostAllocationReplyRetainsRecovery(t *testing.T) {
	options, control := handlerFixture(t)
	options.Service = ""
	control.service.Ephemeral, control.service.ExpiresAt = true, new(options.Approval.ExpiresAt)
	failure := errors.New("allocation reply lost")
	control.allocateErr = failure
	prepared, err := PrepareHandler(t.Context(), options)
	if prepared == nil || !errors.Is(err, failure) {
		t.Fatal("lost allocation reply hid cleanup ownership", err)
	}
	control.allocateErr = nil
	if err := prepared.Cleanup(t.Context()); err != nil || len(control.requests) != 2 || len(control.deletes) != 1 ||
		!reflect.DeepEqual(control.requests[0], control.requests[1]) {
		t.Fatal("ambiguous allocation cleanup did not recover the original invocation", err)
	}
}

func TestHandlerPreparationRejectsMixedModesAndTargetTrust(t *testing.T) {
	for _, boundary := range []string{"missing handler", "mixed settings", "target trust", "private endpoint", "invalid limits", "empty IP", "invalid IP", "invalid mode"} {
		t.Run(boundary, func(t *testing.T) {
			options, control := handlerFixture(t)
			switch boundary {
			case "missing handler":
				options.Handler = nil
			case "mixed settings":
				options.Temporary = &TemporaryHandlerOptions{}
			case "target trust":
				control.service.TargetTls = &controlv1.ServiceTargetTLS{Hostname: "upstream.example.test", Digest: "invalid"}
			case "private endpoint":
				control.service.Endpoint.Public = false
			default:
				options.Service = ""
				options.Temporary = &TemporaryHandlerOptions{}
				switch boundary {
				case "invalid limits":
					options.Temporary.Limits = &controlv1.ProjectHTTPApplicationLimits{Total: new(-1)}
				case "empty IP":
					options.Temporary.IP = []string{}
				case "invalid IP":
					options.Temporary.IP = []string{"not an IP"}
				case "invalid mode":
					options.Temporary.AccessMode = "unrecognized"
				}
			}
			prepared, err := PrepareHandler(t.Context(), options)
			if err == nil || prepared != nil && prepared.Config.Handler != nil || len(control.requests) != 0 || len(control.deletes) != 0 {
				t.Fatal("invalid handler selection reached allocation or serving", err)
			}
		})
	}
}
