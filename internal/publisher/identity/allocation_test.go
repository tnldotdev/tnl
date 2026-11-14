package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type allocationSelectionAuthority struct {
	*publicationAuthority
	err error
}

func (a *allocationSelectionAuthority) ExchangePublisherAssertion(ctx context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	token, err := a.publicationAuthority.ExchangePublisherAssertion(ctx, client, grant, key, private)
	if err == nil && a.calls > 1 {
		return "", a.err
	}
	return token, err
}

type allocationControl struct {
	*privateScopeControl
	allocated                          controlv1.Service
	readErr, allocationErr, cleanupErr error
	allocations, cleanups              int
	cleanupID, cleanupAccess           string
	onRead                             func()
	checkCleanup                       func(context.Context)
}

func (c *allocationControl) AllocatePublisherService(_ context.Context, access string, _ controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if access != "access" {
		return controlv1.Service{}, ErrScope
	}
	c.allocations++
	return c.allocated, c.allocationErr
}

func (c *allocationControl) AllocateDeploymentPublication(ctx context.Context, access, team, project, deployment string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if team != c.allocated.TeamId || project != "project" || deployment != "production" {
		return controlv1.Service{}, ErrScope
	}
	return c.AllocatePublisherService(ctx, access, body)
}

func (c *allocationControl) GetPublisherService(ctx context.Context, service, access string) (controlv1.Service, error) {
	if c.onRead != nil {
		c.onRead()
	}
	if c.readErr != nil {
		return controlv1.Service{}, c.readErr
	}
	return c.privateScopeControl.GetPublisherService(ctx, service, access)
}

func (c *allocationControl) DeletePublisherService(ctx context.Context, access, service string) error {
	c.cleanups++
	c.cleanupID, c.cleanupAccess = service, access
	if c.checkCleanup != nil {
		c.checkCleanup(ctx)
	}
	return c.cleanupErr
}

func allocationFixture(t *testing.T) (*Native, *allocationControl, *publicationAuthority, controlv1.AllocateServiceRequest) {
	t.Helper()
	exact, selected := privateScopeFixture(t)
	domain, err := opaqueid.New(opaqueid.DomainPrefix)
	if err != nil {
		t.Fatal(err)
	}
	selected.service.Protocol = controlv1.ServiceProtocolHTTP
	selected.service.Ephemeral = true
	selected.service.DomainId = &domain
	selected.service.Endpoint = &controlv1.ServiceEndpoint{Hostname: "temporary.member.example.test", Port: 443, Public: true}
	control := &allocationControl{privateScopeControl: selected, allocated: selected.service}
	authority := &publicationAuthority{client: exact.identity.clientID, grant: exact.identity.grantID, key: exact.identity.keyID, private: exact.private}
	scope := nativeScope{clientID: authority.client, grantID: authority.grant, keyID: authority.key, teamID: selected.service.TeamId, kind: "namespace", domainID: domain, namespace: "member.example.test"}
	native, err := newNative(NativeControl{Services: control, Allocations: control}, authority, scope, exact.private)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return native, control, authority, controlv1.AllocateServiceRequest{InvocationId: invocation, Configuration: controlv1.ProjectServiceConfiguration{Target: "localhost:3000"}}
}

func TestAllocateServiceRetainsExactObservedCleanupOwnership(t *testing.T) {
	native, control, _, body := allocationFixture(t)
	service, err := native.AllocateService(t.Context(), body)
	if err != nil || service.Id != control.allocated.Id || native.selectedServiceID != service.Id || native.allocatedServiceID != service.Id || control.cleanups != 0 {
		t.Fatal("allocation did not keep its observed exact service", err)
	}
	fork, err := native.Fork()
	if err != nil || fork.allocatedServiceID != service.Id || fork.allocationInvocation != body.InvocationId {
		t.Fatal("fork lost exact cleanup ownership", err)
	}
	other, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := native.DeleteAllocatedService(t.Context(), other); !errors.Is(err, ErrScope) || control.cleanups != 0 {
		t.Fatal("cleanup accepted an unobserved sibling ID", err)
	}
	changed := body
	changed.InvocationId, err = opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.AllocateService(t.Context(), changed); !errors.Is(err, ErrScope) || control.allocations != 1 {
		t.Fatal("bound worker committed another invocation before rejecting selection", err)
	}
	if err := native.DeleteAllocatedService(t.Context(), service.Id); err != nil || control.cleanupID != service.Id || native.allocatedServiceID != "" {
		t.Fatal("exact cleanup did not retire its ownership", err)
	}
}

func TestAllocateServiceCleansObservedResponseAfterFailedSelection(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleaned", true: "cleanup-failed"}[cleanupFails], func(t *testing.T) {
			native, control, _, body := allocationFixture(t)
			primary, cleanupErr := errors.New("selection unavailable"), errors.New("delete unavailable")
			control.readErr = primary
			if cleanupFails {
				control.cleanupErr = cleanupErr
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control.onRead = cancel
			control.checkCleanup = func(ctx context.Context) {
				if ctx.Err() != nil {
					t.Error("cleanup inherited selection cancellation")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Error("cleanup has no independent bound")
				}
			}
			service, err := native.AllocateService(ctx, body)
			if !errors.Is(err, primary) || control.cleanups != 1 || control.cleanupID != control.allocated.Id || control.cleanupAccess != "access" || native.selectedServiceID != "" {
				t.Fatal("failed selection lost its primary error or actual cleanup credential", err)
			}
			if !cleanupFails {
				if service.Id != "" || native.allocatedServiceID != "" {
					t.Fatal("confirmed cleanup returned a live allocation")
				}
				return
			}
			if !errors.Is(err, cleanupErr) || service.Id != control.allocated.Id || native.allocatedServiceID != service.Id {
				t.Fatal("failed cleanup discarded exact allocation facts or an independent failure", err)
			}
			if _, err := native.PrepareServiceRun(t.Context(), service.Id, "not-selected", "access", ServiceDeclaration(service)); !errors.Is(err, ErrScope) {
				t.Fatal("cleanup-only ownership became publication selection", err)
			}
			control.cleanupErr = nil
			if err := native.DeleteAllocatedService(t.Context(), service.Id); err != nil || control.cleanups != 2 || native.allocatedServiceID != "" {
				t.Fatal("real caller could not retry observed-allocation cleanup", err)
			}
		})
	}
}

func TestAllocateServiceNeverDeletesMalformedAllocationResponses(t *testing.T) {
	for _, boundary := range []string{"id", "team", "saved", "protocol", "domain", "endpoint", "hostname", "port", "reachability"} {
		t.Run(boundary, func(t *testing.T) {
			native, control, _, body := allocationFixture(t)
			valid := control.allocated
			switch boundary {
			case "id":
				control.allocated.Id = "fabricated"
			case "team":
				control.allocated.TeamId = "another-team"
			case "saved":
				control.allocated.Ephemeral = false
			case "protocol":
				control.allocated.Protocol = controlv1.Postgres
			case "domain":
				domain, err := opaqueid.New(opaqueid.DomainPrefix)
				if err != nil {
					t.Fatal(err)
				}
				control.allocated.DomainId = &domain
			case "endpoint":
				control.allocated.Endpoint = nil
			default:
				endpoint := *control.allocated.Endpoint
				control.allocated.Endpoint = &endpoint
				switch boundary {
				case "hostname":
					endpoint.Hostname = "temporary.someone-else.example.test"
				case "port":
					endpoint.Port = 8443
				case "reachability":
					endpoint.Public = false
				}
			}
			service, err := native.AllocateService(t.Context(), body)
			if !errors.Is(err, ErrScope) || !strings.Contains(err.Error(), body.InvocationId) ||
				service.Id != "" || native.allocatedServiceID != "" || control.cleanups != 0 || control.reads != 0 {
				t.Fatal("malformed response was silently lost, selected, or deleted", err)
			}
			control.allocated = valid
			if service, err := native.AllocateService(t.Context(), body); err != nil || service.Id != valid.Id {
				t.Fatal("original invocation could not recover its authoritative allocation", err)
			}
		})
	}
}

func TestAllocateServiceDoesNotDeleteFabricatedSelectionID(t *testing.T) {
	native, control, _, body := allocationFixture(t)
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	control.service.Id = id
	service, err := native.AllocateService(t.Context(), body)
	if !errors.Is(err, ErrScope) || service.Id != "" || control.cleanupID != control.allocated.Id || control.cleanupID == id {
		t.Fatal("selection response changed which observed service was deleted", err)
	}
}

func TestAllocateServiceCleanupUsesOriginalCredentialAfterSelectionExchangeFails(t *testing.T) {
	native, control, authority, body := allocationFixture(t)
	primary := errors.New("selection exchange failed")
	native.authority = &allocationSelectionAuthority{publicationAuthority: authority, err: primary}
	service, err := native.AllocateService(t.Context(), body)
	if !errors.Is(err, primary) || service.Id != "" || control.cleanups != 1 ||
		control.cleanupAccess != "access" || control.cleanupID != control.allocated.Id || authority.calls != 2 {
		t.Fatal("cleanup depended on the failed second credential exchange", err)
	}
}

func TestAllocateServiceResponseLossRequiresOriginalInvocationRecovery(t *testing.T) {
	native, control, _, body := allocationFixture(t)
	primary := errors.New("allocation response lost")
	control.allocationErr = primary
	if service, err := native.AllocateService(t.Context(), body); !errors.Is(err, primary) ||
		service.Id != "" || control.cleanups != 0 || native.allocatedServiceID != "" {
		t.Fatal("response loss authorized cleanup of an unobserved service", err)
	}
	changed := body
	var err error
	changed.InvocationId, err = opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.AllocateService(t.Context(), changed); !errors.Is(err, ErrScope) || control.allocations != 1 {
		t.Fatal("response loss silently abandoned the original invocation", err)
	}
	control.allocationErr = nil
	if service, err := native.AllocateService(t.Context(), body); err != nil || service.Id != control.allocated.Id {
		t.Fatal("original invocation could not recover after response loss", err)
	}
}

func TestPrepareDeploymentAllocationRetainsCleanupOwnerOnFailure(t *testing.T) {
	native, control, authority, body := allocationFixture(t)
	primary, cleanupErr := errors.New("selection unavailable"), errors.New("delete unavailable")
	control.readErr, control.cleanupErr = primary, cleanupErr
	approval := controlv1.DeploymentCredential{ClientId: authority.client, GrantId: authority.grant, KeyId: authority.key, TeamId: native.identity.teamID, ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)}
	owner, service, err := PrepareDeploymentAllocation(t.Context(), control, authority, approval, authority.private, "production", body)
	if !errors.Is(err, primary) || !errors.Is(err, cleanupErr) || owner == nil || service == nil ||
		service.Id != control.allocated.Id || owner.selectedServiceID != "" ||
		owner.identity.kind != "deployment_credential" || owner.PublisherGrantID() != approval.GrantId || control.cleanupID != service.Id {
		t.Fatal("registered allocation lost its original cleanup owner or returned a ready selection", err)
	}
	control.cleanupErr = nil
	if err := owner.DeleteAllocatedService(t.Context(), service.Id); err != nil {
		t.Fatal("registered caller could not finish cleanup", err)
	}
}
