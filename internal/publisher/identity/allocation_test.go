package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
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
	allocated                                   controlv1.Service
	readErr, allocationErr, cleanupErr          error
	allocations, cleanups                       int
	namespaceAllocations, deploymentAllocations int
	cleanupID, cleanupAccess                    string
	onRead                                      func()
	checkAllocation                             func(context.Context, string, controlv1.AllocateServiceRequest)
	checkCleanup                                func(context.Context)
}

func (c *allocationControl) AllocatePublisherService(ctx context.Context, access string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	c.namespaceAllocations++
	return c.allocate(ctx, access, body)
}

func (c *allocationControl) allocate(ctx context.Context, access string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if access != "access" {
		return controlv1.Service{}, ErrScope
	}
	c.allocations++
	if c.checkAllocation != nil {
		c.checkAllocation(ctx, access, body)
	}
	return c.allocated, c.allocationErr
}

func (c *allocationControl) AllocateDeploymentPublication(ctx context.Context, access, team, project, deployment string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	c.deploymentAllocations++
	if team != c.service.TeamId || project != "project" || deployment != "production" {
		return controlv1.Service{}, ErrScope
	}
	return c.allocate(ctx, access, body)
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

func deploymentAllocationFixture(t *testing.T) (*Native, *allocationControl, *publicationAuthority, controlv1.AllocateServiceRequest) {
	t.Helper()
	original, control, authority, body := allocationFixture(t)
	approval := controlv1.DeploymentCredential{ClientId: authority.client, GrantId: authority.grant, KeyId: authority.key,
		TeamId: original.identity.teamID, ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)}
	native, err := NewDeploymentAllocator(control, authority, approval, authority.private, "production")
	if err != nil {
		t.Fatal(err)
	}
	return native, control, authority, body
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
			until := time.Now().Add(time.Second)
			native.WithShutdownDeadline(func() time.Time { return until })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control.onRead = cancel
			control.checkCleanup = func(ctx context.Context) {
				if ctx.Err() != nil {
					t.Error("cleanup inherited selection cancellation")
				}
				deadline, ok := ctx.Deadline()
				if !ok || !deadline.Equal(until) {
					t.Error("cleanup did not use the owner's original deadline", deadline, until)
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
			retry, stop := context.WithDeadline(context.WithoutCancel(ctx), until)
			defer stop()
			if err := native.DeleteAllocatedService(retry, service.Id); err != nil || control.cleanups != 2 || native.allocatedServiceID != "" {
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

func TestDeploymentAllocationRetainsCleanupOwnerOnFailure(t *testing.T) {
	native, control, authority, body := allocationFixture(t)
	primary, cleanupErr := errors.New("selection unavailable"), errors.New("delete unavailable")
	control.readErr, control.cleanupErr = primary, cleanupErr
	approval := controlv1.DeploymentCredential{ClientId: authority.client, GrantId: authority.grant, KeyId: authority.key, TeamId: native.identity.teamID, ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)}
	owner, err := NewDeploymentAllocator(control, authority, approval, authority.private, "production")
	if err != nil {
		t.Fatal(err)
	}
	service, err := owner.AllocateService(t.Context(), body)
	if !errors.Is(err, primary) || !errors.Is(err, cleanupErr) ||
		service.Id != control.allocated.Id || owner.selectedServiceID != "" ||
		owner.identity.kind != "deployment_credential" || owner.PublisherGrantID() != approval.GrantId || control.cleanupID != service.Id {
		t.Fatal("registered allocation lost its original cleanup owner or returned a ready selection", err)
	}
	control.cleanupErr = nil
	if err := owner.DeleteAllocatedService(t.Context(), service.Id); err != nil {
		t.Fatal("registered caller could not finish cleanup", err)
	}
}

func TestDeploymentAllocationPreservesUncertainOwnerForOriginalRetry(t *testing.T) {
	for _, boundary := range []string{"lost-reply", "invalid-id", "wrong-team", "saved-service"} {
		t.Run(boundary, func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			approval := controlv1.DeploymentCredential{ClientId: authority.client, GrantId: authority.grant, KeyId: authority.key,
				TeamId: native.identity.teamID, ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)}
			body.ExpiresAt = new(time.Now().Add(time.Minute))
			body.Configuration.Traffic = &controlv1.TrafficSelection{Connections: new(7)}
			original, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			control.checkAllocation = func(ctx context.Context, access string, got controlv1.AllocateServiceRequest) {
				t.Helper()
				document, err := json.Marshal(got)
				deadline, bounded := ctx.Deadline()
				if err != nil || !bytes.Equal(document, original) || access != "access" || !bounded || !deadline.Equal(approval.ExpiresAt) {
					t.Fatal("deployment retry changed the original invocation, request, access, or context", err)
				}
			}
			valid := control.allocated
			primary := error(ErrScope)
			switch boundary {
			case "lost-reply":
				primary = errors.New("deployment allocation reply lost")
				control.allocationErr = primary
			case "invalid-id":
				control.allocated.Id = "fabricated-service"
			case "wrong-team":
				control.allocated.TeamId = "another-team"
			case "saved-service":
				control.allocated.Ephemeral = false
			}
			owner, err := NewDeploymentAllocator(control, authority, approval, authority.private, "production")
			if err != nil {
				t.Fatal(err)
			}
			service, err := owner.AllocateService(t.Context(), body)
			if !errors.Is(err, primary) || service.Id != "" || !strings.Contains(err.Error(), body.InvocationId) {
				t.Fatal("uncertain deployment allocation lost its native owner or exposed an unvalidated service", err)
			}
			assertOriginalIdentity := func(owner *Native) {
				t.Helper()
				if owner.identity.kind != "deployment_credential" || owner.identity.clientID != approval.ClientId ||
					owner.identity.grantID != approval.GrantId || owner.identity.keyID != approval.KeyId || owner.identity.teamID != approval.TeamId ||
					owner.identity.serviceID != "" || owner.identity.domainID != "" || owner.identity.namespace != "" ||
					owner.allocationInvocation != body.InvocationId || !bytes.Equal(owner.private, authority.private) {
					t.Fatal("deployment allocation changed the original invocation, grant, key, or authority family")
				}
			}
			assertOriginalIdentity(owner)
			if owner.selectedServiceID != "" || owner.allocatedServiceID != "" || owner.allocationFinished ||
				control.allocations != 1 || control.reads != 0 || control.cleanups != 0 || authority.calls != 1 {
				t.Fatal("uncertainty became publication selection or deletion authority")
			}
			for _, guessed := range []string{valid.Id, "fabricated-service"} {
				if err := owner.DeleteAllocatedService(t.Context(), guessed); !errors.Is(err, ErrScope) {
					t.Fatal("uncertain owner authorized deleting an unobserved service", err)
				}
			}
			if control.cleanups != 0 || authority.calls != 1 {
				t.Fatal("unobserved deletion reached control or exchanged another credential")
			}
			control.allocated, control.allocationErr = valid, nil
			recovered, err := owner.Fork()
			if err != nil {
				t.Fatal(err)
			}
			service, err = recovered.AllocateService(t.Context(), body)
			if err != nil || service.Id != valid.Id {
				t.Fatal("same approval and original request could not recover the authoritative allocation", err)
			}
			assertOriginalIdentity(recovered)
			if recovered.selectedServiceID != valid.Id || recovered.allocatedServiceID != valid.Id ||
				control.allocations != 2 || control.reads != 1 || control.cleanups != 0 || authority.calls != 3 {
				t.Fatal("deployment retry selected or owned a different allocation")
			}
			if err := recovered.DeleteAllocatedService(t.Context(), service.Id); err != nil || control.cleanupID != valid.Id ||
				control.cleanupAccess != "access" || control.cleanups != 1 || control.allocations != 2 || authority.calls != 4 ||
				recovered.allocatedServiceID != "" || !recovered.allocationFinished || control.namespaceAllocations != 0 || control.deploymentAllocations != 2 {
				t.Fatal("recovered deployment could not delete its exact observed allocation", err)
			}
		})
	}
}

type failedAllocationExchange struct {
	*publicationAuthority
	err error
}

func (a *failedAllocationExchange) ExchangePublisherAssertion(ctx context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if _, err := a.publicationAuthority.ExchangePublisherAssertion(ctx, client, grant, key, private); err != nil {
		return "", err
	}
	return "", a.err
}

func TestDeploymentAllocationDoesNotAttemptBeforeSignedAccess(t *testing.T) {
	for _, boundary := range []string{"signed-exchange", "expired-approval"} {
		t.Run(boundary, func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			approval := controlv1.DeploymentCredential{ClientId: authority.client, GrantId: authority.grant, KeyId: authority.key,
				TeamId: native.identity.teamID, ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)}
			exchanger := AssertionExchanger(authority)
			primary := error(ErrScope)
			exchanges := 0
			if boundary == "signed-exchange" {
				primary = errors.New("publisher assertion exchange failed")
				exchanger = &failedAllocationExchange{publicationAuthority: authority, err: primary}
				exchanges = 1
			} else {
				approval.ExpiresAt = time.Now().Add(-time.Second)
			}
			owner, err := NewDeploymentAllocator(control, exchanger, approval, authority.private, "production")
			if boundary == "signed-exchange" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = owner.AllocateService(t.Context(), body)
				if cleanup := owner.CleanupServiceAllocation(t.Context(), body); cleanup != nil {
					t.Fatal("pre-attempt cleanup made another attempt", cleanup)
				}
			} else if owner != nil {
				t.Fatal("expired approval created an allocator")
			}
			if !errors.Is(err, primary) || control.allocations != 0 ||
				control.reads != 0 || control.cleanups != 0 || authority.calls != exchanges {
				t.Fatal("pre-attempt failure exposed allocation ownership or performed an allocation", err)
			}
		})
	}
}

func TestDeploymentAllocationConfirmedCleanupIsTerminalAfterSelectionFailure(t *testing.T) {
	for _, alreadyDeleted := range []bool{false, true} {
		t.Run(map[bool]string{false: "deleted", true: "not-found"}[alreadyDeleted], func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			approval := controlv1.DeploymentCredential{ClientId: authority.client, GrantId: authority.grant, KeyId: authority.key,
				TeamId: native.identity.teamID, ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)}
			primary := errors.New("deployment service selection failed")
			control.readErr = primary
			if alreadyDeleted {
				control.cleanupErr = clientcontrol.ErrNotFound
			}
			owner, err := NewDeploymentAllocator(control, authority, approval, authority.private, "production")
			if err != nil {
				t.Fatal(err)
			}
			service, err := owner.AllocateService(t.Context(), body)
			if !errors.Is(err, primary) || service.Id != "" || !owner.allocationFinished || control.allocations != 1 || control.cleanups != 1 ||
				control.cleanupID != control.allocated.Id || control.cleanupAccess != "access" || authority.calls != 2 {
				t.Fatal("confirmed cleanup retained ownership or lost the exact observed allocation credential", err)
			}
			for range 3 {
				if err := owner.CleanupServiceAllocation(t.Context(), body); err != nil || control.allocations != 1 || control.cleanups != 1 || authority.calls != 2 {
					t.Fatal("confirmed cleanup replayed a deleted allocation or returned the publication failure", err)
				}
			}
		})
	}
}

func TestCleanupServiceAllocationRecoversOriginalRequestWithoutServiceSelection(t *testing.T) {
	native, control, authority, body := allocationFixture(t)
	body.ExpiresAt = new(time.Now().Add(time.Hour))
	body.Configuration.Protocol, body.Configuration.Public, body.Configuration.Ephemeral = new(controlv1.ServiceProtocolHTTP), new(true), new(true)
	body.Configuration.Traffic = &controlv1.TrafficSelection{Connections: new(11), TotalDownloadBytes: new(int64(4096))}
	body.Configuration.Http = &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Restricted), Ip: &[]string{"192.0.2.0/24"}}}
	original, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	control.checkAllocation = func(ctx context.Context, access string, got controlv1.AllocateServiceRequest) {
		t.Helper()
		document, err := json.Marshal(got)
		if err != nil || !bytes.Equal(document, original) || access != "access" || ctx != t.Context() {
			t.Fatal("allocation recovery changed the original request, credential, or context", err)
		}
	}
	lost := errors.New("allocation response lost")
	control.allocationErr = lost
	if _, err := native.AllocateService(t.Context(), body); !errors.Is(err, lost) ||
		native.allocatedServiceID != "" || native.allocationFinished || authority.calls != 1 {
		t.Fatal("lost response did not retain unresolved invocation ownership", err)
	}
	control.allocationErr = nil
	control.readErr = errors.New("service selection is unavailable during cleanup")
	control.onRead = func() { t.Error("cleanup attempted service selection") }
	native.Services = nil
	if err := native.CleanupServiceAllocation(t.Context(), body); err != nil || control.allocations != 2 || control.cleanups != 1 ||
		control.reads != 0 || control.cleanupID != control.allocated.Id || control.cleanupAccess != "access" ||
		native.allocatedServiceID != "" || native.selectedServiceID != "" || !native.allocationFinished || authority.calls != 2 {
		t.Fatal("recovery did not delete the observed allocation using its original signed access without selection", err)
	}
	if err := native.CleanupServiceAllocation(t.Context(), body); err != nil || control.allocations != 2 || control.cleanups != 1 || authority.calls != 2 {
		t.Fatal("completed recovery replayed its invocation or exchanged another credential", err)
	}
}

func TestCleanupServiceAllocationConfirmedDeletionIsTerminalAndCopiedByFork(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "deleted"},
		{name: "not-found", err: clientcontrol.ErrNotFound},
		{name: "wrapped-not-found", err: fmt.Errorf("delete response: %w", clientcontrol.ErrNotFound)},
		{name: "joined-only-not-found", err: errors.Join(clientcontrol.ErrNotFound, fmt.Errorf("already removed: %w", clientcontrol.ErrNotFound))},
	} {
		t.Run(test.name, func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			service, err := native.AllocateService(t.Context(), body)
			if err != nil {
				t.Fatal(err)
			}
			control.cleanupErr = test.err
			control.readErr = errors.New("selection must not be repeated during cleanup")
			if err := native.CleanupServiceAllocation(t.Context(), body); err != nil || !native.allocationFinished ||
				native.allocatedServiceID != "" || control.cleanupID != service.Id || control.allocations != 1 || control.cleanups != 1 || control.reads != 1 || authority.calls != 3 {
				t.Fatal("confirmed deletion was not terminal for its exact observed allocation", err)
			}
			fork, err := native.Fork()
			if err != nil || !fork.allocationFinished || fork.allocationInvocation != body.InvocationId {
				t.Fatal("fork lost terminal invocation ownership", err)
			}
			other := body
			other.InvocationId, err = opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				t.Fatal(err)
			}
			for _, worker := range []*Native{native, fork} {
				if err := worker.CleanupServiceAllocation(t.Context(), body); err != nil {
					t.Fatal("completed cleanup was not idempotent", err)
				}
				if err := worker.CleanupServiceAllocation(t.Context(), other); !errors.Is(err, ErrScope) {
					t.Fatal("terminal cleanup accepted a different invocation", err)
				}
				if _, err := worker.AllocateService(t.Context(), body); !errors.Is(err, ErrScope) {
					t.Fatal("completed invocation allocated another service", err)
				}
			}
			if control.allocations != 1 || control.cleanups != 1 || control.reads != 1 || authority.calls != 3 {
				t.Fatal("terminal cleanup or its fork performed another RPC")
			}
		})
	}
}

func TestCleanupServiceAllocationPreservesIndependentDeleteFailuresForRetry(t *testing.T) {
	independent := errors.New("cleanup storage failed")
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "independent", err: independent},
		{name: "not-found-with-independent", err: errors.Join(clientcontrol.ErrNotFound, independent)},
		{name: "wrapped-not-found-with-independent", err: fmt.Errorf("delete response: %w", errors.Join(clientcontrol.ErrNotFound, independent))},
		{name: "canceled-with-independent", err: errors.Join(context.Canceled, independent)},
	} {
		t.Run(test.name, func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			service, err := native.AllocateService(t.Context(), body)
			if err != nil {
				t.Fatal(err)
			}
			control.cleanupErr = test.err
			control.readErr = errors.New("selection must not be repeated during cleanup")
			if err := native.CleanupServiceAllocation(t.Context(), body); !errors.Is(err, independent) ||
				native.allocationFinished || native.allocatedServiceID != service.Id || control.cleanupID != service.Id || control.cleanups != 1 {
				t.Fatal("cleanup hid an independent failure or discarded its exact retry ownership", err)
			}
			pending, err := native.Fork()
			if err != nil || pending.allocationFinished || pending.allocatedServiceID != service.Id {
				t.Fatal("fork lost pending cleanup ownership", err)
			}
			control.cleanupErr = nil
			if err := pending.CleanupServiceAllocation(t.Context(), body); err != nil || !pending.allocationFinished || pending.allocatedServiceID != "" ||
				control.cleanupID != service.Id || control.cleanupAccess != "access" || control.cleanups != 2 ||
				control.allocations != 1 || control.reads != 1 || authority.calls != 4 {
				t.Fatal("pending cleanup could not retry the exact delete without selection or allocation replay", err)
			}
		})
	}
}

func TestCleanupServiceAllocationRetainsUnresolvedOwnershipAfterRecoveryFailures(t *testing.T) {
	for _, boundary := range []string{"signed-access", "allocation-replay"} {
		t.Run(boundary, func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			lost := errors.New("allocation response lost")
			control.allocationErr = lost
			if _, err := native.AllocateService(t.Context(), body); !errors.Is(err, lost) {
				t.Fatal(err)
			}
			primary := errors.New("cleanup recovery unavailable")
			if boundary == "signed-access" {
				native.authority = &allocationSelectionAuthority{publicationAuthority: authority, err: primary}
				control.allocationErr = nil
			} else {
				control.allocationErr = primary
			}
			if err := native.CleanupServiceAllocation(t.Context(), body); !errors.Is(err, primary) || control.cleanups != 0 ||
				control.reads != 0 || native.allocationInvocation != body.InvocationId || native.allocationFinished || native.allocatedServiceID != "" {
				t.Fatal("failed recovery deleted an unobserved ID or discarded unresolved invocation ownership", err)
			}
			expectedAllocations := 1
			if boundary == "allocation-replay" {
				expectedAllocations++
			}
			if control.allocations != expectedAllocations || authority.calls != 2 {
				t.Fatal("failed recovery replayed outside its actual signed access", control.allocations, authority.calls)
			}
			native.authority, control.allocationErr = authority, nil
			native.Services = nil
			if err := native.CleanupServiceAllocation(t.Context(), body); err != nil || control.allocations != expectedAllocations+1 ||
				control.cleanups != 1 || control.cleanupID != control.allocated.Id || control.reads != 0 ||
				!native.allocationFinished || native.allocatedServiceID != "" || authority.calls != 3 {
				t.Fatal("original invocation could not recover cleanup after an independent failure", err)
			}
		})
	}
}

func TestCleanupServiceAllocationNoAttemptWrongInvocationAndExpiredReplay(t *testing.T) {
	t.Run("no-attempt", func(t *testing.T) {
		native, control, authority, body := allocationFixture(t)
		if err := native.CleanupServiceAllocation(t.Context(), body); err != nil ||
			control.allocations != 0 || control.cleanups != 0 || authority.calls != 0 || native.allocationFinished {
			t.Fatal("cleanup attempted an invocation that this worker never started", err)
		}
	})
	t.Run("wrong-invocation", func(t *testing.T) {
		native, control, authority, body := allocationFixture(t)
		native.allocationInvocation = body.InvocationId
		other := body
		var err error
		other.InvocationId, err = opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := native.CleanupServiceAllocation(t.Context(), other); !errors.Is(err, ErrScope) ||
			control.allocations != 0 || control.cleanups != 0 || authority.calls != 0 || native.allocationFinished {
			t.Fatal("cleanup replayed another invocation", err)
		}
	})
	t.Run("expired-no-replay", func(t *testing.T) {
		native, control, authority, body := allocationFixture(t)
		// seed a previously attempted invocation whose fixed deadline has passed.
		native.allocationInvocation = body.InvocationId
		body.ExpiresAt = new(time.Now().Add(-time.Second))
		err := native.CleanupServiceAllocation(t.Context(), body)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), body.InvocationId) ||
			control.allocations != 0 || control.cleanups != 0 || authority.calls != 0 ||
			native.allocatedServiceID != "" || native.allocationFinished {
			t.Fatal("expired recovery replayed its allocation or discarded unresolved ownership", err)
		}
	})
}

func TestCleanupServiceAllocationRejectsInvalidRecoveredScopeWithoutDeleting(t *testing.T) {
	for _, boundary := range []string{"id", "team", "saved", "namespace"} {
		t.Run(boundary, func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			lost := errors.New("allocation response lost")
			control.allocationErr = lost
			if _, err := native.AllocateService(t.Context(), body); !errors.Is(err, lost) {
				t.Fatal(err)
			}
			control.allocationErr = nil
			switch boundary {
			case "id":
				control.allocated.Id = "unobserved-fabricated-id"
			case "team":
				control.allocated.TeamId = "another-team"
			case "saved":
				control.allocated.Ephemeral = false
			case "namespace":
				endpoint := *control.allocated.Endpoint
				endpoint.Hostname = "temporary.someone-else.example.test"
				control.allocated.Endpoint = &endpoint
			}
			if err := native.CleanupServiceAllocation(t.Context(), body); !errors.Is(err, ErrScope) ||
				control.cleanups != 0 || control.reads != 0 || control.allocations != 2 || authority.calls != 2 ||
				native.allocatedServiceID != "" || native.selectedServiceID != "" || native.allocationFinished {
				t.Fatal("invalid recovery response became guessed cleanup or publication ownership", err)
			}
		})
	}
}

func TestCleanupServiceAllocationRequiresCapturedAllocationAuthority(t *testing.T) {
	for _, kind := range []string{"service", "deployment_credential"} {
		t.Run(kind, func(t *testing.T) {
			native, control, authority, body := allocationFixture(t)
			native.identity.kind = kind
			native.allocationInvocation = body.InvocationId
			if err := native.CleanupServiceAllocation(t.Context(), body); !errors.Is(err, ErrScope) ||
				control.allocations != 0 || control.cleanups != 0 || authority.calls != 0 {
				t.Fatal("non-namespace grant recovered a namespace invocation", err)
			}
		})
	}
	if err := (*Native)(nil).CleanupServiceAllocation(t.Context(), controlv1.AllocateServiceRequest{}); !errors.Is(err, ErrScope) {
		t.Fatal("nil cleanup owner was not rejected", err)
	}
}

func TestDeploymentAllocationCleanupRecoversWithoutPublicationSelection(t *testing.T) {
	for _, firstDelete := range []error{nil, clientcontrol.ErrNotFound, errors.Join(context.Canceled, errors.New("delete unavailable"))} {
		t.Run(fmt.Sprint(firstDelete), func(t *testing.T) {
			native, control, authority, body := deploymentAllocationFixture(t)
			body.ExpiresAt = new(time.Now().Add(time.Minute))
			body.Configuration.Http = &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(7)}}
			original, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			control.checkAllocation = func(ctx context.Context, _ string, request controlv1.AllocateServiceRequest) {
				t.Helper()
				document, err := json.Marshal(request)
				deadline, bounded := ctx.Deadline()
				if err != nil || !bytes.Equal(document, original) || !bounded || !deadline.Equal(native.deploymentAllocation.expiresAt) {
					t.Fatal("recovery changed its captured endpoint, declaration, or approval deadline", err)
				}
			}
			lost := io.ErrUnexpectedEOF
			control.allocationErr = lost
			_, operationErr := native.AllocateService(t.Context(), body)
			if !errors.Is(operationErr, lost) {
				t.Fatal(operationErr)
			}
			control.allocationErr, control.cleanupErr = nil, firstDelete
			control.readErr = errors.New("publication selection is unavailable")
			control.onRead = func() { t.Error("cleanup attempted publication selection") }
			// cleanup retains the allocation endpoint independently of service reads.
			native.Services = nil
			cleanupErr := native.CleanupServiceAllocation(t.Context(), body)
			if firstDelete != nil && !errors.Is(firstDelete, clientcontrol.ErrNotFound) {
				combined := errors.Join(operationErr, cleanupErr)
				if !errors.Is(combined, lost) || !errors.Is(combined, firstDelete) || native.allocationFinished ||
					native.allocatedServiceID != control.allocated.Id {
					t.Fatal("failed cleanup lost original ownership or an independent failure", combined)
				}
				native.Services = control
				fork, err := native.Fork()
				if err != nil || fork.deploymentAllocation != native.deploymentAllocation {
					t.Fatal("fork lost the captured deployment allocation authority", err)
				}
				native = fork
				control.cleanupErr = nil
				if err := native.CleanupServiceAllocation(t.Context(), body); err != nil {
					t.Fatal("retry could not delete the already observed allocation", err)
				}
			} else if cleanupErr != nil {
				t.Fatal(cleanupErr)
			}
			allocations, cleanups, exchanges := control.allocations, control.cleanups, authority.calls
			for range 3 {
				if err := native.CleanupServiceAllocation(t.Context(), body); err != nil {
					t.Fatal("confirmed cleanup was not terminal", err)
				}
			}
			wantCleanups := 1
			if firstDelete != nil && !errors.Is(firstDelete, clientcontrol.ErrNotFound) {
				wantCleanups++
			}
			if control.namespaceAllocations != 0 || allocations != 2 || control.deploymentAllocations != 2 ||
				cleanups != wantCleanups || control.reads != 0 || control.cleanupID != control.allocated.Id ||
				control.cleanupAccess != "access" || control.allocations != allocations || control.cleanups != cleanups ||
				authority.calls != exchanges || native.allocatedServiceID != "" || !native.allocationFinished || native.selectedServiceID != "" {
				t.Fatal("cleanup replayed a finished invocation, reselected publication, or used namespace authority",
					control.allocations, control.cleanups, control.reads, authority.calls)
			}
		})
	}
}

func TestDeploymentAllocationCleanupRetriesRecoveryFailuresOnOriginalOwner(t *testing.T) {
	for _, boundary := range []string{"signed-access", "allocation-replay", "invalid-response"} {
		t.Run(boundary, func(t *testing.T) {
			native, control, authority, body := deploymentAllocationFixture(t)
			control.allocationErr = io.ErrUnexpectedEOF
			if _, err := native.AllocateService(t.Context(), body); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal(err)
			}
			valid := control.allocated
			primary := error(ErrScope)
			switch boundary {
			case "signed-access":
				primary = errors.New("signed access unavailable")
				native.authority = &failedAllocationExchange{publicationAuthority: authority, err: primary}
			case "allocation-replay":
				primary = errors.New("recovery unavailable")
				control.allocationErr = primary
			case "invalid-response":
				control.allocationErr = nil
				control.allocated.TeamId = "another-team"
			}
			if err := native.CleanupServiceAllocation(t.Context(), body); !errors.Is(err, primary) || native.allocationFinished ||
				native.allocatedServiceID != "" || control.cleanups != 0 || control.reads != 0 {
				t.Fatal("failed recovery discarded uncertainty or guessed deletion authority", err)
			}
			native.authority, control.allocated, control.allocationErr = authority, valid, nil
			control.onRead = func() { t.Error("cleanup reselected publication") }
			if err := native.CleanupServiceAllocation(t.Context(), body); err != nil || !native.allocationFinished ||
				control.namespaceAllocations != 0 || control.cleanups != 1 || control.cleanupID != valid.Id {
				t.Fatal("original deployment invocation could not recover cleanup", err)
			}
		})
	}
}

func TestDeploymentAllocationDeadlineIsCapturedAndTerminalCleanupSurvivesExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, completed := range []bool{false, true} {
			native, control, authority, body := deploymentAllocationFixture(t)
			expires := native.deploymentAllocation.expiresAt
			if completed {
				if _, err := native.AllocateService(t.Context(), body); err != nil {
					t.Fatal(err)
				}
				if err := native.CleanupServiceAllocation(t.Context(), body); err != nil {
					t.Fatal(err)
				}
			} else {
				control.allocationErr = io.ErrUnexpectedEOF
				if _, err := native.AllocateService(t.Context(), body); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
			}
			allocations, cleanups, exchanges := control.allocations, control.cleanups, authority.calls
			time.Sleep(time.Until(expires))
			// a replacement caller deadline cannot extend the captured approval.
			body.ExpiresAt = new(time.Now().Add(time.Hour))
			ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
			err := native.CleanupServiceAllocation(ctx, body)
			cancel()
			if completed && err != nil || !completed && !errors.Is(err, context.DeadlineExceeded) ||
				control.allocations != allocations || control.cleanups != cleanups || authority.calls != exchanges {
				t.Fatal("expiry replayed authority or invalidated confirmed cleanup", err)
			}
		}
	})
}
