package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ServiceAllocationControl interface {
	AllocatePublisherService(context.Context, string, controlv1.AllocateServiceRequest) (controlv1.Service, error)
	DeletePublisherService(context.Context, string, string) error
}

type DeploymentAllocationControl interface {
	ServiceControl
	ServiceAllocationControl
	AllocateDeploymentPublication(context.Context, string, string, string, string, controlv1.AllocateServiceRequest) (controlv1.Service, error)
}

// deployment allocation keeps the exact endpoint and fixed approval deadline.
// these immutable facts survive worker forks without changing the root grant.
type deploymentAllocation struct {
	control             DeploymentAllocationControl
	project, deployment string
	expiresAt           time.Time
}

// NewDeploymentAllocator prepares allocation authority without making an attempt.
// named publication alone has no allocation capability. callers use AllocateService
// and CleanupServiceAllocation with the original invocation and declaration.
func NewDeploymentAllocator(control DeploymentAllocationControl, authority AssertionExchanger, approval controlv1.DeploymentCredential, private ed25519.PrivateKey, deployment string) (*Native, error) {
	if control == nil || authority == nil || !validSigningKey(private) || deployment == "" ||
		!opaqueid.Valid(approval.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(approval.GrantId, opaqueid.PublisherGrantPrefix) ||
		!opaqueid.Valid(approval.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
		approval.TeamId == "" || approval.ProjectKey == "" || !approval.ExpiresAt.After(time.Now()) {
		return nil, ErrScope
	}
	native, err := newNative(NativeControl{Services: control, Allocations: control}, authority, nativeScope{
		clientID: approval.ClientId, keyID: approval.KeyId, grantID: approval.GrantId,
		teamID: approval.TeamId, kind: "deployment_credential",
	}, private)
	if err != nil {
		return nil, err
	}
	native.deploymentAllocation = &deploymentAllocation{control: control, project: approval.ProjectKey, deployment: deployment, expiresAt: approval.ExpiresAt}
	return native, nil
}

// AllocationScope requires the actual allocation capability, not just a signed
// service selection. deployment recovery never falls back to a namespace endpoint.
func (n *Native) AllocationScope() error {
	if n == nil || n.Allocations == nil {
		return ErrScope
	}
	switch n.identity.kind {
	case "namespace":
		return nil
	case "deployment_credential":
		if n.deploymentAllocation != nil {
			return nil
		}
	}
	return ErrScope
}

// allocation preserves the actual grant and selects only the service
// that control allocated. ForService repeats the authoritative ownership check.
// on failed selection, cleanup uses the original allocation credential. a
// nonzero service with an error means cleanup failed; the caller owns retrying
// DeleteAllocatedService on this native, without a publication-ready selection.
func (n *Native) AllocateService(ctx context.Context, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if err := n.AllocationScope(); err != nil {
		return controlv1.Service{}, err
	}
	if n.Services == nil {
		return controlv1.Service{}, ErrScope
	}
	if err := n.checkAllocationInvocation(body.InvocationId); err != nil {
		return controlv1.Service{}, err
	}
	ctx, cancel := n.allocationContext(ctx)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return controlv1.Service{}, err
	}
	token, err := n.Access(ctx)
	if err != nil {
		return controlv1.Service{}, err
	}
	n.allocationInvocation = body.InvocationId
	service, err := n.requestServiceAllocation(ctx, token, body)
	if err != nil {
		return controlv1.Service{}, allocationRecoveryError(body.InvocationId, err)
	}
	public := body.Configuration.Public == nil || *body.Configuration.Public
	if err := n.observeServiceAllocation(service, public); err != nil {
		return controlv1.Service{}, allocationRecoveryError(body.InvocationId, err)
	}
	_, selected, err := n.ForService(ctx, service.Id)
	if err == nil {
		err = n.validateAllocatedService(selected)
	}
	if err == nil && selected.Endpoint.Public != public {
		err = ErrScope
	}
	if err != nil {
		return n.cleanupFailedAllocation(ctx, token, service, err)
	}
	n.selectedServiceID = selected.Id
	return selected, nil
}

func (n *Native) DeleteAllocatedService(ctx context.Context, id string) error {
	if err := n.AllocationScope(); err != nil {
		return err
	}
	if n.allocatedServiceID == "" || n.allocatedServiceID != id {
		return ErrScope
	}
	ctx, cancel := n.allocationContext(ctx)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	token, err := n.Access(ctx)
	if err != nil {
		return err
	}
	return n.deleteServiceAllocation(ctx, token)
}

// CleanupServiceAllocation closes this worker's original allocation invocation,
// including when its allocation reply was lost. recovery establishes cleanup
// ownership only; it need not prepare a service for publication.
func (n *Native) CleanupServiceAllocation(ctx context.Context, body controlv1.AllocateServiceRequest) error {
	if err := n.AllocationScope(); err != nil {
		return err
	}
	if n.allocationInvocation == "" {
		return nil
	}
	if body.InvocationId != n.allocationInvocation {
		return ErrScope
	}
	if n.allocationFinished {
		return nil
	}
	ctx, cancel := n.allocationContext(ctx)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if n.allocatedServiceID == "" && body.ExpiresAt != nil && !body.ExpiresAt.After(time.Now()) {
		return allocationRecoveryError(body.InvocationId, context.DeadlineExceeded)
	}
	token, err := n.Access(ctx)
	if err != nil {
		return err
	}
	if n.allocatedServiceID == "" {
		service, err := n.requestServiceAllocation(ctx, token, body)
		if err != nil {
			return allocationRecoveryError(body.InvocationId, err)
		}
		if err := n.observeServiceAllocation(service, body.Configuration.Public == nil || *body.Configuration.Public); err != nil {
			return allocationRecoveryError(body.InvocationId, err)
		}
	}
	return n.deleteServiceAllocation(ctx, token)
}

func (n *Native) requestServiceAllocation(ctx context.Context, token string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if selection := n.deploymentAllocation; selection != nil {
		return selection.control.AllocateDeploymentPublication(ctx, token, n.identity.teamID, selection.project, selection.deployment, body)
	}
	return n.Allocations.AllocatePublisherService(ctx, token, body)
}

func (n *Native) allocationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if selection := n.deploymentAllocation; selection != nil {
		return context.WithDeadline(ctx, selection.expiresAt)
	}
	return ctx, func() {}
}

func (n *Native) deleteServiceAllocation(ctx context.Context, token string) error {
	ctx, cancel := n.allocationContext(ctx)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := n.Allocations.DeletePublisherService(ctx, token, n.allocatedServiceID); err != nil && !failure.Only(err, clientcontrol.ErrNotFound) {
		return err
	}
	n.allocatedServiceID = ""
	n.allocationFinished = true
	return nil
}

func (n *Native) checkAllocationInvocation(invocation string) error {
	if n.allocationFinished || !opaqueid.Valid(invocation, opaqueid.InvocationPrefix) ||
		n.allocationInvocation != "" && n.allocationInvocation != invocation ||
		n.selectedServiceID != "" && (n.allocatedServiceID == "" || n.selectedServiceID != n.allocatedServiceID) {
		return ErrScope
	}
	return nil
}

// cleanup ownership needs an allocation response within the actual credential's
// scope, not a service ID returned by a failed read or an arbitrary selection.
// trust metadata is validated separately by ForService before publication.
func (n *Native) validateAllocatedService(service controlv1.Service) error {
	if !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) || service.TeamId != n.identity.teamID ||
		!service.Ephemeral || !service.Enabled || service.Protocol != controlv1.ServiceProtocolHTTP ||
		service.DomainId == nil || !opaqueid.Valid(*service.DomainId, opaqueid.DomainPrefix) ||
		service.Endpoint == nil || service.Endpoint.Port != 443 ||
		n.allocatedServiceID != "" && n.allocatedServiceID != service.Id ||
		n.selectedServiceID != "" && n.selectedServiceID != service.Id {
		return ErrScope
	}
	hostname, err := naming.CanonicalizeHostname(service.Endpoint.Hostname)
	if err != nil || hostname != service.Endpoint.Hostname {
		return ErrScope
	}
	switch n.identity.kind {
	case "namespace":
		depth, within := naming.ChildDepth(hostname, n.identity.namespace)
		if *service.DomainId != n.identity.domainID || !within || depth != 1 {
			return ErrScope
		}
	case "deployment_credential":
		// the allocation endpoint checks the immutable deployment and exact
		// root grant. its signed credential has no namespace enrollment.
	default:
		return ErrScope
	}
	return nil
}

func (n *Native) observeServiceAllocation(service controlv1.Service, public bool) error {
	if err := n.validateAllocatedService(service); err != nil {
		return err
	}
	if service.Endpoint.Public != public {
		return ErrScope
	}
	n.allocatedServiceID = service.Id
	return nil
}

func allocationRecoveryError(invocation string, err error) error {
	return fmt.Errorf("allocation may have committed; retry invocation %s to recover it before cleanup: %w", invocation, err)
}

func (n *Native) cleanupFailedAllocation(ctx context.Context, access string, service controlv1.Service, primary error) (controlv1.Service, error) {
	// selection may fail because its context or a second token exchange failed.
	// the already observed allocation remains owned until cleanup is confirmed.
	n.selectedServiceID = ""
	until := time.Now().Add(10 * time.Second)
	if n.shutdownDeadline != nil {
		if parent := n.shutdownDeadline(); !parent.IsZero() && parent.Before(until) {
			until = parent
		}
	}
	cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
	defer cancel()
	id := n.allocatedServiceID
	err := n.deleteServiceAllocation(cleanup, access)
	if err != nil {
		return service, errors.Join(primary, fmt.Errorf("delete observed service allocation %s: %w", id, err))
	}
	return controlv1.Service{}, primary
}
