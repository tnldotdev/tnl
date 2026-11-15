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

// allocation preserves the actual namespace grant and selects only the service
// that control allocated. ForService repeats the authoritative ownership check.
// on failed selection, cleanup uses the original allocation credential. a
// nonzero service with an error means cleanup failed; the caller owns retrying
// DeleteAllocatedService on this native, without a publication-ready selection.
func (n *Native) AllocateService(ctx context.Context, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if n == nil || n.identity.kind != "namespace" || n.Allocations == nil || n.Services == nil {
		return controlv1.Service{}, ErrScope
	}
	if err := n.checkAllocationInvocation(body.InvocationId); err != nil {
		return controlv1.Service{}, err
	}
	token, err := n.Access(ctx)
	if err != nil {
		return controlv1.Service{}, err
	}
	n.allocationInvocation = body.InvocationId
	service, err := n.Allocations.AllocatePublisherService(ctx, token, body)
	if err != nil {
		return controlv1.Service{}, allocationRecoveryError(body.InvocationId, err)
	}
	if err := n.observeServiceAllocation(service); err != nil {
		return controlv1.Service{}, allocationRecoveryError(body.InvocationId, err)
	}
	_, selected, err := n.ForService(ctx, service.Id)
	if err == nil {
		err = n.validateAllocatedService(selected)
	}
	if err != nil {
		return n.cleanupFailedAllocation(ctx, token, service, err)
	}
	n.selectedServiceID = selected.Id
	return selected, nil
}

func (n *Native) DeleteAllocatedService(ctx context.Context, id string) error {
	if n == nil || n.Allocations == nil || n.allocatedServiceID == "" || n.allocatedServiceID != id ||
		n.identity.kind != "namespace" && n.identity.kind != "deployment_credential" {
		return ErrScope
	}
	token, err := n.Access(ctx)
	if err != nil {
		return err
	}
	return n.deleteServiceAllocation(ctx, token)
}

// CleanupServiceAllocation closes this worker's original namespace invocation,
// including when its allocation reply was lost. recovery establishes cleanup
// ownership only; it need not prepare a service for publication.
func (n *Native) CleanupServiceAllocation(ctx context.Context, body controlv1.AllocateServiceRequest) error {
	if n == nil || n.identity.kind != "namespace" || n.Allocations == nil {
		return ErrScope
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
	if n.allocatedServiceID == "" && body.ExpiresAt != nil && !body.ExpiresAt.After(time.Now()) {
		return allocationRecoveryError(body.InvocationId, context.DeadlineExceeded)
	}
	token, err := n.Access(ctx)
	if err != nil {
		return err
	}
	if n.allocatedServiceID == "" {
		service, err := n.Allocations.AllocatePublisherService(ctx, token, body)
		if err != nil {
			return allocationRecoveryError(body.InvocationId, err)
		}
		if err := n.observeServiceAllocation(service); err != nil {
			return allocationRecoveryError(body.InvocationId, err)
		}
	}
	return n.deleteServiceAllocation(ctx, token)
}

func (n *Native) deleteServiceAllocation(ctx context.Context, token string) error {
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
		service.Endpoint == nil || !service.Endpoint.Public || service.Endpoint.Port != 443 ||
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

func (n *Native) observeServiceAllocation(service controlv1.Service) error {
	if err := n.validateAllocatedService(service); err != nil {
		return err
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
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	id := n.allocatedServiceID
	err := n.deleteServiceAllocation(cleanup, access)
	if err != nil {
		return service, errors.Join(primary, fmt.Errorf("delete observed service allocation %s: %w", id, err))
	}
	return controlv1.Service{}, primary
}

// a registered temporary publication uses the same signed root credential as
// named selection, without fabricating an enrollment or an exact-service grant.
// an attempted but uncertain allocation returns its native owner without a
// service. nil ownership means no attempt or confirmed cleanup, not uncertainty.
func PrepareDeploymentAllocation(ctx context.Context, control DeploymentAllocationControl, authority AssertionExchanger, approval controlv1.DeploymentCredential, private ed25519.PrivateKey, deployment string, body controlv1.AllocateServiceRequest) (*Native, *controlv1.Service, error) {
	if control == nil || authority == nil || !validSigningKey(private) || deployment == "" ||
		!opaqueid.Valid(body.InvocationId, opaqueid.InvocationPrefix) ||
		!opaqueid.Valid(approval.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(approval.GrantId, opaqueid.PublisherGrantPrefix) ||
		!opaqueid.Valid(approval.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
		approval.TeamId == "" || approval.ProjectKey == "" || !approval.ExpiresAt.After(time.Now()) {
		return nil, nil, ErrScope
	}
	native, err := newNative(NativeControl{Services: control, Allocations: control}, authority, nativeScope{
		clientID: approval.ClientId, keyID: approval.KeyId, grantID: approval.GrantId,
		teamID: approval.TeamId, kind: "deployment_credential",
	}, private)
	if err != nil {
		return nil, nil, err
	}
	token, err := native.Access(ctx)
	if err != nil {
		return nil, nil, err
	}
	native.allocationInvocation = body.InvocationId
	service, err := control.AllocateDeploymentPublication(ctx, token, approval.TeamId, approval.ProjectKey, deployment, body)
	if err != nil {
		return native, nil, allocationRecoveryError(body.InvocationId, err)
	}
	if err := native.observeServiceAllocation(service); err != nil {
		return native, nil, allocationRecoveryError(body.InvocationId, err)
	}
	selected, saved, err := native.ForService(ctx, service.Id)
	if err == nil {
		err = native.validateAllocatedService(saved)
	}
	if err != nil {
		pending, combined := native.cleanupFailedAllocation(ctx, token, service, err)
		if pending.Id != "" {
			return native, &pending, combined
		}
		return nil, nil, combined
	}
	return selected, &saved, nil
}
