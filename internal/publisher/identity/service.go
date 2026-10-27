package identity

import (
	"bytes"
	"context"
	"encoding/json"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceControl interface {
	GetPublisherService(context.Context, string) (controlv1.Service, error)
}

type serviceRunControl interface {
	PrepareServiceRun(context.Context, string, string, string, controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error)
	HeartbeatServiceRun(context.Context, string, string, credentials.ServiceRunToken) (controlv1.ServiceRunState, error)
	HeartbeatServiceRunHealth(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error)
	CloseServiceRun(context.Context, string, string, credentials.ServiceRunToken) error
}

// EnsureServiceOwner saves a pending enrollment before redemption, so
// response loss never issues a second grant or abandons the original key.
func EnsureServiceOwner(ctx context.Context, state *clientstate.Store, control OwnerControl, authority EnrollmentAuthority, service controlv1.Service) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || control == nil || authority == nil || !service.Enabled || !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) || service.TeamId == "" {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	if _, err := ServiceTrust(service); err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	scope := "project-publisher:service:" + service.Id
	lock, err := state.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	defer lock.Close()
	saved, found, err := state.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if found {
		var identity authorityv1.PublisherEnrollmentResult
		if json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId != saved.ID {
			return nil, identity, ErrScope
		}
		if identity.ClientId != "" {
			if identity.Kind != authorityv1.Service || identity.ServiceId == nil || *identity.ServiceId != service.Id || identity.TeamId != service.TeamId {
				return nil, identity, ErrScope
			}
			return LoadNative(ctx, state, control, authority, identity.ClientId)
		}
	}
	pending, found, err := state.PendingPublisherEnrollmentForSelection(ctx, "project", scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if !found {
		enrollment, err := control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Name: "tnl", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
		if err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
		if enrollment.Kind != "service" || enrollment.ServiceId == nil || *enrollment.ServiceId != service.Id || enrollment.TeamId != service.TeamId || !opaqueid.Valid(enrollment.Id, opaqueid.PublisherEnrollmentPrefix) || enrollment.EnrollmentKey == "" {
			return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
		}
		pending, err = savePendingEnrollment(ctx, state, "project", scope, enrollment.Id, enrollment.EnrollmentKey)
		if err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
	}
	adapter, identity, err := EnrollNative(ctx, state, control, authority, string(pending.EnrollmentSecret))
	if err != nil {
		return nil, identity, err
	}
	if identity.Kind != authorityv1.Service || identity.ServiceId == nil || *identity.ServiceId != service.Id || identity.TeamId != service.TeamId {
		return nil, identity, ErrScope
	}
	return adapter, identity, nil
}

func (n *Native) serviceControl(serviceID string) (serviceRunControl, error) {
	if n == nil || n.identity.kind != authorityv1.Service || n.identity.serviceID != serviceID {
		return nil, ErrScope
	}
	control, ok := n.NativeControl.(serviceRunControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}

func (n *Native) PrepareServiceRun(ctx context.Context, serviceID, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	control, err := n.serviceControl(serviceID)
	if err != nil || access == "" {
		return controlv1.ServiceRunPreparation{}, ErrScope
	}
	service, err := n.SavedService(ctx)
	if err != nil {
		return controlv1.ServiceRunPreparation{}, err
	}
	if !sameServiceDeclaration(declaration, ServiceDeclaration(service)) {
		return controlv1.ServiceRunPreparation{}, ErrScope
	}
	return control.PrepareServiceRun(ctx, serviceID, key, access, declaration)
}

func (n *Native) HeartbeatServiceRun(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken) (controlv1.ServiceRunState, error) {
	control, err := n.serviceControl(serviceID)
	if err != nil {
		return controlv1.ServiceRunState{}, err
	}
	r, err := control.HeartbeatServiceRun(ctx, serviceID, runID, token)
	if err == nil {
		err = n.renewRuntime(ctx)
	}
	return r, err
}

func (n *Native) HeartbeatServiceRunHealth(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	control, err := n.serviceControl(serviceID)
	if err != nil {
		return controlv1.ServiceRunState{}, err
	}
	r, err := control.HeartbeatServiceRunHealth(ctx, serviceID, runID, token, health)
	if err == nil {
		err = n.renewRuntime(ctx)
	}
	return r, err
}

func (n *Native) CloseServiceRun(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken) error {
	control, err := n.serviceControl(serviceID)
	if err != nil {
		return err
	}
	return control.CloseServiceRun(ctx, serviceID, runID, token)
}

// DeliverNativePeerPair keeps the optional delivery capability inside the
// selected service grant; control still authenticates the exact run token.
func (n *Native) DeliverNativePeerPair(ctx context.Context, serviceID, runID, pairID string, generation int64, token credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	if n == nil || n.identity.kind != authorityv1.Service || n.identity.serviceID != serviceID {
		return controlv1.NativePeerPairDelivery{}, ErrScope
	}
	control, ok := n.NativeControl.(interface {
		DeliverNativePeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error)
	})
	if !ok {
		return controlv1.NativePeerPairDelivery{}, ErrScope
	}
	return control.DeliverNativePeerPair(ctx, serviceID, runID, pairID, generation, token)
}

// ListNativePeerPairs confines reconciliation to the selected service grant.
// each candidate still needs its independently authorized delivery request.
func (n *Native) ListNativePeerPairs(ctx context.Context, serviceID, runID, after string, token credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error) {
	if n == nil || n.identity.kind != authorityv1.Service || n.identity.serviceID != serviceID {
		return controlv1.NativePeerPairCandidates{}, ErrScope
	}
	control, ok := n.NativeControl.(interface {
		ListNativePeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error)
	})
	if !ok {
		return controlv1.NativePeerPairCandidates{}, ErrScope
	}
	return control.ListNativePeerPairs(ctx, serviceID, runID, after, token)
}

func (n *Native) ConfirmNativePeerPairPrepared(ctx context.Context, serviceID, runID, pairID string, prepared controlv1.NativePeerPairPrepared, token credentials.ServiceRunToken) error {
	if n == nil || n.identity.kind != authorityv1.Service || n.identity.serviceID != serviceID {
		return ErrScope
	}
	control, ok := n.NativeControl.(interface {
		ConfirmNativePeerPairPrepared(context.Context, string, string, string, controlv1.NativePeerPairPrepared, credentials.ServiceRunToken) error
	})
	if !ok {
		return ErrScope
	}
	return control.ConfirmNativePeerPairPrepared(ctx, serviceID, runID, pairID, prepared, token)
}

// SavedService reads only the exact service selected by this signing
// identity. a public URL or namespace grant cannot discover services.
func (n *Native) SavedService(ctx context.Context) (controlv1.Service, error) {
	if n == nil || n.identity.kind != authorityv1.Service || n.identity.serviceID == "" {
		return controlv1.Service{}, ErrScope
	}
	access, err := n.Access(ctx)
	if err != nil {
		return controlv1.Service{}, err
	}
	return n.GetPublisherService(ctx, access)
}

func (n *Native) GetPublisherService(ctx context.Context, access string) (controlv1.Service, error) {
	if n == nil || n.identity.kind != authorityv1.Service || n.identity.serviceID == "" || access == "" {
		return controlv1.Service{}, ErrScope
	}
	control, ok := n.NativeControl.(serviceControl)
	if !ok {
		return controlv1.Service{}, ErrScope
	}
	service, err := control.GetPublisherService(ctx, access)
	if err != nil {
		return service, err
	}
	if service.Id != n.identity.serviceID || service.TeamId != n.identity.teamID || !service.Enabled {
		return controlv1.Service{}, ErrScope
	}
	if _, err := ServiceTrust(service); err != nil {
		return controlv1.Service{}, err
	}
	return service, nil
}

// ServiceTrust validates approved publisher-to-target metadata. connectors
// do not receive or interpret it; nil selects a plaintext target connection.
func ServiceTrust(service controlv1.Service) (*targettrust.Snapshot, error) {
	if !service.Protocol.Valid() || service.TrustRevision < 1 {
		return nil, failure.Wrap("read service metadata", failure.ServerResponseInvalid, ErrScope)
	}
	if service.TargetTls == nil {
		return nil, nil
	}
	trust := &targettrust.Snapshot{Hostname: service.TargetTls.Hostname, System: service.TargetTls.System, Digest: service.TargetTls.Digest}
	if service.TargetTls.Pem != nil {
		trust.PEM = []byte(*service.TargetTls.Pem)
	}
	if _, err := trust.Verifier(); err != nil {
		return nil, failure.Wrap("read service TLS", failure.ServerResponseInvalid, err)
	}
	return trust, nil
}

func ServiceDeclaration(service controlv1.Service) controlv1.ServiceRunDeclaration {
	return controlv1.ServiceRunDeclaration{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision}
}

func ServiceMetadata(service controlv1.Service) controlv1.ServiceMetadata {
	return controlv1.ServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool}
}

func ServiceTargetTLS(trust *targettrust.Snapshot) *controlv1.ServiceTargetTLS {
	if trust == nil {
		return nil
	}
	value := &controlv1.ServiceTargetTLS{Hostname: trust.Hostname, System: trust.System, Digest: trust.Digest}
	if len(trust.PEM) != 0 {
		encoded := string(trust.PEM)
		value.Pem = &encoded
	}
	return value
}

// MatchServiceDeclaration never substitutes a remote trust revision for
// a different local protocol, hostname, or CA snapshot.
func MatchServiceDeclaration(service controlv1.Service, protocol string, trust *targettrust.Snapshot) error {
	approved, err := ServiceTrust(service)
	if err != nil {
		return err
	}
	if string(service.Protocol) != protocol || (approved == nil) != (trust == nil) {
		return ErrScope
	}
	if approved != nil {
		if _, err := trust.Verifier(); err != nil {
			return err
		}
		if approved.Digest != trust.Digest || approved.Hostname != trust.Hostname || approved.System != trust.System || !bytes.Equal(approved.PEM, trust.PEM) {
			return ErrScope
		}
	}
	return nil
}

func sameServiceDeclaration(a, b controlv1.ServiceRunDeclaration) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && bytes.Equal(x, y)
}
