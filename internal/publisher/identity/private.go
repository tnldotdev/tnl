package native

import (
	"bytes"
	"context"
	"encoding/json"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	privatetrust "github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type privateServiceControl interface {
	GetPublisherPrivateService(context.Context, string) (controlv1.PrivateService, error)
}

type privateRunControl interface {
	PreparePrivateServiceRun(context.Context, string, string, string, ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error)
	HeartbeatPrivateServiceRun(context.Context, string, string, credentials.PublishRunToken) (controlv1.PrivateServiceRunState, error)
	HeartbeatPrivateServiceRunHealth(context.Context, string, string, credentials.PublishRunToken, controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error)
	ClosePrivateServiceRun(context.Context, string, string, credentials.PublishRunToken) error
}

// EnsurePrivateServiceOwner saves a pending enrollment before redemption, so
// response loss never issues a second grant or abandons the original key.
func EnsurePrivateServiceOwner(ctx context.Context, state *clientstate.Store, control OwnerControl, authority EnrollmentAuthority, service controlv1.PrivateService) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || control == nil || authority == nil || !service.Enabled || !opaqueid.Valid(service.Id, opaqueid.PrivateServicePrefix) || service.TeamId == "" {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	if _, err := PrivateServiceTrust(service); err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	scope := "project-publisher:private:" + service.Id
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
			if identity.Kind != authorityv1.PrivateService || identity.PrivateServiceId == nil || *identity.PrivateServiceId != service.Id || identity.TeamId != service.TeamId {
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
		enrollment, err := control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, PrivateServiceId: &service.Id, Name: "tnl", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
		if err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
		if enrollment.Kind != "private_service" || enrollment.PrivateServiceId == nil || *enrollment.PrivateServiceId != service.Id || enrollment.TeamId != service.TeamId || !opaqueid.Valid(enrollment.Id, opaqueid.PublisherEnrollmentPrefix) || enrollment.EnrollmentKey == "" {
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
	if identity.Kind != authorityv1.PrivateService || identity.PrivateServiceId == nil || *identity.PrivateServiceId != service.Id || identity.TeamId != service.TeamId {
		return nil, identity, ErrScope
	}
	return adapter, identity, nil
}

func (n *Native) privateControl(serviceID string) (privateRunControl, error) {
	if n == nil || n.identity.kind != authorityv1.PrivateService || n.identity.privateServiceID != serviceID {
		return nil, ErrScope
	}
	if control, ok := n.NativeControl.(managedControl); ok {
		return legacyManagedControl{control}, nil
	}
	control, ok := n.NativeControl.(privateRunControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}

func (n *Native) PreparePrivateServiceRun(ctx context.Context, serviceID, key, access string, declarations ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error) {
	control, err := n.privateControl(serviceID)
	if err != nil || len(declarations) != 1 || access == "" {
		return controlv1.PrivateServiceRunPreparation{}, ErrScope
	}
	service, err := n.SavedPrivateService(ctx)
	if err != nil {
		return controlv1.PrivateServiceRunPreparation{}, err
	}
	if !samePrivateDeclaration(declarations[0], PrivateServiceDeclaration(service)) {
		return controlv1.PrivateServiceRunPreparation{}, ErrScope
	}
	return control.PreparePrivateServiceRun(ctx, serviceID, key, access, declarations...)
}

func (n *Native) HeartbeatPrivateServiceRun(ctx context.Context, serviceID, runID string, token credentials.PublishRunToken) (controlv1.PrivateServiceRunState, error) {
	control, err := n.privateControl(serviceID)
	if err != nil {
		return controlv1.PrivateServiceRunState{}, err
	}
	r, err := control.HeartbeatPrivateServiceRun(ctx, serviceID, runID, token)
	if err == nil {
		err = n.renewRuntime(ctx)
	}
	return r, err
}

func (n *Native) HeartbeatPrivateServiceRunHealth(ctx context.Context, serviceID, runID string, token credentials.PublishRunToken, health controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	control, err := n.privateControl(serviceID)
	if err != nil {
		return controlv1.PrivateServiceRunState{}, err
	}
	r, err := control.HeartbeatPrivateServiceRunHealth(ctx, serviceID, runID, token, health)
	if err == nil {
		err = n.renewRuntime(ctx)
	}
	return r, err
}

func (n *Native) ClosePrivateServiceRun(ctx context.Context, serviceID, runID string, token credentials.PublishRunToken) error {
	control, err := n.privateControl(serviceID)
	if err != nil {
		return err
	}
	return control.ClosePrivateServiceRun(ctx, serviceID, runID, token)
}

// SavedPrivateService reads only the exact service selected by this signing
// identity. a public URL or namespace grant cannot discover private services.
func (n *Native) SavedPrivateService(ctx context.Context) (controlv1.PrivateService, error) {
	if n == nil || n.identity.kind != authorityv1.PrivateService || n.identity.privateServiceID == "" {
		return controlv1.PrivateService{}, ErrScope
	}
	access, err := n.Access(ctx)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	return n.GetPublisherPrivateService(ctx, access)
}

func (n *Native) GetPublisherPrivateService(ctx context.Context, access string) (controlv1.PrivateService, error) {
	if n == nil || n.identity.kind != authorityv1.PrivateService || n.identity.privateServiceID == "" || access == "" {
		return controlv1.PrivateService{}, ErrScope
	}
	control, ok := n.NativeControl.(privateServiceControl)
	if !ok {
		return controlv1.PrivateService{}, ErrScope
	}
	service, err := control.GetPublisherPrivateService(ctx, access)
	if err != nil {
		return service, err
	}
	if service.Id != n.identity.privateServiceID || service.TeamId != n.identity.teamID || !service.Enabled {
		return controlv1.PrivateService{}, ErrScope
	}
	if _, err := PrivateServiceTrust(service); err != nil {
		return controlv1.PrivateService{}, err
	}
	return service, nil
}

// PrivateServiceTrust validates approved publisher-to-target metadata. connectors
// do not receive or interpret it; nil selects a plaintext target connection.
func PrivateServiceTrust(service controlv1.PrivateService) (*privatetrust.Snapshot, error) {
	if !service.Protocol.Valid() || service.TrustRevision < 1 {
		return nil, failure.Wrap("read private service metadata", failure.ServerResponseInvalid, ErrScope)
	}
	if service.TargetTls == nil {
		return nil, nil
	}
	trust := &privatetrust.Snapshot{Hostname: service.TargetTls.Hostname, System: service.TargetTls.System, Digest: service.TargetTls.Digest}
	if service.TargetTls.Pem != nil {
		trust.PEM = []byte(*service.TargetTls.Pem)
	}
	if _, err := trust.Verifier(); err != nil {
		return nil, failure.Wrap("read private service TLS", failure.ServerResponseInvalid, err)
	}
	return trust, nil
}

func PrivateServiceDeclaration(service controlv1.PrivateService) controlv1.PrivateServiceRunDeclaration {
	return controlv1.PrivateServiceRunDeclaration{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision}
}

func PrivateServiceMetadata(service controlv1.PrivateService) controlv1.PrivateServiceMetadata {
	return controlv1.PrivateServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool}
}

func PrivateServiceTLS(trust *privatetrust.Snapshot) *controlv1.PrivateServiceTLS {
	if trust == nil {
		return nil
	}
	value := &controlv1.PrivateServiceTLS{Hostname: trust.Hostname, System: trust.System, Digest: trust.Digest}
	if len(trust.PEM) != 0 {
		encoded := string(trust.PEM)
		value.Pem = &encoded
	}
	return value
}

// MatchPrivateServiceDeclaration never substitutes a remote trust revision for
// a different local protocol, hostname, or CA snapshot.
func MatchPrivateServiceDeclaration(service controlv1.PrivateService, protocol string, trust *privatetrust.Snapshot) error {
	approved, err := PrivateServiceTrust(service)
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

func samePrivateDeclaration(a, b controlv1.PrivateServiceRunDeclaration) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && bytes.Equal(x, y)
}
