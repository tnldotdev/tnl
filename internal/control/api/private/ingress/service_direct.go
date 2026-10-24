package ingress

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// direct private operations preserve the cluster API's authentication and
// factual preparation boundaries for the trusted in-process ingress.
func (s *service) privateState() (serviceStore, error) {
	store, ok := s.store.(serviceStore)
	if !ok {
		return nil, serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "service state is unavailable")
	}
	return store, nil
}

func (s *service) privateStateError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, controlstate.ErrStreamCapacity) {
		return serviceapi.NewProblemError(http.StatusTooManyRequests, "capacity_exceeded", "stream capacity is unavailable")
	}
	if errors.Is(err, controlstate.ErrVisitorPolicy) {
		return serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "visitor policy is unavailable")
	}
	if errors.Is(err, controlstate.ErrServiceAccess) {
		return serviceapi.NewProblemError(http.StatusForbidden, "forbidden", "private visitor authorization is not current")
	}
	return s.storeError(ctx, err)
}

func (s *service) ClaimConnectorSession(ctx context.Context, id string, body ingressv1.ConnectorSessionClaim) (ingressv1.ConnectorSessionResult, error) {
	var result ingressv1.ConnectorSessionResult
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	nonce, nonceErr := hex.DecodeString(body.Nonce)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	subject, subjectErr := visitorsubject.Parse(body.Subject)
	if !ok || !sourceOK || nonceErr != nil || signatureErr != nil || subjectErr != nil {
		return result, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid visitor key proof")
	}
	store, err := s.privateState()
	if err != nil {
		return result, err
	}
	bound, err := store.AuthenticateVisitorConnector(ctx, identity, tunnelv1.VisitorConnectorClaim{ServiceID: body.ServiceId, SessionID: body.ConnectorSessionId, Credential: body.SessionCredential, Subject: subject, Nonce: nonce, Signature: signature}, source, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.ConnectorSessionResult{ConnectorSessionId: bound.ID, ServiceId: bound.ServiceID, Subject: visitorsubject.Wire(bound.Subject), ObservedSourceIp: bound.SourceIP.String(), ExpiresAt: bound.ExpiresAt}, nil
}

func (s *service) GetServiceSnapshot(ctx context.Context, id string, params ingressv1.GetServiceSnapshotParams) (ingressv1.ServiceSnapshot, error) {
	identity, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		return ingressv1.ServiceSnapshot{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid ingress lease")
	}
	store, err := s.privateState()
	if err != nil {
		return ingressv1.ServiceSnapshot{}, err
	}
	snapshot, err := store.ReadServiceSnapshot(ctx, identity, s.now())
	if err != nil {
		return ingressv1.ServiceSnapshot{}, s.privateStateError(ctx, err)
	}
	return privateSnapshot(snapshot), nil
}

func (s *service) GetServiceEvents(ctx context.Context, id string, params ingressv1.GetServiceEventsParams) (ingressv1.ServiceSnapshot, error) {
	identity, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		return ingressv1.ServiceSnapshot{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid ingress lease")
	}
	store, err := s.privateState()
	if err != nil {
		return ingressv1.ServiceSnapshot{}, err
	}
	snapshot, err := store.ReadServiceEvents(ctx, identity, params.After, s.now())
	if err != nil {
		return ingressv1.ServiceSnapshot{}, s.privateStateError(ctx, err)
	}
	return privateSnapshot(snapshot), nil
}
