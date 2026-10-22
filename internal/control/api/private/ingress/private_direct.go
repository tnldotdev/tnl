package ingress

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// direct private operations use the same database decisions as the cluster
// API. only the trusted in-process ingress receives this capability.
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
	if errors.Is(err, controlstate.ErrServiceAccess) {
		return serviceapi.NewProblemError(http.StatusForbidden, "forbidden", "private visitor authorization is not current")
	}
	return s.storeError(ctx, err)
}

func privateVisitorRecheckResult(validity controlstate.ServiceVisitorValidity, now time.Time) ingressv1.ServiceVisitorRecheckResult {
	next := now
	if validity.Allowed {
		next = now.Add(30 * time.Second)
		if before := validity.ValidUntil.Add(-5 * time.Second); before.Before(next) {
			next = before
		}
		if !next.After(now) {
			next = now.Add(time.Millisecond)
			if validity.ValidUntil.Before(next) {
				next = validity.ValidUntil
			}
		}
	}
	return ingressv1.ServiceVisitorRecheckResult{Allowed: validity.Allowed, RecheckAt: next, ValidUntil: validity.ValidUntil}
}

func (s *service) ClaimConnectorSession(ctx context.Context, id string, body ingressv1.ConnectorSessionClaim) (ingressv1.ConnectorSessionResult, error) {
	var result ingressv1.ConnectorSessionResult
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	nonce, nerr := hex.DecodeString(body.Nonce)
	signature, serr := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	subject, subjectErr := visitorsubject.Parse(body.Subject)
	if !ok || !sourceOK || nerr != nil || serr != nil || subjectErr != nil {
		return result, serviceapi.NewProblemError(400, "invalid_request", "invalid visitor key proof")
	}
	store, err := s.privateState()
	if err != nil {
		return result, err
	}
	bound, err := store.AuthenticateVisitorConnector(ctx, identity, tunnelv1.VisitorConnectorClaim{ServiceID: body.ServiceId,
		SessionID: body.ConnectorSessionId, Credential: body.SessionCredential, Subject: subject, Nonce: nonce, Signature: signature}, source, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.ConnectorSessionResult{ConnectorSessionId: bound.ID, ServiceId: bound.ServiceID, Subject: visitorsubject.Wire(bound.Subject), ObservedSourceIp: bound.SourceIP.String(), ExpiresAt: bound.ExpiresAt}, nil
}

func (s *service) AuthorizeServiceStream(ctx context.Context, id string, body ingressv1.ServiceStreamClaim) (ingressv1.ServiceStreamResult, error) {
	var result ingressv1.ServiceStreamResult
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK {
		return result, serviceapi.NewProblemError(400, "invalid_request", "invalid private stream identity")
	}
	store, err := s.privateState()
	if err != nil {
		return result, err
	}
	bound, err := store.AuthorizeServiceStream(ctx, identity, body.ServiceId, body.ServiceRunId, body.ConnectorSessionId, body.VisitorConnectionId, body.RunNumber, source, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.ServiceStreamResult{ServiceId: bound.ServiceID, ServiceRunId: bound.ServiceRunID, RunNumber: bound.RunNumber,
		ConnectorSessionId: bound.ConnectorSessionID, Subject: visitorsubject.Wire(bound.Subject), GrantRevision: bound.GrantRevision,
		ObservedSourceIp: bound.SourceIP.String(), VisitorConnectionId: bound.VisitorConnectionID, ExpiresAt: bound.ExpiresAt, ValidUntil: bound.ValidUntil}, nil
}

func (s *service) CloseServiceStream(ctx context.Context, id, visitorID string, body ingressv1.CloseServiceStreamJSONRequestBody) error {
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return serviceapi.NewProblemError(400, "invalid_request", "invalid ingress lease")
	}
	store, err := s.privateState()
	if err != nil {
		return err
	}
	return s.privateStateError(ctx, store.CloseServiceStream(ctx, identity, body.ConnectorSessionId, visitorID, s.now()))
}

func (s *service) GetServiceSnapshot(ctx context.Context, id string, params ingressv1.GetServiceSnapshotParams) (ingressv1.ServiceSnapshot, error) {
	identity, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		return ingressv1.ServiceSnapshot{}, serviceapi.NewProblemError(400, "invalid_request", "invalid ingress lease")
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
		return ingressv1.ServiceSnapshot{}, serviceapi.NewProblemError(400, "invalid_request", "invalid ingress lease")
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

func (s *service) RecheckServiceVisitor(ctx context.Context, id string, body ingressv1.ServiceVisitorRecheck) (ingressv1.ServiceVisitorRecheckResult, error) {
	var result ingressv1.ServiceVisitorRecheckResult
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	subject, subjectErr := visitorsubject.Parse(body.Subject)
	if !ok || !sourceOK || subjectErr != nil {
		return result, serviceapi.NewProblemError(400, "invalid_request", "invalid private visitor identity")
	}
	store, err := s.privateState()
	if err != nil {
		return result, err
	}
	now := s.now()
	decision, err := store.RecheckVisitorServiceStream(ctx, identity, body.ServiceId, body.ServiceRunId, body.ConnectorSessionId, body.VisitorConnectionId, subject, body.RunNumber, source, now)
	if errors.Is(err, controlstate.ErrServiceAccess) {
		decision = controlstate.ServiceVisitorValidity{ValidUntil: now}
		err = nil
	}
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	observability.AuthorizationDecision(ctx, "connector_visitor_recheck", decision.Allowed)
	return privateVisitorRecheckResult(decision, now), nil
}
