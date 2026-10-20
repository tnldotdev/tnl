package ingressapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/visitorsubject"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// direct private operations use the same database decisions as the cluster
// API. only the trusted in-process ingress receives this capability.
func (s *service) privateState() (privateServiceStore, error) {
	store, ok := s.store.(privateServiceStore)
	if !ok {
		return nil, serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "private service state is unavailable")
	}
	return store, nil
}

func (s *service) privateStateError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		return serviceapi.NewProblemError(http.StatusForbidden, "forbidden", "private visitor authorization is not current")
	}
	return s.storeError(ctx, err)
}

func privateVisitorRecheckResult(validity controlstate.PrivateVisitorValidity, now time.Time) ingressv1.PrivateServiceVisitorRecheckResult {
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
	return ingressv1.PrivateServiceVisitorRecheckResult{Allowed: validity.Allowed, RecheckAt: next, ValidUntil: validity.ValidUntil}
}

func (s *service) ClaimPrivateConnectorSession(ctx context.Context, id string, body ingressv1.PrivateConnectorSessionClaim) (ingressv1.PrivateConnectorSessionResult, error) {
	var result ingressv1.PrivateConnectorSessionResult
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
	bound, err := store.AuthenticateVisitorConnector(ctx, identity, tunnelv1.VisitorConnectorClaim{ServiceID: body.PrivateServiceId,
		SessionID: body.ConnectorSessionId, Credential: body.SessionCredential, Subject: subject, Nonce: nonce, Signature: signature}, source, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.PrivateConnectorSessionResult{ConnectorSessionId: bound.ID, PrivateServiceId: bound.PrivateServiceID, Subject: visitorsubject.Wire(bound.Subject), ObservedSourceIp: bound.SourceIP.String(), ExpiresAt: bound.ExpiresAt}, nil
}

func (s *service) AuthorizePrivateServiceStream(ctx context.Context, id string, body ingressv1.PrivateServiceStreamClaim) (ingressv1.PrivateServiceStreamResult, error) {
	var result ingressv1.PrivateServiceStreamResult
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK {
		return result, serviceapi.NewProblemError(400, "invalid_request", "invalid private stream identity")
	}
	store, err := s.privateState()
	if err != nil {
		return result, err
	}
	bound, err := store.AuthorizePrivateServiceStream(ctx, identity, body.PrivateServiceId, body.PrivateRunId, body.ConnectorSessionId, body.VisitorConnectionId, body.RunNumber, source, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.PrivateServiceStreamResult{PrivateServiceId: bound.PrivateServiceID, PrivateRunId: bound.PrivateRunID, RunNumber: bound.RunNumber,
		ConnectorSessionId: bound.ConnectorSessionID, Subject: visitorsubject.Wire(bound.Subject), GrantRevision: bound.GrantRevision,
		ObservedSourceIp: bound.SourceIP.String(), VisitorConnectionId: bound.VisitorConnectionID, ExpiresAt: bound.ExpiresAt, ValidUntil: bound.ValidUntil}, nil
}

func (s *service) ClosePrivateServiceStream(ctx context.Context, id, visitorID string, body ingressv1.ClosePrivateServiceStreamJSONRequestBody) error {
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return serviceapi.NewProblemError(400, "invalid_request", "invalid ingress lease")
	}
	store, err := s.privateState()
	if err != nil {
		return err
	}
	return s.privateStateError(ctx, store.ClosePrivateServiceStream(ctx, identity, body.ConnectorSessionId, visitorID, s.now()))
}

func (s *service) GetPrivateServiceSnapshot(ctx context.Context, id string, params ingressv1.GetPrivateServiceSnapshotParams) (ingressv1.PrivateServiceSnapshot, error) {
	identity, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		return ingressv1.PrivateServiceSnapshot{}, serviceapi.NewProblemError(400, "invalid_request", "invalid ingress lease")
	}
	store, err := s.privateState()
	if err != nil {
		return ingressv1.PrivateServiceSnapshot{}, err
	}
	snapshot, err := store.ReadPrivateServiceSnapshot(ctx, identity, s.now())
	if err != nil {
		return ingressv1.PrivateServiceSnapshot{}, s.privateStateError(ctx, err)
	}
	return privateSnapshot(snapshot), nil
}

func (s *service) GetPrivateServiceEvents(ctx context.Context, id string, params ingressv1.GetPrivateServiceEventsParams) (ingressv1.PrivateServiceSnapshot, error) {
	identity, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		return ingressv1.PrivateServiceSnapshot{}, serviceapi.NewProblemError(400, "invalid_request", "invalid ingress lease")
	}
	store, err := s.privateState()
	if err != nil {
		return ingressv1.PrivateServiceSnapshot{}, err
	}
	snapshot, err := store.ReadPrivateServiceEvents(ctx, identity, params.After, s.now())
	if err != nil {
		return ingressv1.PrivateServiceSnapshot{}, s.privateStateError(ctx, err)
	}
	return privateSnapshot(snapshot), nil
}

func (s *service) RecheckPrivateServiceVisitor(ctx context.Context, id string, body ingressv1.PrivateServiceVisitorRecheck) (ingressv1.PrivateServiceVisitorRecheckResult, error) {
	var result ingressv1.PrivateServiceVisitorRecheckResult
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
	decision, err := store.RecheckVisitorServiceStream(ctx, identity, body.PrivateServiceId, body.PrivateRunId, body.ConnectorSessionId, body.VisitorConnectionId, subject, body.RunNumber, source, now)
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		decision = controlstate.PrivateVisitorValidity{ValidUntil: now}
		err = nil
	}
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	observability.AuthorizationDecision(ctx, "private_visitor_recheck", decision.Allowed)
	return privateVisitorRecheckResult(decision, now), nil
}
