package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorPairRequest(signer Signer, run Run, owner string, previous *controlv1.ConnectorPeerPair) (controlv1.ConnectorPeerPairRequest, error) {
	var body controlv1.ConnectorPeerPairRequest
	if run.PairReady == nil {
		return body, failure.Wrap("prepare connector relay carriers", failure.ConnectionUnavailable, ErrServiceConnection)
	}
	if len(run.PairReady.Relays) != 2 || !opaqueid.Valid(run.PairReady.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || signer.Subject.Validate() != nil {
		return body, ErrServiceConnection
	}
	body = controlv1.ConnectorPeerPairRequest{Action: "create", IdempotencyKey: owner, ServiceRunId: run.ServiceRunID, RunNumber: int64(run.RunNumber), PublisherIdentityId: run.PairReady.PublisherIdentityId,
		Subject: visitorsubject.Wire(signer.Subject), ExpectedRelays: run.PairReady.Relays, RequestedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if previous != nil {
		body.Action, body.PreviousPairId, body.PreviousGeneration = "renew", &previous.PairId, &previous.DeliveryGeneration
	}
	message, err := controlv1.ConnectorPeerPairProofMessage(run.ServiceID, body)
	if err != nil {
		return body, err
	}
	signature := signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, signature) {
		return body, ErrServiceConnection
	}
	body.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return body, nil
}

func requestConnectorPair[T any](ctx context.Context, call func() (T, error)) (result T, err error) {
	// an uncertain reply repeats this exact signed request, not a new owner or
	// timestamp. the caller's bounded preparation/renewal context is the ceiling.
	for {
		if cause := context.Cause(ctx); cause != nil {
			return result, errors.Join(err, cause)
		}
		result, err = call()
		if err == nil || !connectorTemporary(err) {
			return result, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			var zero T
			return zero, errors.Join(err, context.Cause(ctx))
		case <-timer.C:
		}
	}
}

func prepareConnectorPair(ctx context.Context, control Control, signer Signer, run Run, owner string) (controlv1.ConnectorPeerPair, [32]byte, time.Time, controlv1.ConnectorPeerPairRequest, error) {
	body, err := connectorPairRequest(signer, run, owner, nil)
	if err != nil {
		return controlv1.ConnectorPeerPair{}, [32]byte{}, time.Time{}, body, err
	}
	started := time.Now()
	pair, err := requestConnectorPair(ctx, func() (controlv1.ConnectorPeerPair, error) {
		return control.PrepareConnectorPeerPair(ctx, run.ServiceID, body)
	})
	if err != nil {
		return controlv1.ConnectorPeerPair{}, [32]byte{}, time.Time{}, body, err
	}
	key, until, err := validateConnectorPair(ctx, signer, run, body, pair, started, nil)
	if err != nil {
		if _, materialErr := validateConnectorPairMaterial(signer, run, pair); materialErr == nil {
			return pair, key, started.Add(pair.ExpiresAt.Sub(pair.ObservedAt)), body, err
		}
		return controlv1.ConnectorPeerPair{}, [32]byte{}, time.Time{}, body, err
	}
	return pair, key, until, body, nil
}

func renewConnectorPair(ctx context.Context, control Control, signer Signer, run Run, owner string, previous controlv1.ConnectorPeerPair) (controlv1.ConnectorPeerPairRenewal, time.Time, error) {
	body, err := connectorPairRequest(signer, run, owner, &previous)
	if err != nil {
		return controlv1.ConnectorPeerPairRenewal{}, time.Time{}, err
	}
	started := time.Now()
	renewal, err := requestConnectorPair(ctx, func() (controlv1.ConnectorPeerPairRenewal, error) {
		return control.RenewConnectorPeerPair(ctx, run.ServiceID, body)
	})
	if err != nil {
		return controlv1.ConnectorPeerPairRenewal{}, time.Time{}, err
	}
	_, until, err := validateConnectorPair(ctx, signer, run, body, renewal.Pair, started, &previous)
	if err != nil {
		return controlv1.ConnectorPeerPairRenewal{}, time.Time{}, err
	}
	permission := renewal.VisitorPermission
	permission.ExpiresAt = started.Add(permission.ExpiresAt.Sub(renewal.Pair.ObservedAt))
	if permission.ServiceTrustRevision == nil || *permission.ServiceTrustRevision < 1 || *permission.ServiceTrustRevision != renewal.TrustRevision ||
		!renewal.RunValidUntil.After(renewal.Pair.ObservedAt) || !validConnectorPermission(run, permission) ||
		!renewal.VisitorPermission.ExpiresAt.After(renewal.Pair.ObservedAt) || renewal.VisitorPermission.ExpiresAt.After(renewal.Pair.ExpiresAt) ||
		renewal.Pair.PublisherPreparedUntil != nil && renewal.Pair.PublisherPreparedUntil.After(renewal.Pair.ExpiresAt) {
		return controlv1.ConnectorPeerPairRenewal{}, time.Time{}, ErrServiceConnection
	}
	return renewal, until, nil
}

func validateConnectorPair(ctx context.Context, signer Signer, run Run, body controlv1.ConnectorPeerPairRequest, pair controlv1.ConnectorPeerPair, started time.Time, previous *controlv1.ConnectorPeerPair) ([32]byte, time.Time, error) {
	// a spent RPC budget is not an authority denial. the owner keeps its
	// existing fence while a later call retries; this reply installs nothing.
	if err := context.Cause(ctx); err != nil {
		return [32]byte{}, time.Time{}, err
	}
	key, keyErr := connectorPairSecret(pair.Key)
	frameKey, frameKeyErr := connectorPairSecret(pair.SessionKey)
	_, idErr := tunnelv1.ParsePeerDeliveryIdentifier(pair.DeliveryId)
	duration := pair.ExpiresAt.Sub(pair.ObservedAt)
	until := started.Add(duration)
	if keyErr != nil || frameKeyErr != nil || idErr != nil || !opaqueid.Valid(pair.PairId, "cpp_") || pair.DeliveryGeneration < 1 || pair.ServiceId != run.ServiceID || pair.ServiceRunId != run.ServiceRunID || pair.RunNumber != int64(run.RunNumber) || pair.TrustRevision != run.TrustRevision || pair.PublisherIdentityId != run.PairReady.PublisherIdentityId || !visitorsubject.Equal(pair.Subject, signer.Subject) ||
		pair.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !until.After(time.Now()) || len(pair.Relays) != 2 {
		return key, time.Time{}, ErrServiceConnection
	}
	for slot, relay := range pair.Relays {
		if relay != body.ExpectedRelays[slot] {
			return key, time.Time{}, ErrServiceConnection
		}
	}
	if key == [32]byte{} || key == frameKey || previous == nil && (pair.BindingState != controlv1.ConnectorPeerPairBindingActive || pair.OperationId != "" || pair.BindingChallenge != "") ||
		previous != nil && (pair.PairId != previous.PairId || pair.DeliveryId != previous.DeliveryId || pair.DeliveryGeneration != previous.DeliveryGeneration || pair.Key != previous.Key || pair.SessionKey != previous.SessionKey || pair.TrustRevision != previous.TrustRevision || pair.OperationId != previous.OperationId || pair.BindingChallenge != previous.BindingChallenge) {
		return [32]byte{}, time.Time{}, ErrServiceConnection
	}
	return key, until, nil
}

// immutable ownership material may be retained for negative cleanup even when
// the positive setup deadline has elapsed. this never installs serving state.
func validateConnectorPairMaterial(signer Signer, run Run, pair controlv1.ConnectorPeerPair) ([32]byte, error) {
	key, err := connectorPairSecret(pair.SessionKey)
	deliveryKey, deliveryErr := connectorPairSecret(pair.Key)
	_, deliveryIDErr := tunnelv1.ParsePeerDeliveryIdentifier(pair.DeliveryId)
	if err != nil || deliveryErr != nil || deliveryIDErr != nil || key == deliveryKey ||
		!opaqueid.Valid(pair.PairId, "cpp_") || pair.ServiceId != run.ServiceID || pair.ServiceRunId != run.ServiceRunID ||
		pair.RunNumber != int64(run.RunNumber) || run.PairReady == nil || pair.PublisherIdentityId != run.PairReady.PublisherIdentityId ||
		!visitorsubject.Equal(pair.Subject, signer.Subject) {
		return [32]byte{}, ErrServiceConnection
	}
	return key, nil
}

// awaitConnectorPublisher repeats the original signed create only to observe the
// installation barrier. it cannot renew authority or reset startup's deadline.
func awaitConnectorPublisher(ctx context.Context, control Control, service string, request controlv1.ConnectorPeerPairRequest, expected controlv1.ConnectorPeerPair) (time.Time, time.Time, error) {
	for {
		if err := context.Cause(ctx); err != nil {
			return time.Time{}, time.Time{}, err
		}
		started := time.Now()
		pair, err := control.PrepareConnectorPeerPair(ctx, service, request)
		if err == nil {
			if pair.PairId != expected.PairId || pair.DeliveryId != expected.DeliveryId || pair.DeliveryGeneration != expected.DeliveryGeneration || pair.Key != expected.Key || pair.SessionKey != expected.SessionKey || pair.TrustRevision != expected.TrustRevision || pair.OperationId != expected.OperationId || pair.BindingChallenge != expected.BindingChallenge || pair.BindingState != expected.BindingState ||
				pair.ServiceId != expected.ServiceId || pair.ServiceRunId != expected.ServiceRunId || pair.RunNumber != expected.RunNumber || pair.PublisherIdentityId != expected.PublisherIdentityId ||
				!visitorsubject.Same(pair.Subject, expected.Subject) || len(pair.Relays) != 2 || pair.Relays[0] != expected.Relays[0] || pair.Relays[1] != expected.Relays[1] ||
				pair.ObservedAt.IsZero() || !pair.ExpiresAt.After(pair.ObservedAt) || pair.ExpiresAt.Sub(pair.ObservedAt) > 5*time.Minute {
				return time.Time{}, time.Time{}, ErrServiceConnection
			}
			if pair.PublisherPreparedUntil != nil {
				if pair.PublisherPreparedUntil.After(pair.ExpiresAt) {
					return time.Time{}, time.Time{}, ErrServiceConnection
				}
				if remaining := pair.PublisherPreparedUntil.Sub(pair.ObservedAt); remaining > 0 && started.Add(remaining).After(time.Now()) {
					return started.Add(remaining), *pair.PublisherPreparedUntil, context.Cause(ctx)
				}
			}
		} else if !connectorTemporary(err) {
			return time.Time{}, time.Time{}, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return time.Time{}, time.Time{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

type connectorRelayLeg struct {
	selectedHandoff tunnelv1.ConnectorHandoffID
	handoffRevision tunnelv1.ConnectorHandoffRevision
	session         *tunnel.Session
	packets         *peer.SharedSession
	carrier         peer.Carrier
	proof           tunnelv1.ConnectorPairLegProof
	receipt         tunnelv1.ConnectorPairLegAccepted
	transport       tunnel.Transport
	until           time.Time
	relay           controlv1.ConnectorPeerPairRelay
	closeOnce       sync.Once
	closeErr        error
}

func (l *connectorRelayLeg) Close() error {
	l.closeOnce.Do(func() {
		// stop transport i/o before joining borrowed packet registrations.
		if l.session != nil {
			l.closeErr = errors.Join(l.closeErr, l.session.Close())
		}
		if l.carrier != nil {
			l.closeErr = errors.Join(l.closeErr, l.carrier.Close())
		}
		if l.packets != nil {
			l.closeErr = errors.Join(l.closeErr, l.packets.Close())
		}
	})
	return l.closeErr
}

func connectorCleanupFailure(err error) error {
	if err == nil {
		return nil
	}
	return &CleanupError{Err: err}
}

type connectorAttemptStage uint8

const (
	connectorAttemptProof connectorAttemptStage = iota
	connectorAttemptConnect
	connectorAttemptCapability
	connectorAttemptHello
	connectorAttemptActivation
)

type connectorCandidateFailure struct {
	stage    connectorAttemptStage
	cause    error
	cleanup  error
	canceled bool
}

// the leg owner records at most two dial candidates or one activation. alternative
// transports are not independent relay slots or arbitrary joined error children.
type connectorLegAttemptError struct {
	candidates [2]connectorCandidateFailure
	count      int
	context    error
	cleanup    error
}

func (e *connectorLegAttemptError) Unwrap() []error {
	causes := []error{ErrServiceConnection}
	for _, cause := range []error{e.context, e.cleanup} {
		if cause != nil {
			causes = append(causes, cause)
		}
	}
	for _, candidate := range e.candidates[:e.count] {
		for _, cause := range []error{candidate.cause, candidate.cleanup} {
			if cause != nil {
				causes = append(causes, cause)
			}
		}
	}
	return causes
}

func (e *connectorLegAttemptError) Error() string { return errors.Join(e.Unwrap()...).Error() }

func (e *connectorLegAttemptError) disposition(authenticated bool) reconnectDisposition {
	if connectorRetryVeto(e) || e.context != nil && !connectorAttemptTemporary(e.context) {
		return terminateConnection
	}
	retry, stale := authenticated, false
	for _, candidate := range e.candidates[:e.count] {
		if candidate.stage != connectorAttemptConnect && candidate.stage != connectorAttemptHello && candidate.stage != connectorAttemptActivation {
			return terminateConnection
		}
		if candidate.canceled {
			continue
		}
		normalReplyEnd := (candidate.stage == connectorAttemptHello || candidate.stage == connectorAttemptActivation) &&
			tunnel.ConnectorReplyEndedNormally(candidate.cause)
		if connectorReconnectError(candidate.cause) == rebindConnection {
			stale = true
		} else if connectorAttemptTemporary(candidate.cause) || normalReplyEnd {
			retry = true
		} else if candidate.stage != connectorAttemptConnect || !connectorSingleConnectFailure(candidate.cause) {
			return terminateConnection
		}
	}
	if stale {
		return rebindConnection
	}
	if retry {
		return retryAttempt
	}
	return terminateConnection
}

// an unclassified pre-session failure may be an unavailable alternate, but
// cannot supply retry evidence or hide a second independently failed operation.
func connectorSingleConnectFailure(err error) bool {
	if err == nil || connectorRetryVeto(err) {
		return false
	}
	switch cause := err.(type) {
	case *tunnel.ProtocolError, *failure.Error, interface{ FailureReason() failure.Reason }:
		return false
	case interface{ Unwrap() []error }:
		children := cause.Unwrap()
		return len(children) == 1 && connectorSingleConnectFailure(children[0])
	case interface{ Unwrap() error }:
		if child := cause.Unwrap(); child != nil {
			return connectorSingleConnectFailure(child)
		}
	}
	return true
}

func connectorCanceledCandidate(err error) bool {
	if err == context.Canceled {
		return true
	}
	if err == nil || connectorRetryVeto(err) {
		return false
	}
	if connectorAttemptTemporary(err) || muxsession.NormalSessionCloseOnly(err) {
		return true
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		children := cause.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !connectorCanceledCandidate(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return connectorCanceledCandidate(cause.Unwrap())
	}
	return false
}

func connectorLegProof(signer Signer, pair controlv1.ConnectorPeerPair, slot int) (tunnelv1.ConnectorPairLegProof, error) {
	relay := pair.Relays[slot]
	proof := tunnelv1.ConnectorPairLegProof{PairID: pair.PairId, DeliveryGeneration: pair.DeliveryGeneration, ServiceID: pair.ServiceId, ServiceRunID: pair.ServiceRunId, RunNumber: pair.RunNumber, PublisherIdentityID: pair.PublisherIdentityId,
		ConnectionSlot: slot, PublisherConnectionID: relay.PublisherConnectionId, AssignmentRevision: relay.AssignmentRevision, RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId, RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision), RequestedAt: time.Now().UTC().Truncate(time.Microsecond), Nonce: make([]byte, 32)}
	if _, err := rand.Read(proof.Nonce); err != nil {
		return proof, err
	}
	message, err := proof.Message()
	if err != nil {
		return proof, err
	}
	proof.Signature = signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, proof.Signature) {
		return proof, ErrServiceConnection
	}
	return proof, nil
}

// connectConnectorLeg joins both raced candidates before selecting one. candidates
// are passive until activation, so a losing QUIC/TCP attempt cannot spend the
// publisher's registration or replace a sibling's replay state.
func connectConnectorLeg(ctx, lifetime context.Context, config Config, signer Signer, pair controlv1.ConnectorPeerPair, key [32]byte, slot int) (*connectorRelayLeg, error) {
	var operation tunnelv1.ConnectorHandoffID
	if _, err := rand.Read(operation[:]); err != nil {
		return nil, err
	}
	for {
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		leg, err := prepareConnectorLeg(attempt, lifetime, config, signer, pair, key, slot, nil, operation)
		if err == nil {
			err = context.Cause(attempt)
		}
		stop()
		if err == nil {
			return leg, nil
		}
		if leg != nil {
			err = errors.Join(err, connectorCleanupFailure(leg.Close()))
		}
		if ctx.Err() != nil {
			return nil, errors.Join(err, context.Cause(ctx))
		}
		if connectorReconnectError(err) != retryAttempt {
			return nil, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(err, context.Cause(ctx))
		case <-timer.C:
		}
	}
}

type connectorLegReplacement struct {
	previous *connectorRelayLeg
	handoff  tunnelv1.ConnectorHandoff
}

func nextConnectorLegReplacement(previous *connectorRelayLeg) (*connectorLegReplacement, error) {
	revision, err := previous.handoffRevision.Next()
	if err != nil {
		return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.HandoffRevisionExhausted}, err)
	}
	var nextID tunnelv1.ConnectorHandoffID
	if _, err := rand.Read(nextID[:]); err != nil {
		return nil, err
	}
	handoff, err := tunnelv1.NewConnectorHandoff(previous.selectedHandoff, nextID, revision)
	if err != nil {
		return nil, err
	}
	return &connectorLegReplacement{previous: previous, handoff: handoff}, nil
}

func prepareConnectorLeg(ctx, lifetime context.Context, config Config, signer Signer, pair controlv1.ConnectorPeerPair, key [32]byte, slot int, replacement *connectorLegReplacement, initial tunnelv1.ConnectorHandoffID) (*connectorRelayLeg, error) {
	l, err := dialConnectorLeg(ctx, lifetime, config, signer, pair, key, slot, replacement, initial)
	if err != nil {
		return nil, err
	}
	if err := activateConnectorLeg(ctx, l, replacement, initial); err != nil {
		return nil, connectorActivationFailure(ctx, l, err)
	}
	return l, nil
}

func connectorActivationFailure(ctx context.Context, l *connectorRelayLeg, err error) error {
	cleanup := connectorCleanupFailure(l.Close())
	return &connectorLegAttemptError{count: 1,
		candidates: [2]connectorCandidateFailure{{stage: connectorAttemptActivation, cause: err}},
		context:    context.Cause(ctx), cleanup: cleanup}
}

// dialConnectorLeg obtains the relay's source claim without selecting packet
// forwarding. pending bindings must wait for publisher installation first.
func dialConnectorLeg(ctx, lifetime context.Context, config Config, signer Signer, pair controlv1.ConnectorPeerPair, key [32]byte, slot int, replacement *connectorLegReplacement, initial tunnelv1.ConnectorHandoffID) (_ *connectorRelayLeg, retErr error) {
	if (replacement == nil) == (initial == (tunnelv1.ConnectorHandoffID{})) {
		return nil, ErrServiceConnection
	}
	roots := config.TransportTLS
	if roots == nil {
		roots = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	quicConnector, tcpConnector := config.RelayQUIC, config.RelayTCP
	if quicConnector == nil {
		return nil, ErrServiceConnection
	}
	if tcpConnector == nil {
		tcpConnector = muxsession.TLSYamuxConnector{TLSConfig: roots}
	}
	type result struct {
		leg    *connectorRelayLeg
		outer  muxsession.Session
		failed connectorCandidateFailure
	}
	results := make(chan result, 2)
	race, cancel := context.WithCancel(ctx)
	defer cancel()
	start := func(connector muxsession.Connector, transport tunnel.Transport) {
		go func() {
			startedAttempt := time.Now()
			next := func() result {
				proof, err := connectorLegProof(signer, pair, slot)
				if err != nil {
					return result{failed: connectorCandidateFailure{stage: connectorAttemptProof, cause: err}}
				}
				outer, err := connector.Connect(race, muxsession.Endpoint{Address: pair.Relays[slot].RelayAddress, ServerName: pair.Relays[slot].TlsServerName})
				if err != nil {
					failed := connectorCandidateFailure{stage: connectorAttemptConnect, cause: err}
					if outer != nil {
						failed.cleanup = connectorCleanupFailure(outer.Close())
					}
					return result{failed: failed}
				}
				if outer == nil {
					return result{failed: connectorCandidateFailure{stage: connectorAttemptCapability, cause: peer.ErrConfiguration}}
				}
				if transport == tunnel.TransportQUIC {
					packets, ok := outer.(muxsession.DatagramSession)
					if !ok || !packets.SupportsDatagrams() {
						return result{failed: connectorCandidateFailure{stage: connectorAttemptCapability, cause: peer.ErrConfiguration, cleanup: connectorCleanupFailure(outer.Close())}}
					}
				}
				started := time.Now()
				session, receipt, err := tunnel.DialConnector(race, outer, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}, pair.DeliveryId)
				if err != nil {
					return result{failed: connectorCandidateFailure{stage: connectorAttemptHello, cause: err}}
				}
				return result{leg: &connectorRelayLeg{session: session, proof: proof, receipt: receipt, transport: transport, until: started.Add(receipt.ExpiresAt.Sub(receipt.ObservedAt)), relay: pair.Relays[slot]}, outer: outer}
			}()
			next.failed.canceled = race.Err() != nil && ctx.Err() == nil && connectorCanceledCandidate(next.failed.cause)
			config.telemetry.RelayAttempt(race, transport, time.Since(startedAttempt), errors.Join(next.failed.cause, next.failed.cleanup))
			results <- next
		}()
	}
	primary, fallback := quicConnector, tcpConnector
	primaryKind, fallbackKind := tunnel.TransportQUIC, tunnel.TransportTLSTCP
	start(primary, primaryKind)
	remaining, fallbackStarted := 1, false
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	var winner result
	attempt := &connectorLegAttemptError{}
	stopped := ctx.Done()
	for remaining > 0 {
		select {
		case <-stopped:
			stopped = nil
			cancel()
			attempt.context = context.Cause(ctx)
		case <-timer.C:
			if !fallbackStarted && winner.leg == nil {
				fallbackStarted = true
				remaining++
				start(fallback, fallbackKind)
			}
		case next := <-results:
			remaining--
			if next.leg != nil {
				if winner.leg == nil && ctx.Err() == nil {
					winner = next
					cancel()
				} else {
					attempt.cleanup = errors.Join(attempt.cleanup, connectorCleanupFailure(next.leg.Close()))
				}
			} else {
				attempt.candidates[attempt.count] = next.failed
				attempt.count++
				if !fallbackStarted && winner.leg == nil && ctx.Err() == nil {
					fallbackStarted = true
					remaining++
					start(fallback, fallbackKind)
				}
			}
		}
	}
	attempt.context = context.Cause(ctx)
	if winner.leg == nil {
		causes := []error{attempt.context, attempt.cleanup}
		for _, candidate := range attempt.candidates[:attempt.count] {
			causes = append(causes, candidate.cause, candidate.cleanup)
		}
		if cause := context.Cause(ctx); cause != nil && failure.Only(errors.Join(causes...), cause) {
			return nil, cause
		}
		return nil, attempt
	}
	l := winner.leg
	if attempt.disposition(true) != retryAttempt {
		attempt.cleanup = errors.Join(attempt.cleanup, connectorCleanupFailure(l.Close()))
		return nil, attempt
	}
	owned := false
	defer func() {
		if !owned {
			retErr = errors.Join(retErr, connectorCleanupFailure(l.Close()))
		}
	}()
	if l.transport == tunnel.TransportTLSTCP {
		config.telemetry.Record(telemetryv1.Fallback, telemetryv1.TlsTcp, telemetryv1.Succeeded, 0)
	}
	hello, err := tunnelv1.ParseConnectorHelloNonce(l.proof.Nonce)
	if err != nil {
		return nil, err
	}
	l.selectedHandoff = tunnelv1.InitialConnectorActivation(hello).SelectedHandoff()
	if replacement == nil {
		l.selectedHandoff = initial
	}
	if ctx.Err() != nil || !l.until.After(time.Now()) {
		return nil, errors.Join(ErrServiceConnection, context.Cause(ctx))
	}
	if replacement != nil {
		previous := replacement.previous
		if !previous.until.After(time.Now()) || l.receipt.SourceIP != previous.receipt.SourceIP || !previous.proof.SameLeg(l.proof) || previous.receipt.DeliveryID != l.receipt.DeliveryID {
			return nil, ErrServiceConnection
		}
		l.until = earliestConnectorDeadline(l.until, previous.until)
	}
	l.packets, err = peer.NewSharedSession(lifetime, winner.outer)
	if err != nil {
		return nil, err
	}
	id, _ := tunnelv1.ParsePeerDeliveryIdentifier(pair.DeliveryId)
	l.carrier, err = l.packets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(pair.DeliveryGeneration)}, Key: key, Role: 0, Path: uint8(slot)}, true)
	if err != nil {
		return nil, err
	}
	owned = true
	return l, nil
}

func activateConnectorLeg(ctx context.Context, l *connectorRelayLeg, replacement *connectorLegReplacement, initial tunnelv1.ConnectorHandoffID) error {
	request, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err == nil {
		if replacement == nil {
			err = l.session.ActivateConnectorBinding(ctx, request, initial)
		} else {
			l.selectedHandoff = replacement.handoff.Next()
			l.handoffRevision = replacement.handoff.Revision()
			err = l.session.ReplaceConnectorLeg(ctx, request, replacement.handoff)
		}
	}
	return err
}

// a packet-carrier failure must wake the leg owner even when its control stream
// is still connected. the slot closes this wrapper after canceling packet work.
type connectorLegCarrier struct{ *connectorRelayLeg }

func (c connectorLegCarrier) Send(ctx context.Context, b []byte) error { return c.carrier.Send(ctx, b) }
func (c connectorLegCarrier) Receive(ctx context.Context) ([]byte, error) {
	return c.carrier.Receive(ctx)
}
func (c connectorLegCarrier) Close() error { return c.connectorRelayLeg.Close() }
