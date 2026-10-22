package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/readiness"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

var (
	ErrPublishRunCredential = errors.New("controlstate: publish-run credential is invalid")
	ErrPublishRunStale      = errors.New("controlstate: publish run identity or version is stale")
	ErrPublishRunNotReady   = errors.New("controlstate: publish run is not ready")
	ErrPublicURLCertificate = errors.New("controlstate: public URL certificate acknowledgement is invalid")
)

const transactionRollbackTimeout = 5 * time.Second

// PublishRunNotReadyError reports the prerequisites checked under the public URL
// and publish run locks. it does not contain credentials or certificate material.
type PublishRunNotReadyError struct {
	CertificateInstalled          bool
	ReadyPublisherConnectionCount int
	DNSState                      PublicURLDNSState
	CreatedAt                     time.Time
}

func (e *PublishRunNotReadyError) Error() string { return ErrPublishRunNotReady.Error() }
func (e *PublishRunNotReadyError) Unwrap() error { return ErrPublishRunNotReady }

func (e *PublishRunNotReadyError) Reason() readiness.Outcome {
	switch {
	case e.DNSState == PublicURLDNSFailed:
		return readiness.DNSFailed
	case e.DNSState != "":
		return readiness.DNSPending
	case !e.CertificateInstalled && e.ReadyPublisherConnectionCount != publishRunConnectionCount:
		return readiness.CertificateAndConnectionsMissing
	case !e.CertificateInstalled:
		return readiness.CertificateMissing
	default:
		return readiness.ConnectionsMissing
	}
}

// PublishRunAuthentication binds a publish run credential to one exact publish run number.
type PublishRunAuthentication struct {
	PublishRunID     string
	PublicURLID      string
	PublishRunNumber uint64
	PublishRunToken  credentials.PublishRunToken
}

// PublishRunLifecycle reports saved readiness and current publisher connection availability.
type PublishRunLifecycle struct {
	PublishRunID                  string
	PublicURLID                   string
	TeamID                        string
	MembershipID                  string
	PublishRunNumber              uint64
	PolicyRevision                uint64
	State                         PublishRunState
	CreatedAt                     time.Time
	ExpiresAt                     time.Time
	ReadyAt                       *time.Time
	CertificateAt                 *time.Time
	ClosedAt                      *time.Time
	ReadyPublisherConnectionCount int
	Routable                      bool
	RoutingTableRevision          uint64
	PublicURLEntryRevision        uint64
}

func (d *Database) PublishRunAuthentication(
	ctx context.Context,
	publishRunID string,
	publishRunNumber uint64,
	token credentials.PublishRunToken,
) (PublishRunAuthentication, error) {
	if err := d.requireOpen(); err != nil {
		return PublishRunAuthentication{}, err
	}
	if !validStateText(publishRunID) {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	if _, ok := positiveInt64(publishRunNumber); !ok {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	tokenID, tokenHash, err := credentials.ParsePublishRunToken(token)
	if err != nil {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	session, err := controlstatedb.New(d.pool).GetPublishRun(ctx, publishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	if err != nil {
		return PublishRunAuthentication{}, fmt.Errorf("controlstate: read publish run authentication: %w", err)
	}
	if !matchesPositiveInt64(session.PublishRunNumber, publishRunNumber) || tokenID.String() != session.PublishRunTokenID ||
		!credentials.SecretHashMatches(session.PublishRunTokenDigest, tokenHash) {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	return PublishRunAuthentication{
		PublishRunID: publishRunID, PublicURLID: session.PublicURLID, PublishRunNumber: publishRunNumber, PublishRunToken: token,
	}, nil
}

func openPublicURLRecoveryEpisode(
	ctx context.Context,
	queries *controlstatedb.Queries,
	publicURLID string,
	publishRunNumber int64,
	now time.Time,
) error {
	if err := queries.OpenPublicURLRecoveryEpisode(ctx, controlstatedb.OpenPublicURLRecoveryEpisodeParams{
		PublicURLID: publicURLID, PublishRunNumber: publishRunNumber, OpenedAt: timestamptz(now),
	}); err != nil {
		return fmt.Errorf("controlstate: open route recovery episode: %w", err)
	}
	return nil
}

func publishRunLifecycle(
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	routingTableRevision int64,
	entryRevision int64,
) PublishRunLifecycle {
	result := PublishRunLifecycle{
		PublishRunID: session.ID, PublicURLID: session.PublicURLID, TeamID: session.TeamID,
		MembershipID: session.MembershipID.String, PublishRunNumber: uint64(session.PublishRunNumber),
		PolicyRevision: uint64(session.PolicyRevision), State: PublishRunState(session.State), CreatedAt: session.CreatedAt.Time,
		ExpiresAt: session.PublisherExpiresAt.Time, ReadyPublisherConnectionCount: len(connections),
		Routable:             session.ReadyAt.Valid && len(connections) > 0,
		RoutingTableRevision: uint64(routingTableRevision), PublicURLEntryRevision: uint64(entryRevision),
	}
	if session.ReadyAt.Valid {
		value := session.ReadyAt.Time
		result.ReadyAt = &value
	}
	if session.CertificateInstalledAt.Valid {
		value := session.CertificateInstalledAt.Time
		result.CertificateAt = &value
	}
	if session.ClosedAt.Valid {
		value := session.ClosedAt.Time
		result.ClosedAt = &value
	}
	return result
}

func validatePublishRunAuthentication(authentication PublishRunAuthentication) error {
	if !validStateText(authentication.PublishRunID) || !validStateText(authentication.PublicURLID) {
		return errors.New("controlstate: publish-run authentication is invalid")
	}
	if _, ok := positiveInt64(authentication.PublishRunNumber); !ok {
		return errors.New("controlstate: publish-run authentication has an invalid publish run number")
	}
	if _, _, err := credentials.ParsePublishRunToken(authentication.PublishRunToken); err != nil {
		return ErrPublishRunCredential
	}
	return nil
}

func publisherConnectionClaimParams(
	request PublisherConnectionClaimRequest,
	now time.Time,
) controlstatedb.MarkPublisherConnectionReadyParams {
	return controlstatedb.MarkPublisherConnectionReadyParams{
		ReadyAt: timestamptz(now), PublisherConnectionID: request.PublisherConnectionID,
		PublishRunID: request.PublishRunID, PublicURLID: request.PublicURLID, PublishRunNumber: positive(request.PublishRunNumber),
		ConnectionSlot:               int16(request.ConnectionSlot),
		ConnectionAssignmentRevision: positive(request.ConnectionAssignmentRevision),
		RelayServiceID:               request.ConnectionAssignmentIdentity.RelayServiceID,
		RelayID:                      text(request.RelayID), RelayRunID: text(request.RelayRunID),
		RelayLeaseRevision: int8(request.RelayLeaseRevision), ClaimID: text(request.ClaimID),
	}
}

func disconnectPublisherConnectionParams(
	request PublisherConnectionClaimRequest,
	now time.Time,
) controlstatedb.DisconnectPublisherConnectionParams {
	return controlstatedb.DisconnectPublisherConnectionParams{
		DisconnectedAt: timestamptz(now), PublisherConnectionID: request.PublisherConnectionID,
		PublishRunID: request.PublishRunID, PublicURLID: request.PublicURLID, PublishRunNumber: positive(request.PublishRunNumber),
		ConnectionSlot:               int16(request.ConnectionSlot),
		ConnectionAssignmentRevision: positive(request.ConnectionAssignmentRevision),
		RelayServiceID:               request.ConnectionAssignmentIdentity.RelayServiceID,
		RelayID:                      text(request.RelayID), RelayRunID: text(request.RelayRunID),
		RelayLeaseRevision: int8(request.RelayLeaseRevision), ClaimID: text(request.ClaimID),
	}
}
