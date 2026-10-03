package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const publishRunConnectionCount = 2

const maximumExpiredPublishRunBatch = 100

var (
	ErrPublicURLNotFound         = errors.New("controlstate: public URL not found")
	ErrPublicURLNotEnabled       = errors.New("controlstate: public URL is not enabled")
	ErrPublicURLCredential       = errors.New("controlstate: public URL credential is invalid")
	ErrPublicURLAuthority        = errors.New("controlstate: route authority is stale")
	ErrPublishRunConflict        = errors.New("controlstate: public URL already has a live session")
	ErrPublishRunIdempotency     = errors.New("controlstate: publish-run idempotency conflict")
	ErrPublishRunCreationGated   = errors.New("controlstate: publish-run creation is disabled")
	ErrInsufficientRelayServices = errors.New("controlstate: insufficient relay-service placement capacity")
	errRelayPlacementCapacity    = errors.New("controlstate: relay-service placement capacity exhausted")
)

// PublishRunRequest carries authority already established by the control API
// and the authenticated request secret used for retry-stable credentials.
type PublishRunRequest struct {
	PublicURLID              string
	TeamID                   string
	MembershipID             string
	ActingIdentityID         string
	RequireLocalAuthority    bool
	RetrySecret              []byte
	IdempotencyKey           string
	RequestDigest            [32]byte
	PolicyRevision           uint64
	CertificateCacheKey      string
	CertificateScope         string
	CertificateIdentifiers   []string
	CertificateChallenge     certificateidentity.ChallengeMethod
	AuthorityIssuer          string
	ExpectedMutationRevision uint64
}

// ConnectionAssignment is one of the two independently assigned publisher
// connections returned by publish-run setup and heartbeat replenishment.
type ConnectionAssignment struct {
	ConnectionAssignmentIdentity
	RelayAddress                           string
	TLSServerName                          string
	PublisherConnectionCredential          credentials.PublisherConnectionCredential
	PublisherConnectionCredentialExpiresAt time.Time
	State                                  PublisherConnectionState
}

// PublishRunSetup is the retry-stable result of publish-run creation.
type PublishRunSetup struct {
	PublishRunID         string
	PublicURLID          string
	TeamID               string
	MembershipID         string
	PublishRunNumber     uint64
	PolicyRevision       uint64
	PublishRunToken      credentials.PublishRunToken
	State                PublishRunState
	CreatedAt            time.Time
	ExpiresAt            time.Time
	ReadyAt              *time.Time
	ClosedAt             *time.Time
	PolicyDenials        uint64
	PublisherConnections [publishRunConnectionCount]ConnectionAssignment
}

// CreatePublishRun creates one publish run with two connection assignments on
// distinct relay services. an authenticated retry returns the same publish run
// and assignment credentials.
func (d *Database) CreatePublishRun(
	ctx context.Context,
	request PublishRunRequest,
	now time.Time,
	publisherLeaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) (result PublishRunSetup, retErr error) {
	defer d.observeOperation("CreatePublishRun", &retErr)()
	defer func() {
		if !errors.Is(retErr, ErrInsufficientRelayServices) {
			return
		}
		outcome := observability.PlacementInsufficientServices
		if errors.Is(retErr, errRelayPlacementCapacity) {
			outcome = observability.PlacementCapacity
		}
		d.activity.metrics.Load().ObservePlacement("create", outcome)
	}()
	if err := validatePublishRunRequest(request, publisherLeaseDuration, connectionCredentialDuration); err != nil {
		return PublishRunSetup{}, err
	}
	if err := d.requireOpen(); err != nil {
		return PublishRunSetup{}, err
	}
	result, retErr = d.createPublishRun(ctx, request, now, publisherLeaseDuration, connectionCredentialDuration)
	if !errors.Is(retErr, ErrInsufficientRelayServices) {
		return result, retErr
	}
	// placement takes the assignment-total guard after the public URL lock.
	// roll back before closing expired runs on other public URLs, then retry once.
	closed, err := d.ExpireSavedPublishRuns(ctx, now)
	if err != nil {
		return PublishRunSetup{}, err
	}
	if closed == 0 {
		return PublishRunSetup{}, retErr
	}
	return d.createPublishRun(ctx, request, now, publisherLeaseDuration, connectionCredentialDuration)
}

func (d *Database) createPublishRun(
	ctx context.Context,
	request PublishRunRequest,
	now time.Time,
	publisherLeaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) (result PublishRunSetup, retErr error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create publish run", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}

	if request.RequireLocalAuthority {
		if _, err := queries.LockLocalTeamForSession(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return PublishRunSetup{}, ErrPublicURLAuthority
		} else if err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: lock team: %w", err)
		}
	}
	if request.AuthorityIssuer != "" {
		if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
			Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
			PolicyRevision: positive(request.PolicyRevision), UpdatedAt: timestamptz(now),
		}); errors.Is(err, pgx.ErrNoRows) {
			return PublishRunSetup{}, ErrPublicURLAuthority
		} else if err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: observe authority revision: %w", err)
		}
	}
	route, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunSetup{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: lock public_url: %w", err)
	}
	if err := authenticatePublishRunRequest(route, request); err != nil {
		return PublishRunSetup{}, err
	}
	if request.RequireLocalAuthority {
		membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return PublishRunSetup{}, ErrPublicURLAuthority
		}
		if err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: read membership: %w", err)
		}
		if membership.PolicyRevision != positive(request.PolicyRevision) ||
			route.PublicURLScope == "member" && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID || request.MembershipID != membership.ID) ||
			route.PublicURLScope == "shared" && (membership.Role != "admin" && membership.Role != "owner" || request.MembershipID != membership.ID) {
			return PublishRunSetup{}, ErrPublicURLAuthority
		}
	}
	hasOpenSession, _, err := expireStaleOpenPublishRun(ctx, queries, &pendingEvents, route, now)
	if err != nil {
		return PublishRunSetup{}, err
	}

	existing, err := queries.GetPublishRunByIdempotency(ctx, controlstatedb.GetPublishRunByIdempotencyParams{
		PublicURLID: request.PublicURLID, IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, request.RequestDigest[:]) != 1 {
			return PublishRunSetup{}, ErrPublishRunIdempotency
		}
		setup, err := loadPublishRunSetup(ctx, queries, request.RetrySecret, request.PublicURLID+"\x00"+request.IdempotencyKey, existing)
		if err != nil {
			return PublishRunSetup{}, err
		}
		if err := pendingEvents.publish(ctx, queries); err != nil {
			return PublishRunSetup{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: commit retry: %w", err)
		}
		return setup, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: read idempotent session: %w", err)
	}
	if PublicURLLifecycleState(route.LifecycleState) != PublicURLLifecycleEnabled {
		return PublishRunSetup{}, ErrPublicURLNotEnabled
	}
	if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
		return PublishRunSetup{}, ErrPublicURLMutationStale
	}
	enabled, err := queries.LockPublishRunCreationControl(ctx)
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: read maintenance control: %w", err)
	}
	if !enabled {
		return PublishRunSetup{}, ErrPublishRunCreationGated
	}
	if hasOpenSession {
		return PublishRunSetup{}, ErrPublishRunConflict
	}
	if route.Ephemeral {
		if _, err := queries.RenewEphemeralPublicURLExpiry(ctx, controlstatedb.RenewEphemeralPublicURLExpiryParams{
			ExpiresAt: timestamptz(now.Add(ephemeralPublicURLGracePeriod)), PublicURLID: route.ID,
		}); err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: renew ephemeral public_url: %w", err)
		}
	}

	placements, err := selectRelayServicePlacements(ctx, queries, now)
	if err != nil {
		return PublishRunSetup{}, err
	}
	publishRunID, err := opaqueid.New(opaqueid.PublishRunPrefix)
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: generate session ID: %w", err)
	}
	publishRunToken, publishRunTokenID, publishRunTokenHash, err := credentials.DerivePublishRunToken(
		request.RetrySecret, request.PublicURLID+"\x00"+request.IdempotencyKey,
	)
	if err != nil {
		return PublishRunSetup{}, ErrPublicURLCredential
	}
	membershipID := pgtype.Text{}
	if request.MembershipID != "" {
		membershipID = text(request.MembershipID)
	}
	session, err := queries.InsertPublishRun(ctx, controlstatedb.InsertPublishRunParams{
		ID: publishRunID, PublicURLID: request.PublicURLID, TeamID: request.TeamID, MembershipID: membershipID,
		ActingIdentityID: request.ActingIdentityID, ExpectedMutationRevision: positive(request.ExpectedMutationRevision),
		IdempotencyKey: request.IdempotencyKey, RequestDigest: request.RequestDigest[:],
		PublishRunTokenID: publishRunTokenID.String(), PublishRunTokenDigest: publishRunTokenHash[:],
		PolicyRevision: positive(request.PolicyRevision), CertificateCacheKey: request.CertificateCacheKey,
		CertificateScope: request.CertificateScope, CertificateIdentifiers: request.CertificateIdentifiers,
		CertificateChallengeMethod: string(request.CertificateChallenge), CreatedAt: timestamptz(now),
		LastHeartbeatAt: timestamptz(now), PublisherExpiresAt: timestamptz(now.Add(publisherLeaseDuration)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if route.NextPublishRunNumber == math.MaxInt64 || route.MutationRevision == math.MaxInt64 {
			return PublishRunSetup{}, errors.New("controlstate: publish run number or mutation revision is exhausted")
		}
		return PublishRunSetup{}, ErrPublicURLMutationStale
	}
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: insert session: %w", err)
	}

	connections := controlstatedb.InsertPublishRunConnectionsParams{
		PublishRunID: publishRunID, PublicURLID: request.PublicURLID, PublishRunNumber: session.PublishRunNumber,
		PublisherConnectionCredentialExpiresAt: timestamptz(now.Add(connectionCredentialDuration)), AssignedAt: timestamptz(now),
	}
	for _, placement := range placements {
		publisherConnectionID, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
		if err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: generate publisher connection ID: %w", err)
		}
		_, credentialHash, err := credentials.DerivePublisherConnectionCredential(
			publishRunToken, publisherConnectionCredentialContext(publisherConnectionID, 1),
		)
		if err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: derive publisher connection credential: %w", err)
		}
		connections.PublisherConnectionIds = append(connections.PublisherConnectionIds, publisherConnectionID)
		connections.RelayServiceIds = append(connections.RelayServiceIds, placement.relayServiceID)
		connections.RelayAddresses = append(connections.RelayAddresses, placement.relayAddress)
		connections.TlsServerNames = append(connections.TlsServerNames, placement.tlsServerName)
		connections.CredentialDigests = append(connections.CredentialDigests, credentialHash[:])
	}
	connectionRows, err := queries.InsertPublishRunConnections(ctx, connections)
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: insert connections: %w", err)
	}
	setup, err := publishRunSetup(session, publishRunToken, connectionRows)
	if err != nil {
		return PublishRunSetup{}, err
	}
	if err := queries.InsertPublishRunAuditEvent(ctx, controlstatedb.InsertPublishRunAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), Actor: request.ActingIdentityID,
		RequestID: request.IdempotencyKey, PublishRunID: publishRunID, OccurredAt: timestamptz(now),
	}); err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return PublishRunSetup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: create publish run: commit: %w", err)
	}
	d.activity.metrics.Load().ObservePlacement("create", "placed")
	return setup, nil
}

type relayServicePlacement struct {
	relayServiceID string
	relayAddress   string
	tlsServerName  string
	capacity       int64
	assignments    int64
}

func selectRelayServicePlacements(
	ctx context.Context,
	queries *controlstatedb.Queries,
	now time.Time,
) ([publishRunConnectionCount]relayServicePlacement, error) {
	services, _, err := availableRelayServicePlacements(ctx, queries, now)
	if err != nil {
		return [publishRunConnectionCount]relayServicePlacement{}, fmt.Errorf("controlstate: create publish run: %w", err)
	}
	var result [publishRunConnectionCount]relayServicePlacement
	index := 0
	for _, service := range services {
		if service.assignments >= service.capacity {
			continue
		}
		result[index] = service
		index++
		if index == len(result) {
			return result, nil
		}
	}
	if len(services) >= publishRunConnectionCount {
		return result, fmt.Errorf("%w: %w", ErrInsufficientRelayServices, errRelayPlacementCapacity)
	}
	return result, ErrInsufficientRelayServices
}

func availableRelayServicePlacements(
	ctx context.Context,
	queries *controlstatedb.Queries,
	now time.Time,
) ([]relayServicePlacement, []controlstatedb.LockEligibleRelayLeasesRow, error) {
	// the query takes the assignment-total guard before service guards and rows. finish
	// locking services before leases, matching registration's service-first order.
	serviceIDs, err := queries.LockRelayServicesForPlacement(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("lock relay services: %w", err)
	}
	leases, err := queries.LockEligibleRelayLeases(ctx, controlstatedb.LockEligibleRelayLeasesParams{
		Now: timestamptz(now), ProtocolVersion: 1, RelayServiceIds: serviceIDs,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("lock relay leases: %w", err)
	}
	counts, err := queries.ListRelayServiceAssignmentTotals(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read relay-service assignment totals: %w", err)
	}
	assignments := make(map[string]int64, len(counts))
	for _, count := range counts {
		assignments[count.RelayServiceID] = count.AssignmentCount
	}
	servicesByID := make(map[string]*relayServicePlacement)
	for _, lease := range leases {
		service := servicesByID[lease.RelayServiceID]
		if service == nil {
			service = &relayServicePlacement{
				relayServiceID: lease.RelayServiceID, relayAddress: lease.RelayAddress,
				tlsServerName: lease.TlsServerName, assignments: assignments[lease.RelayServiceID],
			}
			servicesByID[lease.RelayServiceID] = service
		}
		if lease.ConnectionCapacity > math.MaxInt64-service.capacity {
			service.capacity = math.MaxInt64
		} else {
			service.capacity += lease.ConnectionCapacity
		}
	}
	services := make([]relayServicePlacement, 0, len(servicesByID))
	for _, service := range servicesByID {
		services = append(services, *service)
	}
	sort.Slice(services, func(left, right int) bool {
		leftLoad := float64(services[left].assignments) / float64(services[left].capacity)
		rightLoad := float64(services[right].assignments) / float64(services[right].capacity)
		if leftLoad == rightLoad {
			return services[left].relayServiceID < services[right].relayServiceID
		}
		return leftLoad < rightLoad
	})
	return services, leases, nil
}

func authenticatePublishRunRequest(route controlstatedb.ControlPublicUrl, request PublishRunRequest) error {
	if route.TeamID != request.TeamID || route.PolicyRevision > positive(request.PolicyRevision) {
		return ErrPublicURLAuthority
	}
	return nil
}

func loadPublishRunSetup(
	ctx context.Context,
	queries *controlstatedb.Queries,
	retrySecret []byte,
	retryContext string,
	session controlstatedb.ControlPublishRun,
) (PublishRunSetup, error) {
	token, tokenID, tokenHash, err := credentials.DerivePublishRunToken(retrySecret, retryContext)
	if err != nil || tokenID.String() != session.PublishRunTokenID ||
		!credentials.SecretHashMatches(session.PublishRunTokenDigest, tokenHash) {
		return PublishRunSetup{}, ErrPublicURLCredential
	}
	return loadPublishRunSetupWithToken(ctx, queries, token, session)
}

func loadPublishRunSetupWithToken(
	ctx context.Context,
	queries *controlstatedb.Queries,
	token credentials.PublishRunToken,
	session controlstatedb.ControlPublishRun,
) (PublishRunSetup, error) {
	connections, err := queries.ListPublishRunConnections(ctx, session.ID)
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: load publish run connections: %w", err)
	}
	return publishRunSetup(session, token, connections)
}

func publishRunSetup(
	session controlstatedb.ControlPublishRun,
	token credentials.PublishRunToken,
	connections []controlstatedb.ControlPublishRunConnectionSlot,
) (PublishRunSetup, error) {
	if session.PublishRunNumber <= 0 || !session.CreatedAt.Valid || !session.PublisherExpiresAt.Valid ||
		len(connections) != publishRunConnectionCount {
		return PublishRunSetup{}, errors.New("controlstate: invalid publish run row")
	}
	setup := PublishRunSetup{
		PublishRunID: session.ID, PublicURLID: session.PublicURLID, TeamID: session.TeamID,
		MembershipID: session.MembershipID.String, PublishRunNumber: uint64(session.PublishRunNumber),
		PolicyRevision: uint64(session.PolicyRevision), PublishRunToken: token, State: PublishRunState(session.State),
		CreatedAt: session.CreatedAt.Time, ExpiresAt: session.PublisherExpiresAt.Time,
		PolicyDenials: uint64(session.PolicyDenials),
	}
	if session.ReadyAt.Valid {
		value := session.ReadyAt.Time
		setup.ReadyAt = &value
	}
	if session.ClosedAt.Valid {
		value := session.ClosedAt.Time
		setup.ClosedAt = &value
	}
	seen := [publishRunConnectionCount]bool{}
	for _, row := range connections {
		if row.ConnectionSlot < 0 || int(row.ConnectionSlot) >= publishRunConnectionCount || seen[row.ConnectionSlot] {
			return PublishRunSetup{}, errors.New("controlstate: invalid publish-run connection slots")
		}
		credential, hash, err := credentials.DerivePublisherConnectionCredential(
			token, publisherConnectionCredentialContext(row.PublisherConnectionID, row.ConnectionAssignmentRevision),
		)
		if err != nil || !credentials.SecretHashMatches(row.PublisherConnectionCredentialDigest, hash) {
			return PublishRunSetup{}, errors.New("controlstate: invalid publisher connection credential")
		}
		assignment, err := connectionAssignment(row, credential)
		if err != nil {
			return PublishRunSetup{}, err
		}
		setup.PublisherConnections[row.ConnectionSlot] = assignment
		seen[row.ConnectionSlot] = true
	}
	return setup, nil
}

func connectionAssignment(
	row controlstatedb.ControlPublishRunConnectionSlot,
	credential credentials.PublisherConnectionCredential,
) (ConnectionAssignment, error) {
	if row.PublishRunNumber <= 0 || row.ConnectionAssignmentRevision <= 0 || row.ConnectionSlot < 0 ||
		row.ConnectionSlot >= publishRunConnectionCount || !row.PublisherConnectionCredentialExpiresAt.Valid {
		return ConnectionAssignment{}, errors.New("controlstate: invalid publish-run connection row")
	}
	return ConnectionAssignment{
		ConnectionAssignmentIdentity: ConnectionAssignmentIdentity{
			PublishRunID: row.PublishRunID, PublicURLID: row.PublicURLID, PublishRunNumber: uint64(row.PublishRunNumber),
			ConnectionSlot: int(row.ConnectionSlot), PublisherConnectionID: row.PublisherConnectionID,
			ConnectionAssignmentRevision: uint64(row.ConnectionAssignmentRevision), RelayServiceID: row.RelayServiceID,
		},
		RelayAddress: row.RelayAddress, TLSServerName: row.TlsServerName,
		PublisherConnectionCredential:          credential,
		PublisherConnectionCredentialExpiresAt: row.PublisherConnectionCredentialExpiresAt.Time,
		State:                                  PublisherConnectionState(row.State),
	}, nil
}

func validatePublishRunRequest(
	request PublishRunRequest,
	publisherLeaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) error {
	for _, value := range []string{
		request.PublicURLID, request.TeamID, request.ActingIdentityID, request.IdempotencyKey,
		request.CertificateCacheKey, request.CertificateScope, string(request.CertificateChallenge),
	} {
		if !validStateText(value) {
			return errors.New("controlstate: publish-run request is invalid")
		}
	}
	if request.MembershipID != "" && !validStateText(request.MembershipID) {
		return errors.New("controlstate: publish-run membership ID is invalid")
	}
	if request.AuthorityIssuer != "" && !validStateText(request.AuthorityIssuer) {
		return errors.New("controlstate: publish-run authority issuer is invalid")
	}
	if len(request.RetrySecret) < 32 {
		return ErrPublicURLCredential
	}
	if _, ok := positiveInt64(request.PolicyRevision); !ok {
		return errors.New("controlstate: publish-run policy revision must be positive")
	}
	identifiers, err := canonicalCertificateIdentifiers(request.CertificateIdentifiers)
	if err != nil || !slices.Equal(identifiers, request.CertificateIdentifiers) {
		return errors.New("controlstate: publish-run certificate identifiers must be a canonical sorted set")
	}
	if !request.CertificateChallenge.Valid() {
		return errors.New("controlstate: publish-run certificate challenge is invalid")
	}
	if request.CertificateChallenge == certificateidentity.ChallengeTLSALPN01 && slices.ContainsFunc(identifiers, func(identifier string) bool {
		return strings.HasPrefix(identifier, "*.")
	}) {
		return errors.New("controlstate: TLS-ALPN-01 does not support wildcard identifiers")
	}
	if request.ExpectedMutationRevision == 0 || request.ExpectedMutationRevision > math.MaxInt64 {
		return errors.New("controlstate: publish-run mutation revision must be positive")
	}
	if publisherLeaseDuration <= 0 || connectionCredentialDuration <= 0 {
		return errors.New("controlstate: publish-run durations must be positive")
	}
	return nil
}

func prefixValues(values []string) []netip.Prefix {
	result := make([]netip.Prefix, len(values))
	for index, value := range values {
		result[index], _ = netip.ParsePrefix(value)
	}
	return result
}

func publisherConnectionCredentialContext(publisherConnectionID string, assignmentRevision int64) string {
	return publisherConnectionID + "/" + strconv.FormatInt(assignmentRevision, 10)
}
