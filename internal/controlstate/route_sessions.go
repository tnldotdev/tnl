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
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const routeSessionConnectionCount = 2

var (
	ErrRouteNotFound             = errors.New("controlstate: route not found")
	ErrRouteNotEnabled           = errors.New("controlstate: route is not enabled")
	ErrRouteCredential           = errors.New("controlstate: route credential is invalid")
	ErrRouteAuthority            = errors.New("controlstate: route authority is stale")
	ErrRouteSessionConflict      = errors.New("controlstate: route already has a live session")
	ErrRouteSessionIdempotency   = errors.New("controlstate: route-session idempotency conflict")
	ErrRouteSessionCreationGated = errors.New("controlstate: route-session creation is disabled")
	ErrInsufficientRelayServices = errors.New("controlstate: insufficient relay-service placement capacity")
)

// RouteSessionRequest contains authority already established by the control
// API plus the authenticated request secret used for retry-stable credentials.
type RouteSessionRequest struct {
	RouteID                  string
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
	CertificateChallenge     string
	AuthorityIssuer          string
	ExpectedMutationRevision uint64
}

// ConnectionAssignment is one of the two independently assigned publisher
// connections returned by route-session setup and heartbeat replenishment.
type ConnectionAssignment struct {
	ConnectionAssignmentIdentity
	RelayAddress                           string
	TLSServerName                          string
	PublisherConnectionCredential          credentials.PublisherConnectionCredential
	PublisherConnectionCredentialExpiresAt time.Time
	State                                  PublisherConnectionState
}

// RouteSessionSetup is the retry-stable result of route-session creation.
type RouteSessionSetup struct {
	RouteSessionID       string
	RouteID              string
	TeamID               string
	MembershipID         string
	RouteVersion         uint64
	PolicyRevision       uint64
	RouteSessionToken    credentials.RouteSessionToken
	State                RouteSessionState
	CreatedAt            time.Time
	ExpiresAt            time.Time
	ReadyAt              *time.Time
	ClosedAt             *time.Time
	PolicyDenials        uint64
	PublisherConnections [routeSessionConnectionCount]ConnectionAssignment
}

// CreateRouteSession creates one route version and exactly two connection
// assignments on distinct relay services. An authenticated retry returns the
// same session and assignment credentials.
func (d *Database) CreateRouteSession(
	ctx context.Context,
	request RouteSessionRequest,
	now time.Time,
	publisherLeaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) (result RouteSessionSetup, retErr error) {
	if err := validateRouteSessionRequest(request, publisherLeaseDuration, connectionCredentialDuration); err != nil {
		return RouteSessionSetup{}, err
	}
	if err := d.requireOpen(); err != nil {
		return RouteSessionSetup{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create route session", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}

	if request.RequireLocalAuthority {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return RouteSessionSetup{}, ErrRouteAuthority
		} else if err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: lock team: %w", err)
		}
	}
	if request.AuthorityIssuer != "" {
		if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
			Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
			PolicyRevision: positive(request.PolicyRevision), UpdatedAt: timestamptz(now),
		}); errors.Is(err, pgx.ErrNoRows) {
			return RouteSessionSetup{}, ErrRouteAuthority
		} else if err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: observe authority revision: %w", err)
		}
	}
	route, err := queries.LockRouteForSession(ctx, request.RouteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionSetup{}, ErrRouteNotFound
	}
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: lock route: %w", err)
	}
	if err := authenticateRouteSessionRequest(route, request); err != nil {
		return RouteSessionSetup{}, err
	}
	if request.RequireLocalAuthority {
		membership, err := queries.GetActiveRouteSessionMembership(ctx, controlstatedb.GetActiveRouteSessionMembershipParams{
			TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return RouteSessionSetup{}, ErrRouteAuthority
		}
		if err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: read membership: %w", err)
		}
		if membership.PolicyRevision != positive(request.PolicyRevision) ||
			route.RouteScope == "member" && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID || request.MembershipID != membership.ID) ||
			route.RouteScope == "shared" && (membership.Role != "admin" && membership.Role != "owner" || request.MembershipID != membership.ID) {
			return RouteSessionSetup{}, ErrRouteAuthority
		}
	}
	if err := expireStaleOpenRouteSession(ctx, queries, &pendingEvents, route, now); err != nil {
		return RouteSessionSetup{}, err
	}

	existing, err := queries.GetRouteSessionByIdempotency(ctx, controlstatedb.GetRouteSessionByIdempotencyParams{
		RouteID: request.RouteID, IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, request.RequestDigest[:]) != 1 {
			return RouteSessionSetup{}, ErrRouteSessionIdempotency
		}
		setup, err := loadRouteSessionSetup(ctx, queries, request.RetrySecret, request.RouteID+"\x00"+request.IdempotencyKey, existing)
		if err != nil {
			return RouteSessionSetup{}, err
		}
		if err := pendingEvents.publish(ctx, queries); err != nil {
			return RouteSessionSetup{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: commit retry: %w", err)
		}
		return setup, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: read idempotent session: %w", err)
	}
	if RouteLifecycleState(route.LifecycleState) != RouteLifecycleEnabled {
		return RouteSessionSetup{}, ErrRouteNotEnabled
	}
	if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
		return RouteSessionSetup{}, ErrRouteMutationStale
	}
	enabled, err := queries.LockRouteSessionCreationControl(ctx)
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: read maintenance control: %w", err)
	}
	if !enabled {
		return RouteSessionSetup{}, ErrRouteSessionCreationGated
	}
	if _, err := queries.GetOpenRouteSession(ctx, request.RouteID); err == nil {
		return RouteSessionSetup{}, ErrRouteSessionConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: read live session: %w", err)
	}
	if route.Ephemeral {
		if _, err := queries.RenewEphemeralRouteExpiry(ctx, controlstatedb.RenewEphemeralRouteExpiryParams{
			ExpiresAt: timestamptz(now.Add(ephemeralRouteGracePeriod)), RouteID: route.ID,
		}); err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: renew ephemeral route: %w", err)
		}
	}

	placements, err := selectRelayServicePlacements(ctx, queries, now)
	if err != nil {
		return RouteSessionSetup{}, err
	}
	routeVersion, err := queries.AllocateRouteVersion(ctx, controlstatedb.AllocateRouteVersionParams{
		UpdatedAt: timestamptz(now), RouteID: request.RouteID,
		ExpectedMutationRevision: positive(request.ExpectedMutationRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if route.NextRouteVersion == math.MaxInt64 || route.MutationRevision == math.MaxInt64 {
			return RouteSessionSetup{}, errors.New("controlstate: route version or mutation revision is exhausted")
		}
		return RouteSessionSetup{}, ErrRouteMutationStale
	}
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: allocate route version: %w", err)
	}
	routeSessionID, err := opaqueid.New("session_")
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: generate session ID: %w", err)
	}
	routeSessionToken, routeSessionTokenID, routeSessionTokenHash, err := credentials.DeriveRouteSessionToken(
		request.RetrySecret, request.RouteID+"\x00"+request.IdempotencyKey,
	)
	if err != nil {
		return RouteSessionSetup{}, ErrRouteCredential
	}
	membershipID := pgtype.Text{}
	if request.MembershipID != "" {
		membershipID = text(request.MembershipID)
	}
	session, err := queries.InsertRouteSession(ctx, controlstatedb.InsertRouteSessionParams{
		ID: routeSessionID, RouteID: request.RouteID, TeamID: request.TeamID, MembershipID: membershipID,
		ActingIdentityID: request.ActingIdentityID, RouteVersion: routeVersion,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: request.RequestDigest[:],
		SessionTokenID: routeSessionTokenID.String(), SessionTokenDigest: routeSessionTokenHash[:],
		PolicyRevision: positive(request.PolicyRevision), CertificateCacheKey: request.CertificateCacheKey,
		CertificateScope: request.CertificateScope, CertificateIdentifiers: request.CertificateIdentifiers,
		CertificateChallenge: request.CertificateChallenge, CreatedAt: timestamptz(now),
		LastHeartbeatAt: timestamptz(now), PublisherExpiresAt: timestamptz(now.Add(publisherLeaseDuration)),
	})
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: insert session: %w", err)
	}

	connectionRows := make([]controlstatedb.ControlRouteSessionConnection, 0, routeSessionConnectionCount)
	for slot, placement := range placements {
		publisherConnectionID, err := opaqueid.New("connection_")
		if err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: generate publisher connection ID: %w", err)
		}
		credential, credentialHash, err := credentials.DerivePublisherConnectionCredential(
			routeSessionToken, publisherConnectionCredentialContext(publisherConnectionID, 1),
		)
		if err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: derive publisher connection credential: %w", err)
		}
		row, err := queries.InsertRouteSessionConnection(ctx, controlstatedb.InsertRouteSessionConnectionParams{
			RouteSessionID: routeSessionID, RouteID: request.RouteID, RouteVersion: routeVersion,
			ConnectionSlot: int16(slot), PublisherConnectionID: publisherConnectionID,
			RelayServiceID: placement.relayServiceID, RelayAddress: placement.relayAddress,
			TlsServerName: placement.tlsServerName, PublisherConnectionCredentialDigest: credentialHash[:],
			PublisherConnectionCredentialExpiresAt: timestamptz(now.Add(connectionCredentialDuration)),
			AssignedAt:                             timestamptz(now),
		})
		if err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: insert connection slot %d: %w", slot, err)
		}
		if _, err := connectionAssignment(row, credential); err != nil {
			return RouteSessionSetup{}, err
		}
		connectionRows = append(connectionRows, row)
	}
	if err := queries.InsertRouteSessionAuditEvent(ctx, controlstatedb.InsertRouteSessionAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), Actor: request.ActingIdentityID,
		RequestID: request.IdempotencyKey, RouteSessionID: routeSessionID, OccurredAt: timestamptz(now),
	}); err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return RouteSessionSetup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: create route session: commit: %w", err)
	}
	return routeSessionSetup(session, routeSessionToken, connectionRows)
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
) ([routeSessionConnectionCount]relayServicePlacement, error) {
	services, _, err := availableRelayServicePlacements(ctx, queries, now)
	if err != nil {
		return [routeSessionConnectionCount]relayServicePlacement{}, fmt.Errorf("controlstate: create route session: %w", err)
	}
	var result [routeSessionConnectionCount]relayServicePlacement
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
	return result, ErrInsufficientRelayServices
}

func availableRelayServicePlacements(
	ctx context.Context,
	queries *controlstatedb.Queries,
	now time.Time,
) ([]relayServicePlacement, []controlstatedb.LockEligibleRelayLeasesRow, error) {
	// Registration also locks the service before its lease. Hold all service
	// locks before taking any lease locks or counting capacity reservations.
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
	counts, err := queries.CountOpenRouteSessionAssignmentsByRelayService(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("count relay-service assignments: %w", err)
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

func authenticateRouteSessionRequest(route controlstatedb.ControlRoute, request RouteSessionRequest) error {
	if route.TeamID != request.TeamID || route.PolicyRevision > positive(request.PolicyRevision) {
		return ErrRouteAuthority
	}
	return nil
}

func loadRouteSessionSetup(
	ctx context.Context,
	queries *controlstatedb.Queries,
	retrySecret []byte,
	retryContext string,
	session controlstatedb.ControlRouteSession,
) (RouteSessionSetup, error) {
	token, tokenID, tokenHash, err := credentials.DeriveRouteSessionToken(retrySecret, retryContext)
	if err != nil || tokenID.String() != session.SessionTokenID ||
		!credentials.SecretHashMatches(session.SessionTokenDigest, tokenHash) {
		return RouteSessionSetup{}, ErrRouteCredential
	}
	return loadRouteSessionSetupWithToken(ctx, queries, token, session)
}

func loadRouteSessionSetupWithToken(
	ctx context.Context,
	queries *controlstatedb.Queries,
	token credentials.RouteSessionToken,
	session controlstatedb.ControlRouteSession,
) (RouteSessionSetup, error) {
	connections, err := queries.ListRouteSessionConnections(ctx, session.ID)
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: load route session connections: %w", err)
	}
	return routeSessionSetup(session, token, connections)
}

func routeSessionSetup(
	session controlstatedb.ControlRouteSession,
	token credentials.RouteSessionToken,
	connections []controlstatedb.ControlRouteSessionConnection,
) (RouteSessionSetup, error) {
	if session.RouteVersion <= 0 || !session.CreatedAt.Valid || !session.PublisherExpiresAt.Valid ||
		len(connections) != routeSessionConnectionCount {
		return RouteSessionSetup{}, errors.New("controlstate: invalid route session row")
	}
	setup := RouteSessionSetup{
		RouteSessionID: session.ID, RouteID: session.RouteID, TeamID: session.TeamID,
		MembershipID: session.MembershipID.String, RouteVersion: uint64(session.RouteVersion),
		PolicyRevision: uint64(session.PolicyRevision), RouteSessionToken: token, State: RouteSessionState(session.State),
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
	seen := [routeSessionConnectionCount]bool{}
	for _, row := range connections {
		if row.ConnectionSlot < 0 || int(row.ConnectionSlot) >= routeSessionConnectionCount || seen[row.ConnectionSlot] {
			return RouteSessionSetup{}, errors.New("controlstate: invalid route-session connection slots")
		}
		credential, hash, err := credentials.DerivePublisherConnectionCredential(
			token, publisherConnectionCredentialContext(row.PublisherConnectionID, row.ConnectionAssignmentRevision),
		)
		if err != nil || !credentials.SecretHashMatches(row.PublisherConnectionCredentialDigest, hash) {
			return RouteSessionSetup{}, errors.New("controlstate: invalid publisher connection credential")
		}
		assignment, err := connectionAssignment(row, credential)
		if err != nil {
			return RouteSessionSetup{}, err
		}
		setup.PublisherConnections[row.ConnectionSlot] = assignment
		seen[row.ConnectionSlot] = true
	}
	return setup, nil
}

func connectionAssignment(
	row controlstatedb.ControlRouteSessionConnection,
	credential credentials.PublisherConnectionCredential,
) (ConnectionAssignment, error) {
	if row.RouteVersion <= 0 || row.ConnectionAssignmentRevision <= 0 || row.ConnectionSlot < 0 ||
		row.ConnectionSlot >= routeSessionConnectionCount || !row.PublisherConnectionCredentialExpiresAt.Valid {
		return ConnectionAssignment{}, errors.New("controlstate: invalid route-session connection row")
	}
	return ConnectionAssignment{
		ConnectionAssignmentIdentity: ConnectionAssignmentIdentity{
			RouteSessionID: row.RouteSessionID, RouteID: row.RouteID, RouteVersion: uint64(row.RouteVersion),
			ConnectionSlot: int(row.ConnectionSlot), PublisherConnectionID: row.PublisherConnectionID,
			ConnectionAssignmentRevision: uint64(row.ConnectionAssignmentRevision), RelayServiceID: row.RelayServiceID,
		},
		RelayAddress: row.RelayAddress, TLSServerName: row.TlsServerName,
		PublisherConnectionCredential:          credential,
		PublisherConnectionCredentialExpiresAt: row.PublisherConnectionCredentialExpiresAt.Time,
		State:                                  PublisherConnectionState(row.State),
	}, nil
}

func validateRouteSessionRequest(
	request RouteSessionRequest,
	publisherLeaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) error {
	for _, value := range []string{
		request.RouteID, request.TeamID, request.ActingIdentityID, request.IdempotencyKey,
		request.CertificateCacheKey, request.CertificateScope, request.CertificateChallenge,
	} {
		if !validStateText(value) {
			return errors.New("controlstate: route-session request is invalid")
		}
	}
	if request.MembershipID != "" && !validStateText(request.MembershipID) {
		return errors.New("controlstate: route-session membership ID is invalid")
	}
	if request.AuthorityIssuer != "" && !validStateText(request.AuthorityIssuer) {
		return errors.New("controlstate: route-session authority issuer is invalid")
	}
	if len(request.RetrySecret) < 32 {
		return ErrRouteCredential
	}
	if _, ok := positiveInt64(request.PolicyRevision); !ok {
		return errors.New("controlstate: route-session policy revision must be positive")
	}
	identifiers, err := canonicalCertificateIdentifiers(request.CertificateIdentifiers)
	if err != nil || !slices.Equal(identifiers, request.CertificateIdentifiers) {
		return errors.New("controlstate: route-session certificate identifiers must be a canonical sorted set")
	}
	if request.CertificateChallenge != "dns-01" && request.CertificateChallenge != "tls-alpn-01" {
		return errors.New("controlstate: route-session certificate challenge is invalid")
	}
	if request.CertificateChallenge == "tls-alpn-01" && slices.ContainsFunc(identifiers, func(identifier string) bool {
		return strings.HasPrefix(identifier, "*.")
	}) {
		return errors.New("controlstate: TLS-ALPN-01 does not support wildcard identifiers")
	}
	if request.ExpectedMutationRevision == 0 || request.ExpectedMutationRevision > math.MaxInt64 {
		return errors.New("controlstate: route-session mutation revision must be positive")
	}
	if publisherLeaseDuration <= 0 || connectionCredentialDuration <= 0 {
		return errors.New("controlstate: route-session durations must be positive")
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
