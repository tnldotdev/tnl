package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

func (s *Store) CurrentSignedRouteID(ctx context.Context, hostname string) (string, error) {
	hostname, err := s.canonicalRouteHostname(hostname)
	if err != nil {
		return "", err
	}
	routeID, err := s.queries.GetCurrentSignedRouteIDByHostname(ctx, hostname)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("routes: find current signed route: %w", err)
	}
	return routeID, nil
}

func (s *Store) CreateSigned(
	ctx context.Context,
	hostname, localTarget, serverInstanceID string,
	routeToken credentials.RouteToken,
	request SignedRequest,
) (provisioning Provisioning, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationRouteCreate, started, err) }()
	if s.authorizationVerifier == nil {
		return Provisioning{}, ErrInvalidArgument
	}
	if serverInstanceID == "" {
		return Provisioning{}, ErrInvalidArgument
	}
	validated, err := s.validateSignedCreate(hostname, localTarget, routeToken, request)
	if err != nil {
		return Provisioning{}, err
	}
	hostname, prefixes, claims := validated.hostname, validated.prefixes, validated.claims
	routeCredentialID, routeHash, err := credentials.ParseRouteToken(routeToken)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	sessionToken, sessionTokenID, sessionHash, err := credentials.DeriveSessionToken(
		routeToken, claims.Issuer+"\x00"+claims.RetryID,
	)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	if !claims.ExpiresAt.After(now) {
		return Provisioning{}, ErrUnauthenticated
	}
	routeID, err := newID("route")
	if err != nil {
		return Provisioning{}, err
	}
	sessionID, err := newID("session")
	if err != nil {
		return Provisioning{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: begin signed create: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	if replay, found, err := s.signedReplay(
		ctx, queries, claims, routeToken, sessionToken, serverInstanceID, prefixes, now,
	); err != nil || found {
		return replay, err
	}
	maxAuthorizationRevision, err := queries.GetMaxSignedRouteAuthorizationRevision(
		ctx, statedb.GetMaxSignedRouteAuthorizationRevisionParams{
			AuthorizationIssuer: claims.Issuer,
			Hostname:            hostname,
		},
	)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: read signed authorization revision floor: %w", err)
	}
	if int64(claims.Revision) < maxAuthorizationRevision {
		return Provisioning{}, ErrAuthorizationReplayed
	}

	routeVersion := uint64(1)
	existingRoute, err := queries.GetCurrentRouteByHostname(ctx, hostname)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Provisioning{}, fmt.Errorf("routes: check existing signed route: %w", err)
	}
	if err == nil {
		existing := routeFromDB(existingRoute)
		if existing.Status != RouteStatusEnabled {
			return Provisioning{}, ErrInvalidStatus
		}
		if existing.AuthorizationID == "" {
			return Provisioning{}, ErrRouteExists
		}
		routeVersion = existing.RouteVersion + 1
		if routeVersion > math.MaxInt32 {
			return Provisioning{}, ErrInvalidStatus
		}
		if err := s.recordLifecycle(ctx, queries, existing.ID, existing.RouteVersion, now, LifecycleDisconnected); err != nil {
			return Provisioning{}, err
		}
		count, err := queries.RotateRouteCredential(ctx, statedb.RotateRouteCredentialParams{
			CredentialID: routeCredentialID.String(), SecretHash: routeHash[:],
			CreatedAt: now.UnixNano(), RouteID: existing.ID,
		})
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: rotate signed route credential: %w", err)
		}
		if err := requireCount(count, ErrInvalidStatus); err != nil {
			return Provisioning{}, err
		}
		if err := queries.ExpireRouteSessions(ctx, existing.ID); err != nil {
			return Provisioning{}, fmt.Errorf("routes: expire replaced signed session: %w", err)
		}
		count, err = queries.ReplaceSignedRoute(ctx, signedReplacementParams(existing.ID, localTarget, routeVersion, claims))
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: replace signed route: %w", err)
		}
		if err := requireCount(count, ErrInvalidStatus); err != nil {
			return Provisioning{}, err
		}
		routeID = existing.ID
	} else {
		if err := queries.InsertSignedRoute(ctx, signedInsertParams(routeID, hostname, localTarget, now, claims)); err != nil {
			return Provisioning{}, fmt.Errorf("routes: create signed route: %w", err)
		}
		if s.lifecycleRecorder != nil {
			registrationID, err := newID("registration")
			if err != nil {
				return Provisioning{}, err
			}
			if err := s.recordRegistration(ctx, queries, RouteRegistration{
				RegistrationID:  registrationID,
				RouteID:         routeID,
				Hostname:        hostname,
				SigningKeyID:    claims.KeyID,
				AuthorizationID: claims.AuthorizationID,
				CreatedAt:       now,
				RetryID:         claims.RetryID,
			}); err != nil {
				return Provisioning{}, err
			}
		}
		if err := queries.InsertRouteCredential(ctx, statedb.InsertRouteCredentialParams{
			CredentialID: routeCredentialID.String(), RouteID: routeID,
			SecretHash: routeHash[:], CreatedAt: now.UnixNano(),
		}); err != nil {
			return Provisioning{}, fmt.Errorf("routes: create signed route credential: %w", err)
		}
	}
	if err := insertAllowedIPPrefixes(ctx, queries, routeID, routeVersion, prefixes); err != nil {
		return Provisioning{}, err
	}
	expiresAt := minTime(now.Add(s.sessionLifetime), claims.ExpiresAt)
	dbRouteVersion, _ := routeVersionToInt64(routeVersion)
	if err := queries.InsertRouteSession(ctx, statedb.InsertRouteSessionParams{
		SessionID: sessionID, RouteID: routeID, RouteVersion: dbRouteVersion,
		TokenID: sessionTokenID.String(), SecretHash: sessionHash[:], ServerInstanceID: serverInstanceID,
		CreatedAt: now.UnixNano(), ExpiresAt: expiresAt.UnixNano(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create signed session: %w", err)
	}
	if err := insertAuthorizationUse(ctx, queries, claims, routeID, routeVersion, now); err != nil {
		return Provisioning{}, err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, routeVersion, now, LifecycleRouteVersionStarted); err != nil {
		return Provisioning{}, err
	}
	if err := tx.Commit(); err != nil {
		return Provisioning{}, fmt.Errorf("routes: commit signed create: %w", err)
	}
	route := routeFromClaims(routeID, hostname, localTarget, routeVersion, now, claims, prefixes)
	return Provisioning{
		Route: route,
		Session: Session{
			ID: sessionID, RouteID: routeID, RouteVersion: routeVersion, Status: SessionStatusPending,
			ServerInstanceID: serverInstanceID, CreatedAt: now, LastHeartbeatAt: now, ExpiresAt: expiresAt,
		},
		SessionToken: sessionToken,
	}, nil
}

type signedCreateValidation struct {
	hostname string
	prefixes []string
	claims   authorization.Claims
}

func (s *Store) validateSignedCreate(
	hostname, localTarget string,
	routeToken credentials.RouteToken,
	request SignedRequest,
) (signedCreateValidation, error) {
	if s.authorizationVerifier == nil || localTarget == "" {
		return signedCreateValidation{}, ErrInvalidArgument
	}
	hostname, err := s.canonicalRouteHostname(hostname)
	if err != nil {
		return signedCreateValidation{}, ErrInvalidArgument
	}
	prefixes, requestHash, ipPolicyHash, err := canonicalSignedRequest(
		authorization.OperationRouteCreate, hostname, localTarget, routeToken, 0, request,
	)
	if err != nil {
		return signedCreateValidation{}, err
	}
	claims, err := s.authorizationVerifier.Verify(request.Token, authorization.Expected{
		Operation: authorization.OperationRouteCreate, Hostname: hostname,
		CanonicalRequestHash: requestHash, IPPolicyHash: ipPolicyHash,
	})
	if err != nil {
		return signedCreateValidation{}, ErrUnauthenticated
	}
	return signedCreateValidation{hostname: hostname, prefixes: prefixes, claims: claims}, nil
}

func (s *Store) CreateSignedSession(
	ctx context.Context,
	routeID, serverInstanceID string,
	routeToken credentials.RouteToken,
	request SignedRequest,
) (provisioning Provisioning, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationSessionCreate, started, err) }()
	if s.authorizationVerifier == nil || routeID == "" || serverInstanceID == "" {
		return Provisioning{}, ErrInvalidArgument
	}
	claims, err := s.authorizationVerifier.Authenticate(request.Token)
	if err != nil || claims.Operation != authorization.OperationRouteSessionCreate || claims.RouteID != routeID {
		return Provisioning{}, ErrUnauthenticated
	}
	prefixes, requestHash, ipPolicyHash, err := canonicalSignedRequest(
		authorization.OperationRouteSessionCreate, claims.Hostname, "", routeToken, 0, request,
	)
	if err != nil {
		return Provisioning{}, err
	}
	credentialID, candidate, err := credentials.ParseRouteToken(routeToken)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	sessionToken, sessionTokenID, sessionHash, err := credentials.DeriveSessionToken(
		routeToken, claims.Issuer+"\x00"+claims.RetryID,
	)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	if !claims.ExpiresAt.After(now) {
		return Provisioning{}, ErrUnauthenticated
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: begin signed session creation: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	route, storedHash, revoked, err := readRouteCredential(ctx, queries, routeID, credentialID)
	if err != nil {
		return Provisioning{}, err
	}
	if revoked || !credentials.SecretHashMatches(storedHash, candidate) {
		return Provisioning{}, ErrUnauthenticated
	}
	if route.Status != RouteStatusEnabled || route.AuthorizationID == "" || !route.AuthorizationExpiresAt.After(now) {
		return Provisioning{}, ErrInvalidStatus
	}
	if claims.Revision < route.AuthorizationRevision {
		return Provisioning{}, ErrAuthorizationReuseRejected
	}
	if claims.RouteVersion == route.RouteVersion {
		if err := claims.Validate(authorization.Expected{
			Operation: authorization.OperationRouteSessionCreate, Hostname: route.Hostname,
			RouteID: route.ID, RouteVersion: route.RouteVersion,
			CanonicalRequestHash: requestHash, IPPolicyHash: ipPolicyHash,
		}); err != nil {
			return Provisioning{}, ErrUnauthenticated
		}
		if replay, found, err := s.signedReplay(
			ctx, queries, claims, routeToken, sessionToken, serverInstanceID, prefixes, now,
		); err != nil || found {
			return replay, err
		}
		return Provisioning{}, ErrAuthorizationReuseRejected
	}
	nextRouteVersion := route.RouteVersion + 1
	if nextRouteVersion > math.MaxInt32 || claims.Validate(authorization.Expected{
		Operation: authorization.OperationRouteSessionCreate, Hostname: route.Hostname,
		RouteID: route.ID, RouteVersion: nextRouteVersion,
		CanonicalRequestHash: requestHash, IPPolicyHash: ipPolicyHash,
	}) != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	if _, found, err := s.signedReplay(
		ctx, queries, claims, routeToken, sessionToken, serverInstanceID, prefixes, now,
	); err != nil || found {
		if err == nil {
			err = ErrAuthorizationReuseRejected
		}
		return Provisioning{}, err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, route.RouteVersion, now, LifecycleDisconnected); err != nil {
		return Provisioning{}, err
	}
	if err := queries.ExpireRouteSessions(ctx, routeID); err != nil {
		return Provisioning{}, fmt.Errorf("routes: expire previous signed session: %w", err)
	}
	dbRouteVersion, _ := routeVersionToInt64(nextRouteVersion)
	count, err := queries.AdvanceSignedRouteVersion(ctx, signedAdvanceParams(route, dbRouteVersion, now, claims))
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: advance signed route: %w", err)
	}
	if err := requireCount(count, ErrInvalidStatus); err != nil {
		return Provisioning{}, err
	}
	if err := insertAllowedIPPrefixes(ctx, queries, routeID, nextRouteVersion, prefixes); err != nil {
		return Provisioning{}, err
	}
	sessionID, err := newID("session")
	if err != nil {
		return Provisioning{}, err
	}
	expiresAt := minTime(now.Add(s.sessionLifetime), claims.ExpiresAt)
	if err := queries.InsertRouteSession(ctx, statedb.InsertRouteSessionParams{
		SessionID: sessionID, RouteID: routeID, RouteVersion: dbRouteVersion,
		TokenID: sessionTokenID.String(), SecretHash: sessionHash[:], ServerInstanceID: serverInstanceID,
		CreatedAt: now.UnixNano(), ExpiresAt: expiresAt.UnixNano(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create replacement signed session: %w", err)
	}
	if err := insertAuthorizationUse(ctx, queries, claims, routeID, nextRouteVersion, now); err != nil {
		return Provisioning{}, err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, nextRouteVersion, now, LifecycleRouteVersionStarted); err != nil {
		return Provisioning{}, err
	}
	if err := tx.Commit(); err != nil {
		return Provisioning{}, fmt.Errorf("routes: commit signed session creation: %w", err)
	}
	route = routeFromClaims(route.ID, route.Hostname, route.LocalTarget, nextRouteVersion, route.CreatedAt, claims, prefixes)
	return Provisioning{
		Route: route,
		Session: Session{
			ID: sessionID, RouteID: routeID, RouteVersion: nextRouteVersion, Status: SessionStatusPending,
			ServerInstanceID: serverInstanceID, CreatedAt: now, LastHeartbeatAt: now, ExpiresAt: expiresAt,
		},
		SessionToken: sessionToken,
	}, nil
}

func (s *Store) HeartbeatSigned(
	ctx context.Context,
	session Session,
	signedAuthorization string,
	requestHash authorization.Digest,
) (expiresAt time.Time, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationSessionHeartbeat, started, err) }()
	if s.authorizationVerifier == nil {
		return time.Time{}, ErrInvalidArgument
	}
	wantHash, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRenew, RouteVersion: session.RouteVersion,
	})
	if err != nil || wantHash != requestHash {
		return time.Time{}, ErrInvalidArgument
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	dbRouteVersion, err := routeVersionToInt64(session.RouteVersion)
	if err != nil {
		return time.Time{}, ErrInvalidArgument
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: begin signed heartbeat: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	dbRoute, err := queries.GetRouteByID(ctx, session.RouteID)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrStaleSession
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: read signed heartbeat route: %w", err)
	}
	route := routeFromDB(dbRoute)
	if route.Status != RouteStatusEnabled || route.RouteVersion != session.RouteVersion || route.AuthorizationID == "" ||
		signedAuthorization == "" && !route.AuthorizationExpiresAt.After(now) {
		return time.Time{}, ErrStaleSession
	}
	authorizationExpiresAt := route.AuthorizationExpiresAt
	if signedAuthorization != "" {
		claims, err := s.authorizationVerifier.Verify(signedAuthorization, authorization.Expected{
			Operation: authorization.OperationRenew, Hostname: route.Hostname,
			RouteID: route.ID, RouteVersion: route.RouteVersion,
			CanonicalRequestHash: requestHash, IPPolicyHash: route.AuthorizationIPPolicyHash,
		})
		if err != nil {
			return time.Time{}, ErrUnauthenticated
		}
		if claims.Issuer != route.AuthorizationIssuer || claims.KeyID != route.AuthorizationKeyID ||
			claims.Revision < route.AuthorizationRevision || !claims.ExpiresAt.After(route.AuthorizationExpiresAt) {
			return time.Time{}, ErrAuthorizationReuseRejected
		}
		if err := requireUnusedAuthorization(ctx, queries, claims); err != nil {
			return time.Time{}, err
		}
		count, err := queries.RenewRouteAuthorization(ctx, statedb.RenewRouteAuthorizationParams{
			NextIssuer:          sql.NullString{String: claims.Issuer, Valid: true},
			NextAuthorizationID: sql.NullString{String: claims.AuthorizationID, Valid: true},
			NextKeyID:           sql.NullString{String: claims.KeyID, Valid: true},
			NextRetryID:         sql.NullString{String: claims.RetryID, Valid: true},
			NextRevision:        sql.NullInt64{Int64: int64(claims.Revision), Valid: true},
			NextExpiresAt:       sql.NullInt64{Int64: claims.ExpiresAt.UnixNano(), Valid: true},
			NextRequestHash:     claims.CanonicalRequestHash[:],
			NextIpPolicyHash:    optionalDigestBytes(claims.IPPolicyHash),
			RouteID:             route.ID,
			PreviousIssuer:      sql.NullString{String: route.AuthorizationIssuer, Valid: true},
			PreviousAuthorizationID: sql.NullString{
				String: route.AuthorizationID, Valid: true,
			},
			PreviousKeyID:     sql.NullString{String: route.AuthorizationKeyID, Valid: true},
			PreviousRetryID:   sql.NullString{String: route.AuthorizationRetryID, Valid: true},
			PreviousRevision:  sql.NullInt64{Int64: int64(route.AuthorizationRevision), Valid: true},
			PreviousExpiresAt: sql.NullInt64{Int64: route.AuthorizationExpiresAt.UnixNano(), Valid: true},
		})
		if err != nil {
			return time.Time{}, fmt.Errorf("routes: renew authorization: %w", err)
		}
		if err := requireCount(count, ErrAuthorizationReuseRejected); err != nil {
			return time.Time{}, err
		}
		if err := insertAuthorizationUse(ctx, queries, claims, route.ID, route.RouteVersion, now); err != nil {
			return time.Time{}, err
		}
		authorizationExpiresAt = claims.ExpiresAt
	}
	expiresAt = minTime(now.Add(s.sessionLifetime), authorizationExpiresAt)
	var count int64
	if signedAuthorization == "" {
		count, err = queries.HeartbeatRouteSession(ctx, statedb.HeartbeatRouteSessionParams{
			LastHeartbeatAt: now.UnixNano(), ExpiresAt: expiresAt.UnixNano(),
			SessionID: session.ID, RouteID: session.RouteID, RouteVersion: dbRouteVersion, Now: now.UnixNano(),
		})
	} else {
		count, err = queries.HeartbeatRenewedRouteSession(ctx, statedb.HeartbeatRenewedRouteSessionParams{
			LastHeartbeatAt: now.UnixNano(), ExpiresAt: expiresAt.UnixNano(),
			SessionID: session.ID, RouteID: session.RouteID, RouteVersion: dbRouteVersion,
			Now: sql.NullInt64{Int64: now.UnixNano(), Valid: true},
		})
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: signed heartbeat: %w", err)
	}
	if err := requireCount(count, ErrStaleSession); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("routes: commit signed heartbeat: %w", err)
	}
	return expiresAt, nil
}

// DeleteSigned authenticates one exact signed route with its route credential
// and records deletion in the same transaction as credential revocation.
func (s *Store) DeleteSigned(ctx context.Context, routeID string, token credentials.RouteToken) error {
	credentialID, candidate, err := credentials.ParseRouteToken(token)
	if err != nil {
		return ErrUnauthenticated
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin signed delete: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	route, storedHash, revoked, err := readRouteCredential(ctx, queries, routeID, credentialID)
	if err != nil {
		return err
	}
	if route.AuthorizationID == "" || revoked || !credentials.SecretHashMatches(storedHash, candidate) {
		return ErrUnauthenticated
	}
	if route.Status != RouteStatusEnabled {
		return ErrNotFound
	}
	count, err := queries.DeleteEnabledSignedRoute(ctx, statedb.DeleteEnabledSignedRouteParams{
		DeletedAt: now.UnixNano(), RouteID: routeID,
	})
	if err != nil {
		return fmt.Errorf("routes: delete signed route: %w", err)
	}
	if err := requireCount(count, ErrNotFound); err != nil {
		return err
	}
	if err := queries.RevokeRouteCredential(ctx, statedb.RevokeRouteCredentialParams{
		RevokedAt: now.UnixNano(), RouteID: routeID,
	}); err != nil {
		return fmt.Errorf("routes: revoke signed route credential: %w", err)
	}
	if err := queries.ExpireRouteSessions(ctx, routeID); err != nil {
		return fmt.Errorf("routes: expire deleted signed route: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, route.RouteVersion, now, LifecycleDisconnected); err != nil {
		return err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, route.RouteVersion, now, LifecycleDeleted); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit signed delete: %w", err)
	}
	return nil
}

func canonicalSignedRequest(
	operation authorization.Operation,
	hostname, localTarget string,
	routeToken credentials.RouteToken,
	routeVersion uint64,
	request SignedRequest,
) ([]string, authorization.Digest, *authorization.Digest, error) {
	prefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil || (request.AllowedIPPrefixes == nil) != (prefixes == nil) ||
		!slices.Equal(prefixes, request.AllowedIPPrefixes) {
		return nil, authorization.Digest{}, nil, ErrInvalidArgument
	}
	requestHash, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: operation, Hostname: hostname, LocalTarget: localTarget,
		RouteToken: routeToken.String(), AllowedIPPrefixes: prefixes, RouteVersion: routeVersion,
	})
	if err != nil || requestHash != request.RequestHash {
		return nil, authorization.Digest{}, nil, ErrInvalidArgument
	}
	ipPolicyHash, err := authorization.IPPolicyHash(prefixes)
	if err != nil || !equalOptionalDigest(ipPolicyHash, request.IPPolicyHash) {
		return nil, authorization.Digest{}, nil, ErrInvalidArgument
	}
	return prefixes, requestHash, ipPolicyHash, nil
}

func (s *Store) signedReplay(
	ctx context.Context,
	queries *statedb.Queries,
	claims authorization.Claims,
	routeToken credentials.RouteToken,
	sessionToken credentials.SessionToken,
	serverInstanceID string,
	prefixes []string,
	now time.Time,
) (Provisioning, bool, error) {
	use, err := queries.GetRouteAuthorizationUseByRetry(ctx, statedb.GetRouteAuthorizationUseByRetryParams{
		AuthorizationIssuer: claims.Issuer, AuthorizationRetryID: claims.RetryID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		_, idErr := queries.GetRouteAuthorizationUseByID(ctx, statedb.GetRouteAuthorizationUseByIDParams{
			AuthorizationIssuer: claims.Issuer, AuthorizationID: claims.AuthorizationID,
		})
		if errors.Is(idErr, sql.ErrNoRows) {
			return Provisioning{}, false, nil
		}
		if idErr != nil {
			return Provisioning{}, false, fmt.Errorf("routes: check authorization replay: %w", idErr)
		}
		return Provisioning{}, false, ErrAuthorizationReuseRejected
	}
	if err != nil {
		return Provisioning{}, false, fmt.Errorf("routes: check authorization retry: %w", err)
	}
	if !authorizationUseMatches(use, claims) {
		return Provisioning{}, false, ErrAuthorizationReuseRejected
	}
	dbRoute, err := queries.GetRouteByID(ctx, use.RouteID)
	if err != nil {
		return Provisioning{}, false, ErrAuthorizationReuseRejected
	}
	route := routeFromDB(dbRoute)
	if route.Status != RouteStatusEnabled || route.RouteVersion != uint64(use.RouteVersion) ||
		!routeAuthorizationMatches(route, claims) || !route.AuthorizationExpiresAt.After(now) {
		return Provisioning{}, false, ErrAuthorizationReuseRejected
	}
	credentialID, candidate, err := credentials.ParseRouteToken(routeToken)
	if err != nil {
		return Provisioning{}, false, ErrUnauthenticated
	}
	_, storedHash, revoked, err := readRouteCredential(ctx, queries, route.ID, credentialID)
	if err != nil || revoked || !credentials.SecretHashMatches(storedHash, candidate) {
		return Provisioning{}, false, ErrUnauthenticated
	}
	dbSession, err := queries.GetRouteSessionByVersion(ctx, statedb.GetRouteSessionByVersionParams{
		RouteID: route.ID, RouteVersion: use.RouteVersion,
	})
	if err != nil {
		return Provisioning{}, false, ErrAuthorizationReuseRejected
	}
	tokenID, tokenHash, err := credentials.ParseSessionToken(sessionToken)
	if err != nil || dbSession.TokenID != tokenID.String() || !credentials.SecretHashMatches(dbSession.SecretHash, tokenHash) {
		return Provisioning{}, false, ErrAuthorizationReuseRejected
	}
	storedPrefixes, err := queries.ListRouteAllowedIPPrefixes(ctx, statedb.ListRouteAllowedIPPrefixesParams{
		RouteID: route.ID, RouteVersion: int64(route.RouteVersion),
	})
	if err != nil || !slices.Equal(storedPrefixes, prefixes) {
		return Provisioning{}, false, ErrAuthorizationReuseRejected
	}
	restored := dbSession.ServerInstanceID != serverInstanceID || SessionStatus(dbSession.Status) == SessionStatusExpired ||
		dbSession.ExpiresAt <= now.UnixNano()
	if restored {
		expiresAt := minTime(now.Add(s.sessionLifetime), route.AuthorizationExpiresAt)
		count, err := queries.RestoreSignedRouteSessionRetry(ctx, statedb.RestoreSignedRouteSessionRetryParams{
			ServerInstanceID: serverInstanceID, Now: now.UnixNano(), ExpiresAt: expiresAt.UnixNano(),
			SessionID: dbSession.ID, RouteID: route.ID, RouteVersion: use.RouteVersion, TokenID: tokenID.String(),
		})
		if err != nil {
			return Provisioning{}, false, fmt.Errorf("routes: restore authorization retry session: %w", err)
		}
		if err := requireCount(count, ErrAuthorizationReuseRejected); err != nil {
			return Provisioning{}, false, err
		}
		dbSession.Status = string(SessionStatusPending)
		dbSession.ServerInstanceID = serverInstanceID
		dbSession.PublisherPublicKey = sql.NullString{}
		dbSession.RelayRegion = sql.NullString{}
		dbSession.LastHeartbeatAt = now.UnixNano()
		dbSession.ExpiresAt = expiresAt.UnixNano()
	}
	route.AllowedIPPrefixes = storedPrefixes
	return Provisioning{
		Route: route, Session: sessionFromDB(dbSession), SessionToken: sessionToken, ReusedResult: true, Restored: restored,
	}, true, nil
}

func authorizationUseMatches(use statedb.RouteAuthorizationUse, claims authorization.Claims) bool {
	return use.AuthorizationIssuer == claims.Issuer && use.AuthorizationID == claims.AuthorizationID &&
		use.AuthorizationKeyID == claims.KeyID && use.AuthorizationRetryID == claims.RetryID &&
		use.AuthorizationRevision == int64(claims.Revision) &&
		use.AuthorizationExpiresAt == claims.ExpiresAt.UnixNano() && use.Operation == string(claims.Operation) &&
		use.Hostname == claims.Hostname && slices.Equal(use.RequestHash, claims.CanonicalRequestHash[:]) &&
		equalOptionalBytes(use.IpPolicyHash, claims.IPPolicyHash)
}

func routeAuthorizationMatches(route Route, claims authorization.Claims) bool {
	return route.AuthorizationIssuer == claims.Issuer && route.AuthorizationID == claims.AuthorizationID &&
		route.AuthorizationKeyID == claims.KeyID && route.AuthorizationRetryID == claims.RetryID &&
		route.AuthorizationRevision == claims.Revision && route.AuthorizationExpiresAt.Equal(claims.ExpiresAt) &&
		route.AuthorizationRequestHash == claims.CanonicalRequestHash &&
		equalOptionalDigest(route.AuthorizationIPPolicyHash, claims.IPPolicyHash)
}

func insertAuthorizationUse(
	ctx context.Context,
	queries *statedb.Queries,
	claims authorization.Claims,
	routeID string,
	routeVersion uint64,
	now time.Time,
) error {
	var ipPolicyHash []byte
	if claims.IPPolicyHash != nil {
		ipPolicyHash = claims.IPPolicyHash[:]
	}
	if err := queries.InsertRouteAuthorizationUse(ctx, statedb.InsertRouteAuthorizationUseParams{
		AuthorizationIssuer: claims.Issuer, AuthorizationID: claims.AuthorizationID,
		AuthorizationKeyID: claims.KeyID, AuthorizationRetryID: claims.RetryID,
		AuthorizationRevision: int64(claims.Revision), AuthorizationExpiresAt: claims.ExpiresAt.UnixNano(),
		Operation: string(claims.Operation), RouteID: routeID, RouteVersion: int64(routeVersion),
		Hostname: claims.Hostname, RequestHash: claims.CanonicalRequestHash[:],
		IpPolicyHash: ipPolicyHash, CreatedAt: now.UnixNano(),
	}); err != nil {
		return fmt.Errorf("routes: consume authorization: %w", err)
	}
	return nil
}

func requireUnusedAuthorization(
	ctx context.Context,
	queries *statedb.Queries,
	claims authorization.Claims,
) error {
	if _, err := queries.GetRouteAuthorizationUseByID(ctx, statedb.GetRouteAuthorizationUseByIDParams{
		AuthorizationIssuer: claims.Issuer, AuthorizationID: claims.AuthorizationID,
	}); !errors.Is(err, sql.ErrNoRows) {
		if err != nil {
			return fmt.Errorf("routes: check authorization ID: %w", err)
		}
		return ErrAuthorizationReuseRejected
	}
	if _, err := queries.GetRouteAuthorizationUseByRetry(ctx, statedb.GetRouteAuthorizationUseByRetryParams{
		AuthorizationIssuer: claims.Issuer, AuthorizationRetryID: claims.RetryID,
	}); !errors.Is(err, sql.ErrNoRows) {
		if err != nil {
			return fmt.Errorf("routes: check authorization retry ID: %w", err)
		}
		return ErrAuthorizationReuseRejected
	}
	return nil
}

func insertAllowedIPPrefixes(
	ctx context.Context,
	queries *statedb.Queries,
	routeID string,
	routeVersion uint64,
	prefixes []string,
) error {
	dbRouteVersion, err := routeVersionToInt64(routeVersion)
	if err != nil {
		return ErrInvalidArgument
	}
	for position, prefix := range prefixes {
		if err := queries.InsertRouteAllowedIPPrefix(ctx, statedb.InsertRouteAllowedIPPrefixParams{
			RouteID: routeID, RouteVersion: dbRouteVersion, Position: int64(position), Prefix: prefix,
		}); err != nil {
			return fmt.Errorf("routes: store allowed IP prefix: %w", err)
		}
	}
	return nil
}

func signedInsertParams(
	routeID, hostname, localTarget string,
	now time.Time,
	claims authorization.Claims,
) statedb.InsertSignedRouteParams {
	return statedb.InsertSignedRouteParams{
		RouteID: routeID, Hostname: hostname, LocalTarget: localTarget,
		AuthorizationIssuer:       sql.NullString{String: claims.Issuer, Valid: true},
		AuthorizationID:           sql.NullString{String: claims.AuthorizationID, Valid: true},
		AuthorizationKeyID:        sql.NullString{String: claims.KeyID, Valid: true},
		AuthorizationRetryID:      sql.NullString{String: claims.RetryID, Valid: true},
		AuthorizationRevision:     sql.NullInt64{Int64: int64(claims.Revision), Valid: true},
		AuthorizationExpiresAt:    sql.NullInt64{Int64: claims.ExpiresAt.UnixNano(), Valid: true},
		AuthorizationRequestHash:  claims.CanonicalRequestHash[:],
		AuthorizationIpPolicyHash: optionalDigestBytes(claims.IPPolicyHash), CreatedAt: now.UnixNano(),
	}
}

func signedReplacementParams(
	routeID, localTarget string,
	routeVersion uint64,
	claims authorization.Claims,
) statedb.ReplaceSignedRouteParams {
	return statedb.ReplaceSignedRouteParams{
		RouteID: routeID, LocalTarget: localTarget, RouteVersion: int64(routeVersion),
		AuthorizationIssuer:       sql.NullString{String: claims.Issuer, Valid: true},
		AuthorizationID:           sql.NullString{String: claims.AuthorizationID, Valid: true},
		AuthorizationKeyID:        sql.NullString{String: claims.KeyID, Valid: true},
		AuthorizationRetryID:      sql.NullString{String: claims.RetryID, Valid: true},
		AuthorizationRevision:     sql.NullInt64{Int64: int64(claims.Revision), Valid: true},
		AuthorizationExpiresAt:    sql.NullInt64{Int64: claims.ExpiresAt.UnixNano(), Valid: true},
		AuthorizationRequestHash:  claims.CanonicalRequestHash[:],
		AuthorizationIpPolicyHash: optionalDigestBytes(claims.IPPolicyHash),
	}
}

func signedAdvanceParams(
	route Route,
	routeVersion int64,
	now time.Time,
	claims authorization.Claims,
) statedb.AdvanceSignedRouteVersionParams {
	return statedb.AdvanceSignedRouteVersionParams{
		RouteID: route.ID, PreviousRouteVersion: int64(route.RouteVersion), RouteVersion: routeVersion,
		AuthorizationIssuer:       sql.NullString{String: claims.Issuer, Valid: true},
		AuthorizationID:           sql.NullString{String: claims.AuthorizationID, Valid: true},
		AuthorizationKeyID:        sql.NullString{String: claims.KeyID, Valid: true},
		AuthorizationRetryID:      sql.NullString{String: claims.RetryID, Valid: true},
		AuthorizationRevision:     sql.NullInt64{Int64: int64(claims.Revision), Valid: true},
		AuthorizationExpiresAt:    sql.NullInt64{Int64: claims.ExpiresAt.UnixNano(), Valid: true},
		AuthorizationRequestHash:  claims.CanonicalRequestHash[:],
		AuthorizationIpPolicyHash: optionalDigestBytes(claims.IPPolicyHash),
		Now:                       sql.NullInt64{Int64: now.UnixNano(), Valid: true},
	}
}

func routeFromClaims(
	routeID, hostname, localTarget string,
	routeVersion uint64,
	createdAt time.Time,
	claims authorization.Claims,
	prefixes []string,
) Route {
	return Route{
		ID: routeID, Hostname: hostname, LocalTarget: localTarget, Status: RouteStatusEnabled, RouteVersion: routeVersion,
		AuthorizationIssuer: claims.Issuer, AuthorizationID: claims.AuthorizationID,
		AuthorizationKeyID: claims.KeyID, AuthorizationRetryID: claims.RetryID,
		AuthorizationRevision: claims.Revision, AuthorizationExpiresAt: claims.ExpiresAt,
		AuthorizationRequestHash:  claims.CanonicalRequestHash,
		AuthorizationIPPolicyHash: cloneOptionalDigest(claims.IPPolicyHash),
		AllowedIPPrefixes:         slices.Clone(prefixes), CreatedAt: createdAt,
	}
}

func optionalDigestBytes(digest *authorization.Digest) []byte {
	if digest == nil {
		return nil
	}
	return digest[:]
}

func equalOptionalBytes(value []byte, digest *authorization.Digest) bool {
	if digest == nil {
		return len(value) == 0
	}
	return slices.Equal(value, digest[:])
}

func equalOptionalDigest(left, right *authorization.Digest) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cloneOptionalDigest(digest *authorization.Digest) *authorization.Digest {
	if digest == nil {
		return nil
	}
	clone := *digest
	return &clone
}

func minTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}
