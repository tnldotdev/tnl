package controlstate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrCertificateIssuanceGated       = errors.New("controlstate: certificate issuance is disabled")
	ErrCertificateIssuanceIdempotency = errors.New("controlstate: certificate issuance idempotency conflict")
	ErrCertificateIssuanceInvalid     = errors.New("controlstate: certificate issuance request is invalid")
	ErrCertificateIssuanceNotFound    = errors.New("controlstate: certificate issuance not found")
	ErrCertificateChallengeNotReady   = errors.New("controlstate: certificate challenge is not ready for acknowledgement")
)

type ACMEAccount struct {
	ID            string
	DirectoryURL  string
	ContactEmail  string
	AccountKeyDER []byte
	AccountURL    string
	AcceptedTerms string
}

type CertificateChallenge struct {
	Identifier string
	Method     string
	Token      string
	Digest     [32]byte
	ExpiresAt  time.Time
}

type CertificatePlan struct {
	CacheKey        string
	Scope           string
	Identifiers     []string
	ChallengeMethod string
}

type CertificateIssuance struct {
	ID              string
	RouteSessionID  string
	RouteID         string
	RouteVersion    uint64
	CertificatePlan CertificatePlan
	State           string
	Challenges      []CertificateChallenge
	CertificatePEM  string
	RetryAt         *time.Time
	NotBefore       *time.Time
	NotAfter        *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type CreateCertificateIssuanceRequest struct {
	Authentication RouteSessionAuthentication
	DirectoryURL   string
	IdempotencyKey string
	RequestDigest  [32]byte
	CSRDER         []byte
}

func (d *Database) EnsureACMEAccount(
	ctx context.Context,
	directoryURL string,
	contactEmail string,
	now time.Time,
) (ACMEAccount, error) {
	if !validStateText(directoryURL) || !validStateText(contactEmail) {
		return ACMEAccount{}, ErrCertificateIssuanceInvalid
	}
	if err := d.requireOpen(); err != nil {
		return ACMEAccount{}, err
	}
	queries := controlstatedb.New(d.pool)
	existing, err := queries.GetACMEAccountByDirectory(ctx, directoryURL)
	if err == nil && existing.ContactEmail == contactEmail {
		return acmeAccount(existing), nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ACMEAccount{}, fmt.Errorf("controlstate: read ACME account: %w", err)
	}
	accountID, err := opaqueid.New("acme_account_")
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: generate ACME account ID: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: generate ACME account key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: encode ACME account key: %w", err)
	}
	if existing.ID != "" {
		accountID = existing.ID
		keyDER = existing.AccountKeyDer
	}
	row, err := queries.EnsureACMEAccount(ctx, controlstatedb.EnsureACMEAccountParams{
		ID: accountID, DirectoryUrl: directoryURL, ContactEmail: contactEmail,
		AccountKeyDer: keyDER, CreatedAt: timestamptz(now),
	})
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: ensure ACME account: %w", err)
	}
	return acmeAccount(row), nil
}

func (d *Database) CreateCertificateIssuance(
	ctx context.Context,
	request CreateCertificateIssuanceRequest,
	now time.Time,
) (result CertificateIssuance, retErr error) {
	csrDigest, err := validateCertificateIssuanceRequest(request)
	if err != nil {
		return CertificateIssuance{}, err
	}
	if err := d.requireOpen(); err != nil {
		return CertificateIssuance{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create certificate issuance", &retErr)()
	queries := controlstatedb.New(tx)
	_, session, err := lockAuthenticatedRouteSession(ctx, queries, request.Authentication, now)
	if err != nil {
		return CertificateIssuance{}, err
	}
	csr, _ := x509.ParseCertificateRequest(request.CSRDER)
	csrIdentifiers, err := canonicalCertificateIdentifiers(csr.DNSNames)
	if err != nil {
		return CertificateIssuance{}, ErrCertificateIssuanceInvalid
	}
	planIdentifiers, err := canonicalCertificateIdentifiers(session.CertificateIdentifiers)
	if err != nil || !slices.Equal(csrIdentifiers, planIdentifiers) {
		return CertificateIssuance{}, ErrCertificateIssuanceInvalid
	}
	account, err := queries.GetACMEAccountByDirectory(ctx, request.DirectoryURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return CertificateIssuance{}, ErrCertificateIssuanceInvalid
	}
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: read ACME account: %w", err)
	}
	existing, err := queries.GetACMEOrderByIdempotency(ctx, controlstatedb.GetACMEOrderByIdempotencyParams{
		RouteSessionID: session.ID, IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, request.RequestDigest[:]) != 1 {
			return CertificateIssuance{}, ErrCertificateIssuanceIdempotency
		}
		result, err = loadCertificateIssuance(ctx, queries, existing, now)
		if err != nil {
			return CertificateIssuance{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: commit retry: %w", err)
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: read idempotent order: %w", err)
	}
	enabled, err := queries.LockCertificateIssuanceControl(ctx)
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: read maintenance control: %w", err)
	}
	if !enabled {
		return CertificateIssuance{}, ErrCertificateIssuanceGated
	}
	issuanceID, err := opaqueid.New("issuance_")
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: generate certificate issuance ID: %w", err)
	}
	row, err := queries.InsertACMEOrder(ctx, controlstatedb.InsertACMEOrderParams{
		ID: issuanceID, AccountID: account.ID, RouteSessionID: session.ID, RouteID: session.RouteID,
		RouteVersion: session.RouteVersion, IdempotencyKey: request.IdempotencyKey,
		RequestDigest: request.RequestDigest[:], CertificateCacheKey: session.CertificateCacheKey,
		CertificateScope: session.CertificateScope, CertificateIdentifiers: slices.Clone(session.CertificateIdentifiers),
		ChallengeMethod: session.CertificateChallenge, CsrDer: slices.Clone(request.CSRDER),
		CsrDigest: csrDigest[:], CreatedAt: timestamptz(now),
	})
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return CertificateIssuance{}, ErrCertificateIssuanceIdempotency
		}
		return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: insert order: %w", err)
	}
	if err := queries.InsertCertificateIssuanceAuditEvent(ctx, controlstatedb.InsertCertificateIssuanceAuditEventParams{
		ActorIdentityID: text(session.ActingIdentityID), RequestID: request.IdempotencyKey,
		IssuanceID: issuanceID, OccurredAt: timestamptz(now),
	}); err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: insert audit event: %w", err)
	}
	result, err = loadCertificateIssuance(ctx, queries, row, now)
	if err != nil {
		return CertificateIssuance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: create certificate issuance: commit: %w", err)
	}
	return result, nil
}

func (d *Database) GetCertificateIssuance(
	ctx context.Context,
	issuanceID string,
	token credentials.SessionToken,
	now time.Time,
) (result CertificateIssuance, retErr error) {
	if !validStateText(issuanceID) {
		return CertificateIssuance{}, ErrCertificateIssuanceNotFound
	}
	if err := d.requireOpen(); err != nil {
		return CertificateIssuance{}, err
	}
	authentication, err := d.routeSessionAuthenticationForToken(ctx, token)
	if err != nil {
		return CertificateIssuance{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: get certificate issuance: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "get certificate issuance", &retErr)()
	queries := controlstatedb.New(tx)
	_, session, err := lockAuthenticatedRouteSession(ctx, queries, authentication, now)
	if err != nil {
		return CertificateIssuance{}, err
	}
	order, err := queries.GetACMEOrder(ctx, issuanceID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && order.RouteSessionID != session.ID {
		return CertificateIssuance{}, ErrCertificateIssuanceNotFound
	}
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: get certificate issuance: read order: %w", err)
	}
	result, err = loadCertificateIssuance(ctx, queries, order, now)
	if err != nil {
		return CertificateIssuance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: get certificate issuance: commit: %w", err)
	}
	return result, nil
}

func (d *Database) MarkCertificateChallengeReady(
	ctx context.Context,
	issuanceID string,
	token credentials.SessionToken,
	now time.Time,
) (CertificateIssuance, error) {
	return d.updateCertificateChallenge(ctx, issuanceID, token, now, true)
}

func (d *Database) MarkCertificateChallengeRemoved(
	ctx context.Context,
	issuanceID string,
	token credentials.SessionToken,
	now time.Time,
) (CertificateIssuance, error) {
	return d.updateCertificateChallenge(ctx, issuanceID, token, now, false)
}

func (d *Database) updateCertificateChallenge(
	ctx context.Context,
	issuanceID string,
	token credentials.SessionToken,
	now time.Time,
	ready bool,
) (result CertificateIssuance, retErr error) {
	if !validStateText(issuanceID) {
		return CertificateIssuance{}, ErrCertificateIssuanceNotFound
	}
	if err := d.requireOpen(); err != nil {
		return CertificateIssuance{}, err
	}
	authentication, err := d.routeSessionAuthenticationForToken(ctx, token)
	if err != nil {
		return CertificateIssuance{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: update certificate challenge: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "update certificate challenge", &retErr)()
	queries := controlstatedb.New(tx)
	route, session, err := lockAuthenticatedRouteSession(ctx, queries, authentication, now)
	if err != nil {
		return CertificateIssuance{}, err
	}
	order, err := queries.LockACMEOrder(ctx, issuanceID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && order.RouteSessionID != session.ID {
		return CertificateIssuance{}, ErrCertificateIssuanceNotFound
	}
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: update certificate challenge: lock order: %w", err)
	}
	authorizations, err := queries.ListACMEOrderAuthorizations(ctx, issuanceID)
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: update certificate challenge: list authorizations: %w", err)
	}
	if !validCertificateChallengeAcknowledgement(order, authorizations, ready, now) {
		return CertificateIssuance{}, ErrCertificateChallengeNotReady
	}
	challengeExpiresAt := authorizations[0].ExpiresAt.Time
	transitioning := false
	for _, authorization := range authorizations {
		if authorization.ExpiresAt.Time.Before(challengeExpiresAt) {
			challengeExpiresAt = authorization.ExpiresAt.Time
		}
		transitioning = transitioning || ready && authorization.State == "presenting" ||
			!ready && authorization.State != "complete"
	}
	if transitioning {
		connections := []controlstatedb.ListValidReadyPublisherConnectionsRow(nil)
		eventKind := IngressChallengeTombstone
		if ready {
			connections, err = validReadyPublisherConnections(ctx, queries, session.ID, now)
			if err != nil {
				return CertificateIssuance{}, err
			}
			if len(connections) == 0 {
				return CertificateIssuance{}, ErrCertificateChallengeNotReady
			}
			eventKind = IngressChallengeUpsert
		}
		if _, _, err := emitChallengeRoutingTableEvent(
			ctx, queries, route, session, connections, eventKind, challengeExpiresAt, now,
		); err != nil {
			return CertificateIssuance{}, err
		}
	}
	if ready {
		if _, err := queries.MarkACMEAuthorizationsPresented(ctx, controlstatedb.MarkACMEAuthorizationsPresentedParams{
			PresentedAt: timestamptz(now), IssuanceID: issuanceID,
		}); err != nil {
			return CertificateIssuance{}, fmt.Errorf("controlstate: mark certificate challenge presented: %w", err)
		}
		if err := queries.WakeACMEOrder(ctx, controlstatedb.WakeACMEOrderParams{
			AvailableAt: timestamptz(now), IssuanceID: issuanceID,
		}); err != nil {
			return CertificateIssuance{}, fmt.Errorf("controlstate: wake certificate order: %w", err)
		}
	} else if _, err := queries.CompleteACMEAuthorizationCleanup(ctx, controlstatedb.CompleteACMEAuthorizationCleanupParams{
		CompletedAt: timestamptz(now), IssuanceID: issuanceID,
	}); err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: complete certificate challenge cleanup: %w", err)
	}
	order, err = queries.GetACMEOrder(ctx, issuanceID)
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: update certificate challenge: reload order: %w", err)
	}
	result, err = loadCertificateIssuance(ctx, queries, order, now)
	if err != nil {
		return CertificateIssuance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: update certificate challenge: commit: %w", err)
	}
	return result, nil
}

func validCertificateChallengeAcknowledgement(
	order controlstatedb.ControlAcmeOrder,
	authorizations []controlstatedb.ControlAcmeAuthorization,
	ready bool,
	now time.Time,
) bool {
	if len(authorizations) == 0 || order.ChallengeMethod != "tls-alpn-01" {
		return false
	}
	if ready && order.State != "authorizing" && order.State != "ready_to_finalize" &&
		order.State != "finalizing" && order.State != "waiting_for_install" && order.State != "installed" {
		return false
	}
	for _, authorization := range authorizations {
		if authorization.ChallengeType != "tls-alpn-01" || !authorization.ExpiresAt.Valid ||
			ready && !authorization.ExpiresAt.Time.After(now) {
			return false
		}
		if ready {
			if authorization.State != "presenting" && authorization.State != "presented" &&
				authorization.State != "validating" && authorization.State != "valid" &&
				authorization.State != "cleaning" && authorization.State != "complete" {
				return false
			}
		} else if order.State != "waiting_for_install" && order.State != "installed" &&
			order.State != "failed" && order.State != "canceled" ||
			authorization.State != "presenting" && authorization.State != "presented" &&
				authorization.State != "validating" && authorization.State != "valid" &&
				authorization.State != "cleaning" && authorization.State != "failed" &&
				authorization.State != "complete" {
			return false
		}
	}
	return true
}

func (d *Database) routeSessionAuthenticationForToken(
	ctx context.Context,
	token credentials.SessionToken,
) (RouteSessionAuthentication, error) {
	tokenID, tokenHash, err := credentials.ParseSessionToken(token)
	if err != nil {
		return RouteSessionAuthentication{}, ErrRouteSessionCredential
	}
	session, err := controlstatedb.New(d.pool).GetRouteSessionByTokenID(ctx, tokenID.String())
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !credentials.SecretHashMatches(session.SessionTokenDigest, tokenHash) {
		return RouteSessionAuthentication{}, ErrRouteSessionCredential
	}
	if err != nil {
		return RouteSessionAuthentication{}, fmt.Errorf("controlstate: read route session by credential: %w", err)
	}
	return RouteSessionAuthentication{
		RouteSessionID: session.ID, RouteID: session.RouteID,
		RouteVersion: uint64(session.RouteVersion), SessionToken: token,
	}, nil
}

func validateCertificateIssuanceRequest(request CreateCertificateIssuanceRequest) ([32]byte, error) {
	if err := validateRouteSessionAuthentication(request.Authentication); err != nil {
		return [32]byte{}, err
	}
	if !validStateText(request.DirectoryURL) || !validStateText(request.IdempotencyKey) ||
		len(request.IdempotencyKey) > 128 || len(request.CSRDER) == 0 || len(request.CSRDER) > 65536 {
		return [32]byte{}, ErrCertificateIssuanceInvalid
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) == 0 || len(csr.EmailAddresses) != 0 ||
		len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || csr.Subject.String() != "" ||
		!certificateidentity.DNSNamesOnly(csr.Extensions, csr.DNSNames) {
		return [32]byte{}, ErrCertificateIssuanceInvalid
	}
	if _, err := canonicalCertificateIdentifiers(csr.DNSNames); err != nil {
		return [32]byte{}, ErrCertificateIssuanceInvalid
	}
	return sha256.Sum256(request.CSRDER), nil
}

func canonicalCertificateIdentifiers(identifiers []string) ([]string, error) {
	if len(identifiers) == 0 {
		return nil, ErrCertificateIssuanceInvalid
	}
	result := make([]string, 0, len(identifiers))
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		canonicalInput := strings.TrimPrefix(identifier, "*.")
		if strings.Contains(identifier, "*") && canonicalInput == identifier {
			return nil, ErrCertificateIssuanceInvalid
		}
		canonical, err := naming.CanonicalizeHostname(canonicalInput)
		if err != nil || canonical != canonicalInput {
			return nil, ErrCertificateIssuanceInvalid
		}
		canonicalIdentifier := canonical
		if canonicalInput != identifier {
			canonicalIdentifier = "*." + canonical
		}
		if _, exists := seen[canonicalIdentifier]; exists {
			return nil, ErrCertificateIssuanceInvalid
		}
		seen[canonicalIdentifier] = struct{}{}
		result = append(result, canonicalIdentifier)
	}
	slices.Sort(result)
	return result, nil
}

func loadCertificateIssuance(
	ctx context.Context,
	queries *controlstatedb.Queries,
	order controlstatedb.ControlAcmeOrder,
	now time.Time,
) (CertificateIssuance, error) {
	rows, err := queries.ListACMEOrderAuthorizations(ctx, order.ID)
	if err != nil {
		return CertificateIssuance{}, fmt.Errorf("controlstate: list certificate challenges: %w", err)
	}
	result := CertificateIssuance{
		ID: order.ID, RouteSessionID: order.RouteSessionID, RouteID: order.RouteID,
		RouteVersion: uint64(order.RouteVersion), CertificatePlan: CertificatePlan{
			CacheKey: order.CertificateCacheKey, Scope: order.CertificateScope,
			Identifiers: slices.Clone(order.CertificateIdentifiers), ChallengeMethod: order.ChallengeMethod,
		},
		State: order.State, Challenges: make([]CertificateChallenge, 0, len(rows)),
		CertificatePEM: string(order.CertificatePem), CreatedAt: order.CreatedAt.Time, UpdatedAt: order.UpdatedAt.Time,
	}
	if order.AvailableAt.Valid && order.AvailableAt.Time.After(now) {
		retryAt := order.AvailableAt.Time
		result.RetryAt = &retryAt
	}
	if order.NotBefore.Valid {
		notBefore := order.NotBefore.Time
		result.NotBefore = &notBefore
	}
	if order.NotAfter.Valid {
		notAfter := order.NotAfter.Time
		result.NotAfter = &notAfter
	}
	for _, row := range rows {
		if len(row.ChallengeDigest) != sha256.Size || !row.ExpiresAt.Valid || row.State == "complete" || row.State == "canceled" {
			continue
		}
		challenge := CertificateChallenge{
			Identifier: row.Identifier, Method: row.ChallengeType, Token: row.ChallengeToken,
			ExpiresAt: row.ExpiresAt.Time,
		}
		copy(challenge.Digest[:], row.ChallengeDigest)
		result.Challenges = append(result.Challenges, challenge)
	}
	return result, nil
}

func acmeAccount(row controlstatedb.ControlAcmeAccount) ACMEAccount {
	return ACMEAccount{
		ID: row.ID, DirectoryURL: row.DirectoryUrl, ContactEmail: row.ContactEmail,
		AccountKeyDER: slices.Clone(row.AccountKeyDer), AccountURL: row.AccountUrl.String,
		AcceptedTerms: row.AcceptedTermsUrl.String,
	}
}
