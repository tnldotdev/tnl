package certificates

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

type store struct {
	queries      *statedb.Queries
	now          func() time.Time
	directoryURL string
	acmeProfile  string
}

func newStore(db *sql.DB, now func() time.Time, directoryURL, acmeProfile string) (*store, error) {
	if db == nil {
		return nil, errors.New("certificates: nil state database")
	}
	if now == nil {
		now = time.Now
	}
	return &store{queries: statedb.New(db), now: now, directoryURL: directoryURL, acmeProfile: acmeProfile}, nil
}

func (s *store) loadAccount(ctx context.Context, directoryURL string) (account, error) {
	result, err := s.queries.GetACMEAccount(ctx, directoryURL)
	if errors.Is(err, sql.ErrNoRows) {
		return account{}, ErrNotFound
	}
	if err != nil {
		return account{}, fmt.Errorf("certificates: load ACME account: %w", err)
	}
	return accountFromState(result), nil
}

func (s *store) insertAccount(ctx context.Context, value account) error {
	now := s.databaseTime()
	err := s.queries.InsertACMEAccount(ctx, statedb.InsertACMEAccountParams{
		DirectoryUrl: value.DirectoryURL,
		Email:        value.Email,
		KeyDer:       value.KeyDER,
		CreatedAt:    now.UnixNano(),
		UpdatedAt:    now.UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("certificates: insert ACME account: %w", err)
	}
	return nil
}

func (s *store) updateAccount(ctx context.Context, value account) error {
	count, err := s.queries.UpdateACMEAccount(ctx, statedb.UpdateACMEAccountParams{
		Email:            value.Email,
		Kid:              nullableString(value.KID),
		AcceptedTermsUrl: nullableString(value.AcceptedTOS),
		UpdatedAt:        s.databaseTime().UnixNano(),
		DirectoryUrl:     value.DirectoryURL,
	})
	if err != nil {
		return fmt.Errorf("certificates: update ACME account: %w", err)
	}
	return requireRow(count)
}

func (s *store) createIssuance(
	ctx context.Context,
	routeID string,
	version uint64,
	hostname string,
	csrDER []byte,
	csrHash, spkiHash [32]byte,
) (Issuance, bool, error) {
	existing, err := s.findBoundIssuance(ctx, routeID, version, csrHash)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Issuance{}, false, err
	}
	id, err := issuanceID()
	if err != nil {
		return Issuance{}, false, err
	}
	now := s.databaseTime()
	count, err := s.queries.InsertCertificateIssuance(ctx, statedb.InsertCertificateIssuanceParams{
		ID:           id,
		DirectoryUrl: s.directoryURL,
		AcmeProfile:  s.acmeProfile,
		CsrDer:       csrDER,
		CsrHash:      csrHash[:],
		SpkiHash:     spkiHash[:],
		CreatedAt:    now.UnixNano(),
		UpdatedAt:    now.UnixNano(),
		RouteID:      routeID,
		RouteVersion: int64(version),
		Hostname:     hostname,
		Now:          nullableTime(now),
	})
	if err != nil {
		return Issuance{}, false, fmt.Errorf("certificates: create issuance: %w", err)
	}
	if count == 0 {
		existing, err = s.findBoundIssuance(ctx, routeID, version, csrHash)
		if err == nil {
			return existing, false, nil
		}
		if errors.Is(err, ErrNotFound) {
			return Issuance{}, false, ErrInvalidStatus
		}
		return Issuance{}, false, err
	}
	created, err := s.getIssuance(ctx, id)
	return created, true, err
}

func (s *store) routeHostname(ctx context.Context, routeID string, version uint64) (string, error) {
	hostname, err := s.queries.GetEnabledRouteHostname(ctx, statedb.GetEnabledRouteHostnameParams{
		RouteID:      routeID,
		RouteVersion: int64(version),
		Now:          nullableTime(s.databaseTime()),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidStatus
	}
	if err != nil {
		return "", fmt.Errorf("certificates: read route: %w", err)
	}
	return hostname, nil
}

func (s *store) getIssuance(ctx context.Context, id string) (Issuance, error) {
	return issuanceFromDB(s.queries.GetCertificateIssuance(ctx, id))
}

func (s *store) getCAIssuance(ctx context.Context, id string) (Issuance, error) {
	issuance, err := s.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	if issuance.DirectoryURL != s.directoryURL || issuance.ACMEProfile != s.acmeProfile {
		return Issuance{}, ErrInvalidStatus
	}
	return issuance, nil
}

func (s *store) findBoundIssuance(ctx context.Context, routeID string, version uint64, csrHash [32]byte) (Issuance, error) {
	return issuanceFromDB(s.queries.FindBoundCertificateIssuance(ctx, statedb.FindBoundCertificateIssuanceParams{
		RouteID:      routeID,
		RouteVersion: int64(version),
		CsrHash:      csrHash[:],
		DirectoryUrl: s.directoryURL,
		AcmeProfile:  s.acmeProfile,
	}))
}

func (s *store) findRebindableIssuance(
	ctx context.Context,
	routeID string,
	csrHash [32]byte,
	now, validAfter time.Time,
) (Issuance, error) {
	return issuanceFromDB(s.queries.FindRebindableCertificateIssuance(ctx, statedb.FindRebindableCertificateIssuanceParams{
		RouteID:      routeID,
		CsrHash:      csrHash[:],
		DirectoryUrl: s.directoryURL,
		AcmeProfile:  s.acmeProfile,
		Now:          now.UnixNano(),
		ValidAfter:   validAfter.UnixNano(),
	}))
}

func (s *store) rebindIssuance(ctx context.Context, issuance Issuance, version uint64) (Issuance, error) {
	now := s.databaseTime()
	count, err := s.queries.RebindCertificateIssuance(ctx, statedb.RebindCertificateIssuanceParams{
		RouteVersion: int64(version),
		UpdatedAt:    now.UnixNano(),
		IssuanceID:   issuance.ID,
		RouteID:      issuance.RouteID,
		DirectoryUrl: s.directoryURL,
		AcmeProfile:  s.acmeProfile,
		Now:          nullableTime(now),
	})
	if err != nil {
		return Issuance{}, fmt.Errorf("certificates: rebind issuance: %w", err)
	}
	if count == 0 {
		return Issuance{}, ErrInvalidStatus
	}
	return s.getIssuance(ctx, issuance.ID)
}

func (s *store) allowIssuanceCreation(
	ctx context.Context,
	routeID string,
	version uint64,
	csrHash [32]byte,
	now time.Time,
) error {
	blocked, err := s.queries.HasBlockingCertificateIssuance(ctx, statedb.HasBlockingCertificateIssuanceParams{
		RouteID:      routeID,
		RouteVersion: int64(version),
		CsrHash:      csrHash[:],
		DirectoryUrl: s.directoryURL,
		AcmeProfile:  s.acmeProfile,
		Now:          now.UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("certificates: check active issuances: %w", err)
	}
	if blocked != 0 {
		return ErrInvalidStatus
	}
	recent, err := s.queries.GetRecentCertificateAttempts(ctx, statedb.GetRecentCertificateAttemptsParams{
		RouteID:      routeID,
		StartedAfter: nullableTime(now.Add(-time.Hour)),
	})
	if err != nil {
		return fmt.Errorf("certificates: count recent issuances: %w", err)
	}
	if recent.Count >= 3 {
		return &RateLimitError{RetryAt: time.Unix(0, recent.EarliestStartedAt).UTC().Add(time.Hour)}
	}
	return nil
}

func (s *store) saveIssuance(ctx context.Context, issuance Issuance) error {
	now := s.databaseTime()
	count, err := s.queries.UpdateCertificateIssuance(ctx, statedb.UpdateCertificateIssuanceParams{
		Status:             issuance.Status,
		OrderStartedAt:     nullableTime(issuance.OrderStartedAt),
		OrderUrl:           nullableString(issuance.OrderURL),
		OrderExpiresAt:     nullableTime(issuance.OrderExpires),
		RetryAt:            nullableTime(issuance.RetryAt),
		AuthorizationUrl:   nullableString(issuance.AuthorizationURL),
		FinalizeUrl:        nullableString(issuance.FinalizeURL),
		ChallengeUrl:       nullableString(issuance.ChallengeURL),
		ChallengeDigest:    nullableDigest(issuance.ChallengeURL, issuance.ChallengeDigest),
		ChallengeExpiresAt: nullableTime(issuance.ChallengeExpires),
		CertificateUrl:     nullableString(issuance.CertificateURL),
		CertificatePem:     nullableBytes(issuance.CertificatePEM),
		NotBefore:          nullableTime(issuance.NotBefore),
		NotAfter:           nullableTime(issuance.NotAfter),
		RenewAt:            nullableTime(issuance.RenewAt),
		LastError:          nullableString(issuance.LastError),
		UpdatedAt:          now.UnixNano(),
		IssuanceID:         issuance.ID,
		DirectoryUrl:       s.directoryURL,
		AcmeProfile:        s.acmeProfile,
		Now:                nullableTime(now),
	})
	if err != nil {
		return fmt.Errorf("certificates: save issuance: %w", err)
	}
	if count == 0 {
		return ErrInvalidStatus
	}
	return nil
}

func (s *store) removeChallenge(ctx context.Context, id string) (Issuance, error) {
	now := s.databaseTime()
	count, err := s.queries.RemoveCertificateChallenge(ctx, statedb.RemoveCertificateChallengeParams{
		UpdatedAt: now.UnixNano(), IssuanceID: id, Now: nullableTime(now),
	})
	if err != nil {
		return Issuance{}, fmt.Errorf("certificates: remove challenge: %w", err)
	}
	if count == 0 {
		return Issuance{}, ErrInvalidStatus
	}
	return s.getIssuance(ctx, id)
}

func (s *store) markInstalled(ctx context.Context, id, routeID string, version uint64) (Issuance, error) {
	now := s.databaseTime()
	count, err := s.queries.MarkCertificateInstalled(ctx, statedb.MarkCertificateInstalledParams{
		UpdatedAt: now.UnixNano(), IssuanceID: id, ExpectedRouteID: routeID,
		ExpectedRouteVersion: int64(version), Now: nullableTime(now),
	})
	if err != nil {
		return Issuance{}, fmt.Errorf("certificates: mark installed: %w", err)
	}
	if count == 0 {
		return Issuance{}, ErrInvalidStatus
	}
	return s.getIssuance(ctx, id)
}

func issuanceFromDB(value statedb.CertificateIssuance, err error) (Issuance, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return Issuance{}, ErrNotFound
	}
	if err != nil {
		return Issuance{}, fmt.Errorf("certificates: scan issuance: %w", err)
	}
	if len(value.CsrHash) != len(Issuance{}.CSRHash) || len(value.SpkiHash) != len(Issuance{}.SPKIHash) ||
		(len(value.ChallengeDigest) != 0 && len(value.ChallengeDigest) != len(Issuance{}.ChallengeDigest)) {
		return Issuance{}, errors.New("certificates: corrupt issuance digest")
	}
	issuance := Issuance{
		ID:               value.ID,
		RouteID:          value.RouteID,
		RouteVersion:     uint64(value.RouteVersion),
		Hostname:         value.Hostname,
		DirectoryURL:     value.DirectoryUrl,
		ACMEProfile:      value.AcmeProfile,
		Status:           value.Status,
		CSRDER:           value.CsrDer,
		OrderStartedAt:   sqlTime(value.OrderStartedAt),
		OrderURL:         value.OrderUrl.String,
		OrderExpires:     sqlTime(value.OrderExpiresAt),
		RetryAt:          sqlTime(value.RetryAt),
		AuthorizationURL: value.AuthorizationUrl.String,
		FinalizeURL:      value.FinalizeUrl.String,
		ChallengeURL:     value.ChallengeUrl.String,
		ChallengeExpires: sqlTime(value.ChallengeExpiresAt),
		CertificateURL:   value.CertificateUrl.String,
		CertificatePEM:   value.CertificatePem,
		NotBefore:        sqlTime(value.NotBefore),
		NotAfter:         sqlTime(value.NotAfter),
		RenewAt:          sqlTime(value.RenewAt),
		LastError:        value.LastError.String,
		CreatedAt:        time.Unix(0, value.CreatedAt).UTC(),
		UpdatedAt:        time.Unix(0, value.UpdatedAt).UTC(),
	}
	copy(issuance.CSRHash[:], value.CsrHash)
	copy(issuance.SPKIHash[:], value.SpkiHash)
	copy(issuance.ChallengeDigest[:], value.ChallengeDigest)
	return issuance, nil
}

func accountFromState(value statedb.AcmeAccount) account {
	return account{
		DirectoryURL: value.DirectoryUrl,
		Email:        value.Email,
		KeyDER:       value.KeyDer,
		KID:          value.Kid.String,
		AcceptedTOS:  value.AcceptedTermsUrl.String,
		CreatedAt:    time.Unix(0, value.CreatedAt).UTC(),
		UpdatedAt:    time.Unix(0, value.UpdatedAt).UTC(),
	}
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullableBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableDigest(present string, value [32]byte) []byte {
	if present == "" {
		return nil
	}
	return value[:]
}

func nullableTime(value time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: value.UnixNano(), Valid: !value.IsZero()}
}

func sqlTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(0, value.Int64).UTC()
}

func requireRow(count int64) error {
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *store) databaseTime() time.Time {
	return time.Unix(0, s.now().UnixNano()).UTC()
}

func issuanceID() (string, error) {
	id, err := opaqueid.New("issuance_")
	if err != nil {
		return "", fmt.Errorf("certificates: generate issuance ID: %w", err)
	}
	return id, nil
}
