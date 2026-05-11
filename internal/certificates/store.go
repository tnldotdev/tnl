package certificates

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/state/statedb"
)

type store struct {
	queries *statedb.Queries
	now     func() time.Time
}

func newStore(db *sql.DB, now func() time.Time) (*store, error) {
	if db == nil {
		return nil, errors.New("certificates: nil state database")
	}
	if now == nil {
		now = time.Now
	}
	return &store{queries: statedb.New(db), now: now}, nil
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
	now := time.Unix(0, s.now().UnixNano()).UTC()
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
	now := time.Unix(0, s.now().UnixNano()).UTC()
	count, err := s.queries.UpdateACMEAccount(ctx, statedb.UpdateACMEAccountParams{
		Email:            value.Email,
		Kid:              nullableString(value.KID),
		AcceptedTermsUrl: nullableString(value.AcceptedTOS),
		UpdatedAt:        now.UnixNano(),
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
	hostname, acmeProfile string,
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
	now := time.Unix(0, s.now().UnixNano()).UTC()
	err = s.queries.InsertCertificateIssuance(ctx, statedb.InsertCertificateIssuanceParams{
		ID:          id,
		RouteID:     routeID,
		Version:     int64(version),
		Hostname:    hostname,
		AcmeProfile: acmeProfile,
		Status:      StatusCreatingOrder,
		CsrDer:      csrDER,
		CsrHash:     csrHash[:],
		SpkiHash:    spkiHash[:],
		CreatedAt:   now.UnixNano(),
		UpdatedAt:   now.UnixNano(),
	})
	if err != nil {
		return Issuance{}, false, fmt.Errorf("certificates: create issuance: %w", err)
	}
	created, err := s.findBoundIssuance(ctx, routeID, version, csrHash)
	if err != nil {
		return Issuance{}, false, err
	}
	return created, created.ID == id, nil
}

func (s *store) routeHostname(ctx context.Context, routeID string, version uint64) (string, error) {
	hostname, err := s.queries.GetActiveRouteHostname(ctx, statedb.GetActiveRouteHostnameParams{
		RouteID: routeID,
		Version: int64(version),
		Now:     sql.NullInt64{Int64: s.now().UnixNano(), Valid: true},
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

func (s *store) findBoundIssuance(ctx context.Context, routeID string, version uint64, csrHash [32]byte) (Issuance, error) {
	return issuanceFromDB(s.queries.FindBoundCertificateIssuance(ctx, statedb.FindBoundCertificateIssuanceParams{
		RouteID: routeID,
		Version: int64(version),
		CsrHash: csrHash[:],
	}))
}

func (s *store) findResumableIssuance(ctx context.Context, routeID string, csrHash [32]byte, now time.Time) (Issuance, error) {
	return issuanceFromDB(s.queries.FindResumableCertificateIssuance(ctx, statedb.FindResumableCertificateIssuanceParams{
		RouteID: routeID,
		CsrHash: csrHash[:],
		Now:     now.UnixNano(),
	}))
}

func (s *store) rebindIssuance(ctx context.Context, id string, version uint64) (Issuance, error) {
	now := time.Unix(0, s.now().UnixNano()).UTC()
	count, err := s.queries.RebindCertificateIssuance(ctx, statedb.RebindCertificateIssuanceParams{
		Version:   int64(version),
		UpdatedAt: now.UnixNano(),
		ID:        id,
	})
	if err != nil {
		return Issuance{}, fmt.Errorf("certificates: rebind issuance: %w", err)
	}
	if err := requireRow(count); err != nil {
		return Issuance{}, err
	}
	return s.getIssuance(ctx, id)
}

func (s *store) allowIssuanceCreation(
	ctx context.Context,
	routeID string,
	version uint64,
	csrHash [32]byte,
	now time.Time,
) error {
	blocked, err := s.queries.HasBlockingCertificateIssuance(ctx, statedb.HasBlockingCertificateIssuanceParams{
		RouteID: routeID,
		Version: int64(version),
		CsrHash: csrHash[:],
		Now:     now.UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("certificates: check active issuances: %w", err)
	}
	if blocked != 0 {
		return ErrInvalidStatus
	}
	recent, err := s.queries.GetRecentCertificateAttempts(ctx, statedb.GetRecentCertificateAttemptsParams{
		RouteID:   routeID,
		CreatedAt: now.Add(-time.Hour).UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("certificates: count recent issuances: %w", err)
	}
	if recent.Count >= 3 {
		return &RateLimitError{RetryAt: time.Unix(0, recent.EarliestCreatedAt).UTC().Add(time.Hour)}
	}
	return nil
}

func (s *store) findReusableIssuance(ctx context.Context, routeID string, csrHash [32]byte, validAfter time.Time) (Issuance, error) {
	return issuanceFromDB(s.queries.FindReusableCertificateIssuance(ctx, statedb.FindReusableCertificateIssuanceParams{
		RouteID:    routeID,
		CsrHash:    csrHash[:],
		ValidAfter: validAfter.UnixNano(),
	}))
}

func (s *store) saveIssuance(ctx context.Context, issuance Issuance) error {
	now := time.Unix(0, s.now().UnixNano()).UTC()
	count, err := s.queries.UpdateCertificateIssuance(ctx, statedb.UpdateCertificateIssuanceParams{
		Status:             issuance.Status,
		OrderUrl:           nullableString(issuance.OrderURL),
		AcmeStatus:         nullableString(issuance.ACMEStatus),
		OrderAttempts:      int64(issuance.OrderAttempts),
		OrderExpiresAt:     nullableTime(issuance.OrderExpires),
		RetryAt:            nullableTime(issuance.RetryAt),
		AuthorizationUrl:   nullableString(issuance.AuthorizationURL),
		FinalizeUrl:        nullableString(issuance.FinalizeURL),
		ChallengeUrl:       nullableString(issuance.ChallengeURL),
		ChallengeToken:     nullableString(issuance.ChallengeToken),
		ChallengeDigest:    nullableDigest(issuance.ChallengeURL, issuance.ChallengeDigest),
		ChallengeExpiresAt: nullableTime(issuance.ChallengeExpires),
		CertificateUrl:     nullableString(issuance.CertificateURL),
		CertificatePem:     nullableBytes(issuance.CertificatePEM),
		NotBefore:          nullableTime(issuance.NotBefore),
		NotAfter:           nullableTime(issuance.NotAfter),
		RenewAt:            nullableTime(issuance.RenewAt),
		InstalledAt:        nullableTime(issuance.InstalledAt),
		ChallengeRemovedAt: nullableTime(issuance.ChallengeRemoved),
		LastError:          nullableString(issuance.LastError),
		UpdatedAt:          now.UnixNano(),
		ID:                 issuance.ID,
	})
	if err != nil {
		return fmt.Errorf("certificates: save issuance: %w", err)
	}
	return requireRow(count)
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
		Version:          uint64(value.Version),
		Hostname:         value.Hostname,
		ACMEProfile:      value.AcmeProfile,
		Status:           value.Status,
		CSRDER:           value.CsrDer,
		OrderURL:         value.OrderUrl.String,
		ACMEStatus:       value.AcmeStatus.String,
		OrderAttempts:    int(value.OrderAttempts),
		OrderExpires:     sqlTime(value.OrderExpiresAt),
		RetryAt:          sqlTime(value.RetryAt),
		AuthorizationURL: value.AuthorizationUrl.String,
		FinalizeURL:      value.FinalizeUrl.String,
		ChallengeURL:     value.ChallengeUrl.String,
		ChallengeToken:   value.ChallengeToken.String,
		ChallengeExpires: sqlTime(value.ChallengeExpiresAt),
		CertificateURL:   value.CertificateUrl.String,
		CertificatePEM:   value.CertificatePem,
		NotBefore:        sqlTime(value.NotBefore),
		NotAfter:         sqlTime(value.NotAfter),
		RenewAt:          sqlTime(value.RenewAt),
		InstalledAt:      sqlTime(value.InstalledAt),
		ChallengeRemoved: sqlTime(value.ChallengeRemovedAt),
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

func issuanceID() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("certificates: generate issuance ID: %w", err)
	}
	return "issuance_" + hex.EncodeToString(material[:]), nil
}
