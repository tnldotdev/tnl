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
	now := time.Unix(s.now().Unix(), 0).UTC()
	err := s.queries.InsertACMEAccount(ctx, statedb.InsertACMEAccountParams{
		DirectoryUrl: value.DirectoryURL,
		Email:        value.Email,
		KeyDer:       value.KeyDER,
		CreatedAt:    now.Unix(),
		UpdatedAt:    now.Unix(),
	})
	if err != nil {
		return fmt.Errorf("certificates: insert ACME account: %w", err)
	}
	return nil
}

func (s *store) updateAccount(ctx context.Context, value account) error {
	now := time.Unix(s.now().Unix(), 0).UTC()
	count, err := s.queries.UpdateACMEAccount(ctx, statedb.UpdateACMEAccountParams{
		Email:            value.Email,
		Kid:              nullableString(value.KID),
		AcceptedTermsUrl: nullableString(value.AcceptedTOS),
		UpdatedAt:        now.Unix(),
		DirectoryUrl:     value.DirectoryURL,
	})
	if err != nil {
		return fmt.Errorf("certificates: update ACME account: %w", err)
	}
	return requireRow(count)
}

func (s *store) createJob(
	ctx context.Context,
	routeID string,
	generation uint64,
	hostname, profile string,
	csrDER []byte,
	csrHash, spkiHash [32]byte,
) (Job, bool, error) {
	existing, err := s.findBoundJob(ctx, routeID, generation, csrHash)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Job{}, false, err
	}
	id, err := certificateID()
	if err != nil {
		return Job{}, false, err
	}
	now := time.Unix(s.now().Unix(), 0).UTC()
	err = s.queries.InsertCertificateJob(ctx, statedb.InsertCertificateJobParams{
		ID:         id,
		RouteID:    routeID,
		Generation: int64(generation),
		Hostname:   hostname,
		Profile:    profile,
		State:      StateCreatingOrder,
		CsrDer:     csrDER,
		CsrHash:    csrHash[:],
		SpkiHash:   spkiHash[:],
		CreatedAt:  now.Unix(),
		UpdatedAt:  now.Unix(),
	})
	if err != nil {
		return Job{}, false, fmt.Errorf("certificates: create job: %w", err)
	}
	created, err := s.findBoundJob(ctx, routeID, generation, csrHash)
	if err != nil {
		return Job{}, false, err
	}
	return created, created.ID == id, nil
}

func (s *store) routeHostname(ctx context.Context, routeID string, generation uint64) (string, error) {
	hostname, err := s.queries.GetActiveRouteHostname(ctx, statedb.GetActiveRouteHostnameParams{
		ID:         routeID,
		Generation: int64(generation),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidState
	}
	if err != nil {
		return "", fmt.Errorf("certificates: read route: %w", err)
	}
	return hostname, nil
}

func (s *store) getJob(ctx context.Context, id string) (Job, error) {
	return jobFromState(s.queries.GetCertificateJob(ctx, id))
}

func (s *store) findBoundJob(ctx context.Context, routeID string, generation uint64, csrHash [32]byte) (Job, error) {
	return jobFromState(s.queries.FindBoundCertificateJob(ctx, statedb.FindBoundCertificateJobParams{
		RouteID:    routeID,
		Generation: int64(generation),
		CsrHash:    csrHash[:],
	}))
}

func (s *store) findResumableJob(ctx context.Context, routeID string, csrHash [32]byte, now time.Time) (Job, error) {
	return jobFromState(s.queries.FindResumableCertificateJob(ctx, statedb.FindResumableCertificateJobParams{
		RouteID: routeID,
		CsrHash: csrHash[:],
		Now:     now.Unix(),
	}))
}

func (s *store) rebindJob(ctx context.Context, id string, generation uint64) (Job, error) {
	now := time.Unix(s.now().Unix(), 0).UTC()
	count, err := s.queries.RebindCertificateJob(ctx, statedb.RebindCertificateJobParams{
		Generation: int64(generation),
		UpdatedAt:  now.Unix(),
		ID:         id,
	})
	if err != nil {
		return Job{}, fmt.Errorf("certificates: rebind job: %w", err)
	}
	if err := requireRow(count); err != nil {
		return Job{}, err
	}
	return s.getJob(ctx, id)
}

func (s *store) allowJobCreation(
	ctx context.Context,
	routeID string,
	generation uint64,
	csrHash [32]byte,
	now time.Time,
) error {
	blocked, err := s.queries.HasBlockingCertificateJob(ctx, statedb.HasBlockingCertificateJobParams{
		RouteID:    routeID,
		Generation: int64(generation),
		CsrHash:    csrHash[:],
		Now:        now.Unix(),
	})
	if err != nil {
		return fmt.Errorf("certificates: check active jobs: %w", err)
	}
	if blocked != 0 {
		return ErrInvalidState
	}
	recent, err := s.queries.GetRecentCertificateAttempts(ctx, statedb.GetRecentCertificateAttemptsParams{
		RouteID:   routeID,
		CreatedAt: now.Add(-time.Hour).Unix(),
	})
	if err != nil {
		return fmt.Errorf("certificates: count recent jobs: %w", err)
	}
	if recent.Count >= 3 {
		return &RateLimitError{RetryAt: time.Unix(recent.EarliestCreatedAt, 0).UTC().Add(time.Hour)}
	}
	return nil
}

func (s *store) findReusableJob(ctx context.Context, routeID string, csrHash [32]byte, validAfter time.Time) (Job, error) {
	return jobFromState(s.queries.FindReusableCertificateJob(ctx, statedb.FindReusableCertificateJobParams{
		RouteID:    routeID,
		CsrHash:    csrHash[:],
		ValidAfter: validAfter.Unix(),
	}))
}

func (s *store) saveJob(ctx context.Context, job Job) error {
	now := time.Unix(s.now().Unix(), 0).UTC()
	count, err := s.queries.UpdateCertificateJob(ctx, statedb.UpdateCertificateJobParams{
		State:              job.State,
		OrderUrl:           nullableString(job.OrderURL),
		AcmeStatus:         nullableString(job.ACMEStatus),
		OrderAttempts:      int64(job.OrderAttempts),
		OrderExpiresAt:     nullableTime(job.OrderExpires),
		RetryAt:            nullableTime(job.RetryAt),
		AuthorizationUrl:   nullableString(job.AuthorizationURL),
		FinalizeUrl:        nullableString(job.FinalizeURL),
		ChallengeUrl:       nullableString(job.ChallengeURL),
		ChallengeToken:     nullableString(job.ChallengeToken),
		ChallengeDigest:    nullableDigest(job.ChallengeURL, job.ChallengeDigest),
		ChallengeExpiresAt: nullableTime(job.ChallengeExpires),
		CertificateUrl:     nullableString(job.CertificateURL),
		CertificatePem:     nullableBytes(job.CertificatePEM),
		NotBefore:          nullableTime(job.NotBefore),
		NotAfter:           nullableTime(job.NotAfter),
		RenewAt:            nullableTime(job.RenewAt),
		InstalledAt:        nullableTime(job.InstalledAt),
		ChallengeRemovedAt: nullableTime(job.ChallengeRemoved),
		LastError:          nullableString(job.LastError),
		UpdatedAt:          now.Unix(),
		ID:                 job.ID,
	})
	if err != nil {
		return fmt.Errorf("certificates: save job: %w", err)
	}
	return requireRow(count)
}

func jobFromState(value statedb.CertificateJob, err error) (Job, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, fmt.Errorf("certificates: scan job: %w", err)
	}
	if len(value.CsrHash) != len(Job{}.CSRHash) || len(value.SpkiHash) != len(Job{}.SPKIHash) ||
		(len(value.ChallengeDigest) != 0 && len(value.ChallengeDigest) != len(Job{}.ChallengeDigest)) {
		return Job{}, errors.New("certificates: corrupt job digest")
	}
	job := Job{
		ID:               value.ID,
		RouteID:          value.RouteID,
		Generation:       uint64(value.Generation),
		Hostname:         value.Hostname,
		Profile:          value.Profile,
		State:            value.State,
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
		CreatedAt:        time.Unix(value.CreatedAt, 0).UTC(),
		UpdatedAt:        time.Unix(value.UpdatedAt, 0).UTC(),
	}
	copy(job.CSRHash[:], value.CsrHash)
	copy(job.SPKIHash[:], value.SpkiHash)
	copy(job.ChallengeDigest[:], value.ChallengeDigest)
	return job, nil
}

func accountFromState(value statedb.AcmeAccount) account {
	return account{
		DirectoryURL: value.DirectoryUrl,
		Email:        value.Email,
		KeyDER:       value.KeyDer,
		KID:          value.Kid.String,
		AcceptedTOS:  value.AcceptedTermsUrl.String,
		CreatedAt:    time.Unix(value.CreatedAt, 0).UTC(),
		UpdatedAt:    time.Unix(value.UpdatedAt, 0).UTC(),
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
	return sql.NullInt64{Int64: value.Unix(), Valid: !value.IsZero()}
}

func sqlTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(value.Int64, 0).UTC()
}

func requireRow(count int64) error {
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func certificateID() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("certificates: generate job ID: %w", err)
	}
	return "cert_" + hex.EncodeToString(material[:]), nil
}
