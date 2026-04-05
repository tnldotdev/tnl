package certificates

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type store struct {
	db  *sql.DB
	now func() time.Time
}

func newStore(db *sql.DB, now func() time.Time) (*store, error) {
	if db == nil {
		return nil, errors.New("certificates: nil state database")
	}
	if now == nil {
		now = time.Now
	}
	return &store{db: db, now: now}, nil
}

func (s *store) loadAccount(ctx context.Context, directoryURL string) (account, error) {
	var result account
	var kid, terms sql.NullString
	var createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT directory_url, email, key_der, kid,
		accepted_terms_url, created_at, updated_at FROM acme_accounts WHERE directory_url = ?`, directoryURL).Scan(
		&result.DirectoryURL, &result.Email, &result.KeyDER, &kid, &terms, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return account{}, ErrNotFound
	}
	if err != nil {
		return account{}, fmt.Errorf("certificates: load ACME account: %w", err)
	}
	result.KID = kid.String
	result.AcceptedTOS = terms.String
	result.CreatedAt = time.Unix(createdAt, 0).UTC()
	result.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return result, nil
}

func (s *store) insertAccount(ctx context.Context, value account) error {
	now := time.Unix(s.now().Unix(), 0).UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO acme_accounts
		(directory_url, email, key_der, kid, accepted_terms_url, created_at, updated_at)
		VALUES (?, ?, ?, NULL, NULL, ?, ?)`, value.DirectoryURL, value.Email, value.KeyDER, now.Unix(), now.Unix())
	if err != nil {
		return fmt.Errorf("certificates: insert ACME account: %w", err)
	}
	return nil
}

func (s *store) updateAccount(ctx context.Context, value account) error {
	now := time.Unix(s.now().Unix(), 0).UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE acme_accounts
		SET email = ?, kid = ?, accepted_terms_url = ?, updated_at = ? WHERE directory_url = ?`,
		value.Email, nullableString(value.KID), nullableString(value.AcceptedTOS), now.Unix(), value.DirectoryURL)
	if err != nil {
		return fmt.Errorf("certificates: update ACME account: %w", err)
	}
	return requireRow(result)
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
	_, err = s.db.ExecContext(ctx, `INSERT INTO certificate_jobs
		(id, route_id, generation, hostname, profile, state, csr_der, csr_hash, spki_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (route_id, generation, csr_hash) DO NOTHING`,
		id, routeID, generation, hostname, profile, StateCreatingOrder, csrDER, csrHash[:], spkiHash[:], now.Unix(), now.Unix())
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
	var hostname string
	err := s.db.QueryRowContext(ctx, `SELECT hostname FROM routes
		WHERE id = ? AND generation = ? AND state = 'active'`, routeID, generation).Scan(&hostname)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidState
	}
	if err != nil {
		return "", fmt.Errorf("certificates: read route: %w", err)
	}
	return hostname, nil
}

func (s *store) getJob(ctx context.Context, id string) (Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, jobSelect+` WHERE id = ?`, id))
}

func (s *store) findBoundJob(ctx context.Context, routeID string, generation uint64, csrHash [32]byte) (Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, jobSelect+`
		WHERE route_id = ? AND generation = ? AND csr_hash = ?`, routeID, generation, csrHash[:]))
}

func (s *store) findResumableJob(ctx context.Context, routeID string, csrHash [32]byte, now time.Time) (Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, jobSelect+`
		WHERE route_id = ? AND csr_hash = ? AND certificate_pem IS NULL
		AND state NOT IN ('succeeded', 'invalid', 'blocked', 'canceled')
		AND (order_expires_at IS NULL OR order_expires_at > ?)
		AND (challenge_expires_at IS NULL OR challenge_expires_at > ?)
		ORDER BY created_at DESC LIMIT 1`, routeID, csrHash[:], now.Unix(), now.Unix()))
}

func (s *store) rebindJob(ctx context.Context, id string, generation uint64) (Job, error) {
	now := time.Unix(s.now().Unix(), 0).UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE certificate_jobs SET generation = ?, updated_at = ? WHERE id = ?`,
		generation, now.Unix(), id)
	if err != nil {
		return Job{}, fmt.Errorf("certificates: rebind job: %w", err)
	}
	if err := requireRow(result); err != nil {
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
	var blocked int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM certificate_jobs WHERE route_id = ? AND generation = ? AND csr_hash != ?
		AND (state NOT IN ('succeeded', 'invalid', 'blocked', 'canceled')
			OR (state = 'succeeded' AND renew_at > ?))
	)`, routeID, generation, csrHash[:], now.Unix()).Scan(&blocked)
	if err != nil {
		return fmt.Errorf("certificates: check active jobs: %w", err)
	}
	if blocked != 0 {
		return ErrInvalidState
	}
	var recent int
	var earliest sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), MIN(created_at) FROM certificate_jobs
		WHERE route_id = ? AND order_attempts > 0 AND created_at >= ?`,
		routeID, now.Add(-time.Hour).Unix()).Scan(&recent, &earliest)
	if err != nil {
		return fmt.Errorf("certificates: count recent jobs: %w", err)
	}
	if recent >= 3 {
		return &RateLimitError{RetryAt: time.Unix(earliest.Int64, 0).UTC().Add(time.Hour)}
	}
	return nil
}

func (s *store) findReusableJob(ctx context.Context, routeID string, csrHash [32]byte, validAfter time.Time) (Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, jobSelect+`
		WHERE route_id = ? AND csr_hash = ? AND certificate_pem IS NOT NULL AND not_after > ?
		AND state IN ('waiting_for_install', 'succeeded') ORDER BY not_after DESC LIMIT 1`,
		routeID, csrHash[:], validAfter.Unix()))
}

func (s *store) saveJob(ctx context.Context, job Job) error {
	now := time.Unix(s.now().Unix(), 0).UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE certificate_jobs SET
		state = ?, order_url = ?, acme_status = ?, order_attempts = ?, order_expires_at = ?, retry_at = ?, authorization_url = ?, finalize_url = ?,
		challenge_url = ?, challenge_token = ?, challenge_digest = ?, challenge_expires_at = ?,
		certificate_url = ?, certificate_pem = ?, not_before = ?, not_after = ?, renew_at = ?,
		installed_at = ?, challenge_removed_at = ?, last_error = ?, updated_at = ? WHERE id = ?`,
		job.State, nullableString(job.OrderURL), nullableString(job.ACMEStatus), job.OrderAttempts, nullableTime(job.OrderExpires), nullableTime(job.RetryAt), nullableString(job.AuthorizationURL), nullableString(job.FinalizeURL),
		nullableString(job.ChallengeURL), nullableString(job.ChallengeToken), nullableDigest(job.ChallengeURL, job.ChallengeDigest), nullableTime(job.ChallengeExpires),
		nullableString(job.CertificateURL), nullableBytes(job.CertificatePEM), nullableTime(job.NotBefore), nullableTime(job.NotAfter), nullableTime(job.RenewAt),
		nullableTime(job.InstalledAt), nullableTime(job.ChallengeRemoved), nullableString(job.LastError), now.Unix(), job.ID)
	if err != nil {
		return fmt.Errorf("certificates: save job: %w", err)
	}
	return requireRow(result)
}

const jobSelect = `SELECT
	id, route_id, generation, hostname, profile, state, csr_der, csr_hash, spki_hash,
	order_url, acme_status, order_attempts, order_expires_at, retry_at, authorization_url, finalize_url, challenge_url, challenge_token,
	challenge_digest, challenge_expires_at, certificate_url, certificate_pem,
	not_before, not_after, renew_at, installed_at, challenge_removed_at, last_error,
	created_at, updated_at FROM certificate_jobs`

type rowScanner interface {
	Scan(...any) error
}

func scanJob(row rowScanner) (Job, error) {
	var job Job
	var orderURL, acmeStatus, authorizationURL, finalizeURL, challengeURL, challengeToken sql.NullString
	var certificateURL, lastError sql.NullString
	var orderExpires, retryAt, challengeExpires, notBefore, notAfter, renewAt, installedAt, challengeRemoved sql.NullInt64
	var csrHash, spkiHash, challengeDigest, certificatePEM []byte
	var createdAt, updatedAt int64
	err := row.Scan(
		&job.ID, &job.RouteID, &job.Generation, &job.Hostname, &job.Profile, &job.State,
		&job.CSRDER, &csrHash, &spkiHash, &orderURL, &acmeStatus, &job.OrderAttempts, &orderExpires, &retryAt, &authorizationURL, &finalizeURL,
		&challengeURL, &challengeToken, &challengeDigest, &challengeExpires, &certificateURL,
		&certificatePEM, &notBefore, &notAfter, &renewAt, &installedAt, &challengeRemoved,
		&lastError, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, fmt.Errorf("certificates: scan job: %w", err)
	}
	if len(csrHash) != len(job.CSRHash) || len(spkiHash) != len(job.SPKIHash) ||
		(len(challengeDigest) != 0 && len(challengeDigest) != len(job.ChallengeDigest)) {
		return Job{}, errors.New("certificates: corrupt job digest")
	}
	copy(job.CSRHash[:], csrHash)
	copy(job.SPKIHash[:], spkiHash)
	copy(job.ChallengeDigest[:], challengeDigest)
	job.OrderURL = orderURL.String
	job.ACMEStatus = acmeStatus.String
	job.OrderExpires = sqlTime(orderExpires)
	job.RetryAt = sqlTime(retryAt)
	job.AuthorizationURL = authorizationURL.String
	job.FinalizeURL = finalizeURL.String
	job.ChallengeURL = challengeURL.String
	job.ChallengeToken = challengeToken.String
	job.ChallengeExpires = sqlTime(challengeExpires)
	job.CertificateURL = certificateURL.String
	job.CertificatePEM = certificatePEM
	job.NotBefore = sqlTime(notBefore)
	job.NotAfter = sqlTime(notAfter)
	job.RenewAt = sqlTime(renewAt)
	job.InstalledAt = sqlTime(installedAt)
	job.ChallengeRemoved = sqlTime(challengeRemoved)
	job.LastError = lastError.String
	job.CreatedAt = time.Unix(createdAt, 0).UTC()
	job.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return job, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableDigest(present string, value [32]byte) any {
	if present == "" {
		return nil
	}
	return value[:]
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.Unix()
}

func sqlTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(value.Int64, 0).UTC()
}

func requireRow(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
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
