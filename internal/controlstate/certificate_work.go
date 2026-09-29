package controlstate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var ErrACMEWorkStale = errors.New("controlstate: ACME work lease is stale")

type ACMEAuthorizationWork struct {
	ID                    string
	Identifier            string
	AuthorizationURL      string
	ChallengeType         string
	ChallengeURL          string
	ChallengeToken        string
	ChallengeDigest       [32]byte
	PresentationReference string
	State                 string
	Revision              uint64
	Attempts              uint64
	AvailableAt           time.Time
	PresentedAt           *time.Time
	ValidatedAt           *time.Time
	CleanupCompletedAt    *time.Time
	ExpiresAt             *time.Time
	LastError             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type ACMEOrderWork struct {
	ID                     string
	Account                ACMEAccount
	PublishRunID           string
	PublicURLID            string
	PublishRunNumber       uint64
	CertificateCacheKey    string
	CertificateScope       string
	CertificateIdentifiers []string
	ChallengeMethod        string
	CSRDER                 []byte
	CSRDigest              [32]byte
	State                  string
	OrderRevision          uint64
	OrderURL               string
	FinalizeURL            string
	CertificateURL         string
	CertificatePEM         []byte
	NotBefore              *time.Time
	NotAfter               *time.Time
	RenewAt                *time.Time
	Attempts               uint64
	AvailableAt            time.Time
	LastError              string
	CreatedAt              time.Time
	UpdatedAt              time.Time
	WorkerID               string
	WorkEpoch              uint64
	WorkExpiresAt          time.Time
	Authorizations         []ACMEAuthorizationWork
}

func (d *Database) UpdateACMEAccountRegistration(
	ctx context.Context,
	accountID string,
	contactEmail string,
	accountURL string,
	acceptedTermsURL string,
	now time.Time,
) (ACMEAccount, error) {
	if !validStateText(accountID) || !validStateText(contactEmail) || !validStateText(accountURL) ||
		acceptedTermsURL != "" && !validStateText(acceptedTermsURL) {
		return ACMEAccount{}, ErrCertificateIssuanceInvalid
	}
	if err := d.requireOpen(); err != nil {
		return ACMEAccount{}, err
	}
	row, err := controlstatedb.New(d.pool).UpdateACMEAccountRegistration(ctx, controlstatedb.UpdateACMEAccountRegistrationParams{
		ContactEmail: contactEmail, AccountUrl: text(accountURL), AcceptedTermsUrl: nullableText(acceptedTermsURL),
		UpdatedAt: timestamptz(now), AccountID: accountID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEAccount{}, ErrCertificateIssuanceInvalid
	}
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: update ACME account registration: %w", err)
	}
	return d.acmeAccount(ctx, controlstatedb.New(d.pool), row)
}

func (d *Database) ClaimACMEOrderWork(
	ctx context.Context,
	workerID string,
	now time.Time,
	leaseDuration time.Duration,
) (work ACMEOrderWork, found bool, retErr error) {
	if !validStateText(workerID) || leaseDuration <= 0 {
		return ACMEOrderWork{}, false, ErrCertificateIssuanceInvalid
	}
	if err := d.requireOpen(); err != nil {
		return ACMEOrderWork{}, false, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ACMEOrderWork{}, false, fmt.Errorf("controlstate: claim ACME order work: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "claim ACME order work", &retErr)()
	queries := controlstatedb.New(tx)
	order, err := queries.ClaimACMEOrderWork(ctx, controlstatedb.ClaimACMEOrderWorkParams{
		WorkOwner: text(workerID), WorkExpiresAt: timestamptz(now.Add(leaseDuration)), ClaimedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return ACMEOrderWork{}, false, fmt.Errorf("controlstate: claim ACME order work: commit empty claim: %w", err)
		}
		return ACMEOrderWork{}, false, nil
	}
	if err != nil {
		return ACMEOrderWork{}, false, fmt.Errorf("controlstate: claim ACME order work: claim order: %w", err)
	}
	account, err := d.getACMEAccountByID(ctx, tx, order.AccountID)
	if err != nil {
		return ACMEOrderWork{}, false, err
	}
	authorizations, err := queries.ListACMEOrderAuthorizations(ctx, order.ID)
	if err != nil {
		return ACMEOrderWork{}, false, fmt.Errorf("controlstate: claim ACME order work: list authorizations: %w", err)
	}
	work, err = acmeOrderWork(order, account, authorizations, true)
	if err != nil {
		return ACMEOrderWork{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ACMEOrderWork{}, false, fmt.Errorf("controlstate: claim ACME order work: commit: %w", err)
	}
	return work, true, nil
}

func (d *Database) ACMEChallengeRoutingReady(ctx context.Context, issuanceID string, now time.Time) (bool, error) {
	if !validStateText(issuanceID) {
		return false, ErrCertificateIssuanceInvalid
	}
	if err := d.requireOpen(); err != nil {
		return false, err
	}
	ready, err := controlstatedb.New(d.pool).CheckACMEChallengeRoutingReady(ctx, controlstatedb.CheckACMEChallengeRoutingReadyParams{
		IssuanceID: issuanceID, CheckedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("controlstate: check ACME challenge routing: %w", err)
	}
	return ready, nil
}

func (d *Database) SaveACMEOrderWork(
	ctx context.Context,
	work ACMEOrderWork,
	now time.Time,
) (result ACMEOrderWork, retErr error) {
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ChallengeType == "dns-01" && authorization.PresentationReference == "" {
			var err error
			authorization.PresentationReference, err = opaqueid.New("acme_presentation_")
			if err != nil {
				return ACMEOrderWork{}, fmt.Errorf("controlstate: generate ACME presentation reference: %w", err)
			}
		}
	}
	if err := validateACMEOrderWork(work); err != nil {
		return ACMEOrderWork{}, err
	}
	if err := d.requireOpen(); err != nil {
		return ACMEOrderWork{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ACMEOrderWork{}, fmt.Errorf("controlstate: save ACME order work: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "save ACME order work", &retErr)()
	queries := controlstatedb.New(tx)
	order, err := queries.SaveACMEOrderWork(ctx, controlstatedb.SaveACMEOrderWorkParams{
		State: work.State, OrderUrl: nullableText(work.OrderURL), FinalizeUrl: nullableText(work.FinalizeURL),
		CertificateUrl: nullableText(work.CertificateURL), CertificatePem: slices.Clone(work.CertificatePEM),
		NotBefore: nullableTime(work.NotBefore), NotAfter: nullableTime(work.NotAfter), RenewAt: nullableTime(work.RenewAt),
		AvailableAt: timestamptz(work.AvailableAt), LastError: nullableText(work.LastError),
		CompletedAt: timestamptz(now), IssuanceID: work.ID, WorkOwner: text(work.WorkerID),
		WorkEpoch: positive(work.WorkEpoch), ExpectedOrderRevision: positive(work.OrderRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEOrderWork{}, ErrACMEWorkStale
	}
	if err != nil {
		return ACMEOrderWork{}, fmt.Errorf("controlstate: save ACME order work: update order: %w", err)
	}
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ID == "" {
			authorization.ID, err = opaqueid.New("acme_authorization_")
			if err != nil {
				return ACMEOrderWork{}, fmt.Errorf("controlstate: generate ACME authorization ID: %w", err)
			}
		}
		createdAt := authorization.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		var challengeDigest []byte
		if authorization.ChallengeType != "" {
			challengeDigest = authorization.ChallengeDigest[:]
		}
		if _, err := queries.SaveACMEAuthorizationWork(ctx, controlstatedb.SaveACMEAuthorizationWorkParams{
			ID: authorization.ID, OrderID: work.ID, Identifier: authorization.Identifier,
			AuthorizationUrl: authorization.AuthorizationURL, ChallengeType: nullableText(authorization.ChallengeType),
			ChallengeUrl: nullableText(authorization.ChallengeURL), ChallengeToken: nullableText(authorization.ChallengeToken),
			ChallengeDigest: challengeDigest, PresentationReference: nullableText(authorization.PresentationReference),
			State:                 authorization.State,
			AuthorizationRevision: positive(max(authorization.Revision, 1)), Attempts: nonnegative(authorization.Attempts),
			AvailableAt: timestamptz(authorization.AvailableAt), PresentedAt: nullableTime(authorization.PresentedAt),
			ValidatedAt: nullableTime(authorization.ValidatedAt), CleanupCompletedAt: nullableTime(authorization.CleanupCompletedAt),
			ExpiresAt: nullableTime(authorization.ExpiresAt), LastError: nullableText(authorization.LastError),
			CreatedAt: timestamptz(createdAt), UpdatedAt: timestamptz(now),
			ExpectedAuthorizationRevision: nonnegative(authorization.Revision),
		}); errors.Is(err, pgx.ErrNoRows) {
			return ACMEOrderWork{}, ErrACMEWorkStale
		} else if err != nil {
			return ACMEOrderWork{}, fmt.Errorf("controlstate: save ACME order work: update authorization: %w", err)
		}
	}
	account, err := d.getACMEAccountByID(ctx, tx, order.AccountID)
	if err != nil {
		return ACMEOrderWork{}, err
	}
	authorizations, err := queries.ListACMEOrderAuthorizations(ctx, order.ID)
	if err != nil {
		return ACMEOrderWork{}, fmt.Errorf("controlstate: save ACME order work: reload authorizations: %w", err)
	}
	result, err = acmeOrderWork(order, account, authorizations, false)
	if err != nil {
		return ACMEOrderWork{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ACMEOrderWork{}, fmt.Errorf("controlstate: save ACME order work: commit: %w", err)
	}
	return result, nil
}

func (d *Database) getACMEAccountByID(ctx context.Context, db controlstatedb.DBTX, accountID string) (ACMEAccount, error) {
	var account controlstatedb.ControlAcmeAccount
	err := db.QueryRow(ctx, `
		SELECT id, directory_url, contact_email, account_key_ciphertext, account_key_storage_key_id, account_url,
			accepted_terms_url, created_at, updated_at
		FROM control.acme_accounts
		WHERE id = $1
	`, accountID).Scan(
		&account.ID, &account.DirectoryUrl, &account.ContactEmail, &account.AccountKeyCiphertext, &account.AccountKeyStorageKeyID,
		&account.AccountUrl, &account.AcceptedTermsUrl, &account.CreatedAt, &account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEAccount{}, errors.New("controlstate: ACME work references a missing account")
	}
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: read ACME work account: %w", err)
	}
	return d.acmeAccount(ctx, controlstatedb.New(db), account)
}

func acmeOrderWork(
	order controlstatedb.ControlAcmeOrder,
	account ACMEAccount,
	authorizations []controlstatedb.ControlAcmeAuthorization,
	requireLease bool,
) (ACMEOrderWork, error) {
	if order.PublishRunNumber <= 0 || order.OrderRevision <= 0 || order.WorkEpoch <= 0 ||
		requireLease && (!order.WorkOwner.Valid || !order.WorkExpiresAt.Valid) ||
		order.Attempts <= 0 || !order.AvailableAt.Valid || !order.CreatedAt.Valid || !order.UpdatedAt.Valid ||
		len(order.CsrDigest) != 32 {
		return ACMEOrderWork{}, errors.New("controlstate: invalid ACME order work row")
	}
	work := ACMEOrderWork{
		ID: order.ID, Account: account, PublishRunID: order.PublishRunID,
		PublicURLID: order.PublicURLID, PublishRunNumber: uint64(order.PublishRunNumber), CertificateCacheKey: order.CertificateCacheKey,
		CertificateScope: order.CertificateScope, CertificateIdentifiers: slices.Clone(order.CertificateIdentifiers),
		ChallengeMethod: order.ChallengeMethod, CSRDER: slices.Clone(order.CsrDer), State: order.State,
		OrderRevision: uint64(order.OrderRevision), OrderURL: order.OrderUrl.String, FinalizeURL: order.FinalizeUrl.String,
		CertificateURL: order.CertificateUrl.String, CertificatePEM: slices.Clone(order.CertificatePem),
		Attempts: uint64(order.Attempts), AvailableAt: order.AvailableAt.Time, LastError: order.LastError.String,
		CreatedAt: order.CreatedAt.Time, UpdatedAt: order.UpdatedAt.Time,
		WorkerID: order.WorkOwner.String, WorkEpoch: uint64(order.WorkEpoch), WorkExpiresAt: order.WorkExpiresAt.Time,
		Authorizations: make([]ACMEAuthorizationWork, len(authorizations)),
	}
	copy(work.CSRDigest[:], order.CsrDigest)
	work.NotBefore = optionalTime(order.NotBefore)
	work.NotAfter = optionalTime(order.NotAfter)
	work.RenewAt = optionalTime(order.RenewAt)
	for index, authorization := range authorizations {
		if authorization.ChallengeType.Valid && len(authorization.ChallengeDigest) != 32 ||
			!authorization.ChallengeType.Valid && len(authorization.ChallengeDigest) != 0 ||
			authorization.AuthorizationRevision <= 0 || authorization.Attempts < 0 ||
			!authorization.AvailableAt.Valid || !authorization.CreatedAt.Valid || !authorization.UpdatedAt.Valid {
			return ACMEOrderWork{}, errors.New("controlstate: invalid ACME authorization work row")
		}
		value := ACMEAuthorizationWork{
			ID: authorization.ID, Identifier: authorization.Identifier, AuthorizationURL: authorization.AuthorizationUrl,
			ChallengeType: authorization.ChallengeType.String, ChallengeURL: authorization.ChallengeUrl.String,
			ChallengeToken: authorization.ChallengeToken.String, PresentationReference: authorization.PresentationReference.String,
			State:    authorization.State,
			Revision: uint64(authorization.AuthorizationRevision), Attempts: uint64(authorization.Attempts),
			AvailableAt: authorization.AvailableAt.Time, PresentedAt: optionalTime(authorization.PresentedAt),
			ValidatedAt: optionalTime(authorization.ValidatedAt), CleanupCompletedAt: optionalTime(authorization.CleanupCompletedAt),
			ExpiresAt: optionalTime(authorization.ExpiresAt), LastError: authorization.LastError.String,
			CreatedAt: authorization.CreatedAt.Time, UpdatedAt: authorization.UpdatedAt.Time,
		}
		copy(value.ChallengeDigest[:], authorization.ChallengeDigest)
		if err := validateACMEAuthorizationWork(value); err != nil {
			return ACMEOrderWork{}, err
		}
		work.Authorizations[index] = value
	}
	return work, nil
}

func validateACMEOrderWork(work ACMEOrderWork) error {
	_, workEpochOK := positiveInt64(work.WorkEpoch)
	_, orderRevisionOK := positiveInt64(work.OrderRevision)
	_, attemptsOK := nonnegativeInt64(work.Attempts)
	if !validStateText(work.ID) || !validStateText(work.WorkerID) || !workEpochOK || !orderRevisionOK || !attemptsOK ||
		work.WorkExpiresAt.IsZero() ||
		work.State != "pending" && work.State != "authorizing" && work.State != "ready_to_finalize" &&
			work.State != "finalizing" && work.State != "waiting_for_install" && work.State != "installed" &&
			work.State != "failed" && work.State != "canceled" ||
		work.AvailableAt.IsZero() || len(work.LastError) > 1024 {
		return ErrCertificateIssuanceInvalid
	}
	identifiers := make(map[string]bool, len(work.Authorizations))
	urls := make(map[string]bool, len(work.Authorizations))
	for _, authorization := range work.Authorizations {
		if err := validateACMEAuthorizationWork(authorization); err != nil {
			return err
		}
		if !slices.Contains(work.CertificateIdentifiers, authorization.Identifier) ||
			identifiers[authorization.Identifier] || urls[authorization.AuthorizationURL] {
			return ErrCertificateIssuanceInvalid
		}
		identifiers[authorization.Identifier], urls[authorization.AuthorizationURL] = true, true
	}
	if len(work.Authorizations) != 0 && len(work.Authorizations) != len(work.CertificateIdentifiers) {
		return ErrCertificateIssuanceInvalid
	}
	return nil
}

func validateACMEAuthorizationWork(authorization ACMEAuthorizationWork) error {
	_, revisionOK := nonnegativeInt64(authorization.Revision)
	_, attemptsOK := nonnegativeInt64(authorization.Attempts)
	if !validStateText(authorization.Identifier) || !validStateText(authorization.AuthorizationURL) ||
		!revisionOK || !attemptsOK || authorization.State == "" || authorization.AvailableAt.IsZero() ||
		len(authorization.LastError) > 1024 {
		return ErrCertificateIssuanceInvalid
	}
	if authorization.ChallengeType == "" {
		if authorization.State != "complete" || authorization.ValidatedAt == nil || authorization.CleanupCompletedAt == nil ||
			authorization.PresentedAt != nil || authorization.Attempts != 0 || authorization.ExpiresAt == nil ||
			!authorization.ExpiresAt.After(*authorization.ValidatedAt) || authorization.ChallengeURL != "" ||
			authorization.ChallengeToken != "" || authorization.ChallengeDigest != ([32]byte{}) || authorization.PresentationReference != "" {
			return ErrCertificateIssuanceInvalid
		}
	} else if !validStateText(authorization.ChallengeURL) || !validStateText(authorization.ChallengeToken) ||
		authorization.ChallengeType != "tls-alpn-01" && authorization.ChallengeType != "dns-01" ||
		(authorization.ChallengeType == "dns-01") != validStateText(authorization.PresentationReference) {
		return ErrCertificateIssuanceInvalid
	}
	return nil
}

func nullableTime(value *time.Time) pgtype.Timestamptz {
	if value == nil {
		return pgtype.Timestamptz{}
	}
	return timestamptz(*value)
}

func optionalTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time
	return &result
}

func nonnegative(value uint64) int64 {
	if value > uint64(^uint64(0)>>1) {
		return int64(^uint64(0) >> 1)
	}
	return int64(value)
}
