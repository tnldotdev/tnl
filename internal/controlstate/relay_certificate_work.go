package controlstate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrRelayCertificateWorkStale   = errors.New("controlstate: relay certificate work lease is stale")
	ErrRelayCertificateWorkInvalid = errors.New("controlstate: relay certificate work is invalid")
)

type RelayCertificateOrderWork struct {
	ID                     string
	Account                ACMEAccount
	RelayServiceID         string
	TLSServerName          string
	PrivateKeyPEM          []byte
	CSRDER                 []byte
	CSRDigest              [32]byte
	State                  RelayCertificateOrderState
	OrderRevision          uint64
	OrderURL               string
	FinalizeURL            string
	CertificateURL         string
	AuthorizationURL       string
	AuthorizationExpiresAt *time.Time
	ChallengeURL           string
	ChallengeToken         string
	ChallengeDigest        [32]byte
	PresentationReference  string
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
}

type RelayDNSChallengeContext struct {
	OrderID               string
	RelayServiceID        string
	TLSServerName         string
	State                 string
	ChallengeDigest       [32]byte
	PresentationReference string
	Presentations         []DNSChallengePresentation
}

// PrepareRelayCertificateOrder schedules managed material at its persisted
// RenewAt.
func (d *Database) PrepareRelayCertificateOrder(
	ctx context.Context,
	accountID string,
	now time.Time,
	failedRetryInterval time.Duration,
) (created bool, retErr error) {
	if !validStateText(accountID) || now.IsZero() || failedRetryInterval <= 0 {
		return false, ErrRelayCertificateWorkInvalid
	}
	if err := d.requireOpen(); err != nil {
		return false, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "prepare relay certificate order", &retErr)()
	queries := controlstatedb.New(tx)
	service, err := queries.ClaimRelayServiceForCertificateOrder(ctx, controlstatedb.ClaimRelayServiceForCertificateOrderParams{
		Now: timestamptz(now), RetryFailedAfter: timestamptz(now.Add(-failedRetryInterval)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("controlstate: prepare relay certificate order: commit empty claim: %w", err)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: claim relay service: %w", err)
	}
	orderID, err := opaqueid.New("relay_certificate_order_")
	if err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: generate ID: %w", err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: generate private key: %w", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: encode private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{service.TlsServerName}}, privateKey)
	if err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: create CSR: %w", err)
	}
	privateKeyCiphertext, err := d.sealSecret(relayCertificateOrderPrivateKeyContext(orderID), privateKeyPEM)
	if err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: encrypt private key: %w", err)
	}
	csrDigest := sha256.Sum256(csrDER)
	if _, err := queries.InsertRelayCertificateOrder(ctx, controlstatedb.InsertRelayCertificateOrderParams{
		ID: orderID, AccountID: accountID, RelayServiceID: service.RelayServiceID, TlsServerName: service.TlsServerName,
		PrivateKeyCiphertext: privateKeyCiphertext, PrivateKeyStorageKeyID: d.storageKey.CurrentID(),
		CsrDer: csrDER, CsrDigest: csrDigest[:], CreatedAt: timestamptz(now),
	}); err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: insert order: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("controlstate: prepare relay certificate order: commit: %w", err)
	}
	return true, nil
}

func (d *Database) ClaimRelayCertificateOrderWork(
	ctx context.Context,
	workerID string,
	now time.Time,
	leaseDuration time.Duration,
) (work RelayCertificateOrderWork, found bool, retErr error) {
	if !validStateText(workerID) || now.IsZero() || leaseDuration <= 0 {
		return RelayCertificateOrderWork{}, false, ErrRelayCertificateWorkInvalid
	}
	if err := d.requireOpen(); err != nil {
		return RelayCertificateOrderWork{}, false, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RelayCertificateOrderWork{}, false, fmt.Errorf("controlstate: claim relay certificate work: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "claim relay certificate work", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.ClaimRelayCertificateOrderWork(ctx, controlstatedb.ClaimRelayCertificateOrderWorkParams{
		WorkOwner: text(workerID), WorkExpiresAt: timestamptz(now.Add(leaseDuration)), ClaimedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return RelayCertificateOrderWork{}, false, fmt.Errorf("controlstate: claim relay certificate work: commit empty claim: %w", err)
		}
		return RelayCertificateOrderWork{}, false, nil
	}
	if err != nil {
		return RelayCertificateOrderWork{}, false, fmt.Errorf("controlstate: claim relay certificate work: %w", err)
	}
	account, err := d.getACMEAccountByID(ctx, tx, row.AccountID)
	if err != nil {
		return RelayCertificateOrderWork{}, false, err
	}
	work, err = d.relayCertificateOrderWork(ctx, queries, row, account, true)
	if err != nil {
		return RelayCertificateOrderWork{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RelayCertificateOrderWork{}, false, fmt.Errorf("controlstate: claim relay certificate work: commit: %w", err)
	}
	return work, true, nil
}

func (d *Database) SaveRelayCertificateOrderWork(
	ctx context.Context,
	work RelayCertificateOrderWork,
	now time.Time,
) (result RelayCertificateOrderWork, retErr error) {
	if err := validateRelayCertificateOrderWork(work); err != nil || now.IsZero() {
		return RelayCertificateOrderWork{}, ErrRelayCertificateWorkInvalid
	}
	if err := d.requireOpen(); err != nil {
		return RelayCertificateOrderWork{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RelayCertificateOrderWork{}, fmt.Errorf("controlstate: save relay certificate work: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "save relay certificate work", &retErr)()
	queries := controlstatedb.New(tx)
	// preparation locks the service before inserting an order. completion must
	// use the same order before updating both the order and installed material.
	if _, err := queries.LockRelayServiceForCertificate(ctx, work.RelayServiceID); errors.Is(err, pgx.ErrNoRows) {
		return RelayCertificateOrderWork{}, ErrRelayCertificateWorkInvalid
	} else if err != nil {
		return RelayCertificateOrderWork{}, fmt.Errorf("controlstate: save relay certificate work: lock service: %w", err)
	}
	row, err := queries.SaveRelayCertificateOrderWork(ctx, controlstatedb.SaveRelayCertificateOrderWorkParams{
		State: string(work.State), OrderUrl: nullableText(work.OrderURL), FinalizeUrl: nullableText(work.FinalizeURL),
		CertificateUrl: nullableText(work.CertificateURL), AuthorizationUrl: nullableText(work.AuthorizationURL),
		AuthorizationExpiresAt: nullableTime(work.AuthorizationExpiresAt),
		ChallengeUrl:           nullableText(work.ChallengeURL), ChallengeToken: nullableText(work.ChallengeToken),
		ChallengeDigest:       nullableBytes(work.ChallengeDigest[:], work.AuthorizationURL != ""),
		PresentationReference: nullableText(work.PresentationReference), CertificatePem: nullableBytes(work.CertificatePEM, len(work.CertificatePEM) != 0),
		NotBefore: nullableTime(work.NotBefore), NotAfter: nullableTime(work.NotAfter), RenewAt: nullableTime(work.RenewAt),
		AvailableAt: timestamptz(work.AvailableAt), LastError: nullableText(work.LastError), CompletedAt: timestamptz(now),
		OrderID: work.ID, WorkOwner: text(work.WorkerID), WorkEpoch: positive(work.WorkEpoch),
		ExpectedOrderRevision: positive(work.OrderRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayCertificateOrderWork{}, ErrRelayCertificateWorkStale
	}
	if err != nil {
		return RelayCertificateOrderWork{}, fmt.Errorf("controlstate: save relay certificate work: %w", err)
	}
	if work.State == "complete" {
		if err := validateRelayCertificateMaterial(work, now); err != nil {
			return RelayCertificateOrderWork{}, err
		}
		privateKeyCiphertext, err := d.sealSecret(relayTransportPrivateKeyContext(work.RelayServiceID), work.PrivateKeyPEM)
		if err != nil {
			return RelayCertificateOrderWork{}, fmt.Errorf("controlstate: save relay certificate work: encrypt installed key: %w", err)
		}
		leaf, _ := relayCertificateLeaf(work.CertificatePEM, work.PrivateKeyPEM)
		if _, err := queries.StoreRelayTransportCertificate(ctx, controlstatedb.StoreRelayTransportCertificateParams{
			TransportCertificatePem: text(string(work.CertificatePEM)), TransportPrivateKeyCiphertext: privateKeyCiphertext,
			TransportPrivateKeyStorageKeyID: text(d.storageKey.CurrentID()), TransportCertificateSerial: text(leaf.SerialNumber.String()),
			TransportCertificateExpiresAt: timestamptz(leaf.NotAfter), UpdatedAt: timestamptz(now),
			RelayServiceID: work.RelayServiceID, TlsServerName: work.TLSServerName,
		}); err != nil {
			return RelayCertificateOrderWork{}, fmt.Errorf("controlstate: save relay certificate work: install certificate: %w", err)
		}
	}
	account, err := d.getACMEAccountByID(ctx, tx, row.AccountID)
	if err != nil {
		return RelayCertificateOrderWork{}, err
	}
	result, err = d.relayCertificateOrderWork(ctx, queries, row, account, false)
	if err != nil {
		return RelayCertificateOrderWork{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RelayCertificateOrderWork{}, fmt.Errorf("controlstate: save relay certificate work: commit: %w", err)
	}
	return result, nil
}

func (d *Database) GetRelayDNSChallengeContext(ctx context.Context, orderID string) (RelayDNSChallengeContext, error) {
	if !validStateText(orderID) {
		return RelayDNSChallengeContext{}, ErrRelayCertificateWorkInvalid
	}
	if err := d.requireOpen(); err != nil {
		return RelayDNSChallengeContext{}, err
	}
	queries := controlstatedb.New(d.pool)
	row, err := queries.GetRelayDNSChallengeContext(ctx, orderID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayDNSChallengeContext{}, ErrRelayCertificateWorkInvalid
	}
	if err != nil {
		return RelayDNSChallengeContext{}, fmt.Errorf("controlstate: get relay DNS challenge context: %w", err)
	}
	if len(row.ChallengeDigest) != 32 || !validStateText(row.PresentationReference.String) {
		return RelayDNSChallengeContext{}, errors.New("controlstate: invalid relay DNS challenge context row")
	}
	rows, err := queries.ListRelayDNSChallengePresentations(ctx, row.TlsServerName)
	if err != nil {
		return RelayDNSChallengeContext{}, fmt.Errorf("controlstate: list relay DNS challenge presentations: %w", err)
	}
	result := RelayDNSChallengeContext{
		OrderID: row.ID, RelayServiceID: row.RelayServiceID, TLSServerName: row.TlsServerName,
		State: row.State, PresentationReference: row.PresentationReference.String,
		Presentations: make([]DNSChallengePresentation, len(rows)),
	}
	copy(result.ChallengeDigest[:], row.ChallengeDigest)
	for index, presentation := range rows {
		if len(presentation.ChallengeDigest) != 32 {
			return RelayDNSChallengeContext{}, errors.New("controlstate: invalid relay DNS presentation row")
		}
		copy(result.Presentations[index].ChallengeDigest[:], presentation.ChallengeDigest)
		result.Presentations[index].Active = presentation.State == "authorizing" || presentation.State == "presenting" ||
			presentation.State == "presented" || presentation.State == "validating" ||
			presentation.State == "ready_to_finalize" || presentation.State == "finalizing"
	}
	return result, nil
}

func (d *Database) relayCertificateOrderWork(
	ctx context.Context,
	queries *controlstatedb.Queries,
	row controlstatedb.ControlRelayCertificateOrder,
	account ACMEAccount,
	requireLease bool,
) (RelayCertificateOrderWork, error) {
	if row.OrderRevision <= 0 || row.WorkEpoch <= 0 || row.Attempts <= 0 || !row.AvailableAt.Valid ||
		!row.CreatedAt.Valid || !row.UpdatedAt.Valid || len(row.CsrDigest) != 32 ||
		requireLease && (!row.WorkOwner.Valid || !row.WorkExpiresAt.Valid) {
		return RelayCertificateOrderWork{}, errors.New("controlstate: invalid relay certificate work row")
	}
	privateKey, previous, err := d.openSecret(
		row.PrivateKeyStorageKeyID, relayCertificateOrderPrivateKeyContext(row.ID), row.PrivateKeyCiphertext,
	)
	if err != nil {
		return RelayCertificateOrderWork{}, errors.New("controlstate: relay certificate order private key ciphertext is invalid")
	}
	if previous {
		rotated, err := d.sealSecret(relayCertificateOrderPrivateKeyContext(row.ID), privateKey)
		if err != nil {
			return RelayCertificateOrderWork{}, err
		}
		if err := queries.RotateRelayCertificateOrderPrivateKey(ctx, controlstatedb.RotateRelayCertificateOrderPrivateKeyParams{
			PrivateKeyCiphertext: rotated, PrivateKeyStorageKeyID: d.storageKey.CurrentID(), UpdatedAt: timestamptz(time.Now()),
			OrderID: row.ID, PreviousKeyID: row.PrivateKeyStorageKeyID, PreviousCiphertext: row.PrivateKeyCiphertext,
		}); err != nil {
			return RelayCertificateOrderWork{}, fmt.Errorf("controlstate: rotate relay certificate order private key: %w", err)
		}
	}
	work := RelayCertificateOrderWork{
		ID: row.ID, Account: account, RelayServiceID: row.RelayServiceID, TLSServerName: row.TlsServerName,
		PrivateKeyPEM: privateKey, CSRDER: slices.Clone(row.CsrDer), State: RelayCertificateOrderState(row.State),
		OrderRevision: uint64(row.OrderRevision), OrderURL: row.OrderUrl.String, FinalizeURL: row.FinalizeUrl.String,
		CertificateURL: row.CertificateUrl.String, AuthorizationURL: row.AuthorizationUrl.String,
		AuthorizationExpiresAt: optionalTime(row.AuthorizationExpiresAt),
		ChallengeURL:           row.ChallengeUrl.String, ChallengeToken: row.ChallengeToken.String,
		PresentationReference: row.PresentationReference.String, CertificatePEM: slices.Clone(row.CertificatePem),
		NotBefore: optionalTime(row.NotBefore), NotAfter: optionalTime(row.NotAfter), RenewAt: optionalTime(row.RenewAt),
		Attempts: uint64(row.Attempts), AvailableAt: row.AvailableAt.Time, LastError: row.LastError.String,
		CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time, WorkerID: row.WorkOwner.String,
		WorkEpoch: uint64(row.WorkEpoch), WorkExpiresAt: row.WorkExpiresAt.Time,
	}
	if !work.State.valid() {
		return RelayCertificateOrderWork{}, errors.New("controlstate: invalid relay certificate order state")
	}
	copy(work.CSRDigest[:], row.CsrDigest)
	if len(row.ChallengeDigest) == 32 {
		copy(work.ChallengeDigest[:], row.ChallengeDigest)
	}
	return work, nil
}

func validateRelayCertificateOrderWork(work RelayCertificateOrderWork) error {
	validState := work.State.valid()
	hasChallenge := work.ChallengeURL != "" || work.ChallengeToken != "" || work.ChallengeDigest != ([32]byte{}) ||
		work.PresentationReference != ""
	challengeComplete := validStateText(work.AuthorizationURL) && validStateText(work.ChallengeURL) &&
		validStateText(work.ChallengeToken) && work.ChallengeDigest != ([32]byte{}) && validStateText(work.PresentationReference)
	if !validStateText(work.ID) || !validStateText(work.RelayServiceID) || !validStateText(work.TLSServerName) ||
		len(work.PrivateKeyPEM) == 0 || len(work.CSRDER) == 0 || work.CSRDigest == ([32]byte{}) || !validState ||
		work.OrderRevision == 0 || work.OrderRevision > math.MaxInt64 || work.Attempts == 0 || work.Attempts > math.MaxInt64 ||
		work.AvailableAt.IsZero() || len(work.LastError) > 1024 || !validStateText(work.WorkerID) ||
		work.WorkEpoch == 0 || work.WorkEpoch > math.MaxInt64 || work.WorkExpiresAt.IsZero() ||
		work.AuthorizationExpiresAt != nil && work.AuthorizationExpiresAt.IsZero() ||
		hasChallenge && !challengeComplete {
		return ErrRelayCertificateWorkInvalid
	}
	return nil
}

func validateRelayCertificateMaterial(work RelayCertificateOrderWork, now time.Time) error {
	leaf, err := relayCertificateLeaf(work.CertificatePEM, work.PrivateKeyPEM)
	if err != nil || leaf.VerifyHostname(work.TLSServerName) != nil || !certificateidentity.DNSNamesOnly(leaf.Extensions, leaf.DNSNames) ||
		len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != work.TLSServerName || leaf.IsCA ||
		work.NotBefore == nil || work.NotAfter == nil || work.RenewAt == nil ||
		!leaf.NotBefore.Equal(*work.NotBefore) || !leaf.NotAfter.Equal(*work.NotAfter) || !leaf.NotAfter.After(now) ||
		leaf.NotBefore.After(now) || !work.RenewAt.After(leaf.NotBefore) || !work.RenewAt.Before(leaf.NotAfter) {
		return ErrRelayCertificateWorkInvalid
	}
	return nil
}

func relayCertificateLeaf(certificatePEM, privateKeyPEM []byte) (*x509.Certificate, error) {
	keyPair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(keyPair.Certificate) == 0 {
		return nil, ErrRelayCertificateWorkInvalid
	}
	return x509.ParseCertificate(keyPair.Certificate[0])
}

func nullableBytes(value []byte, valid bool) []byte {
	if !valid {
		return nil
	}
	return slices.Clone(value)
}
