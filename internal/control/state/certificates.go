package state

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

var (
	ErrCertificateIssuanceGated       = errors.New("controlstate: certificate issuance is disabled")
	ErrCertificateIssuanceIdempotency = errors.New("controlstate: certificate issuance idempotency conflict")
	ErrCertificateIssuanceInvalid     = errors.New("controlstate: certificate issuance request is invalid")
	ErrCertificateIssuanceNotFound    = errors.New("controlstate: certificate issuance not found")
)

type ACMEAccount struct {
	ID            string
	DirectoryURL  string
	ContactEmail  string
	AccountKeyDER []byte
	AccountURL    string
	AcceptedTerms string
}

type CertificatePlan struct {
	CacheKey        string                              `json:"cache_key"`
	Scope           string                              `json:"scope"`
	Identifiers     []string                            `json:"identifiers"`
	ChallengeMethod certificateidentity.ChallengeMethod `json:"challenge_method"`
}

type CertificateIssuance struct {
	// new order facts describe a committed insertion, not an idempotent retry.
	NewOrder            bool
	DomainKind          DomainKind
	ID                  string
	ServiceRunID        string
	ServiceID           string
	ServiceRunNumber    uint64
	PublisherIdentityID string
	CertificatePlan     CertificatePlan
	State               ACMEOrderState
	CertificatePEM      string
	RetryAt             *time.Time
	NotBefore           *time.Time
	NotAfter            *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
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
		return d.acmeAccount(ctx, queries, existing)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ACMEAccount{}, fmt.Errorf("controlstate: read ACME account: %w", err)
	}
	accountID, err := opaqueid.New(opaqueid.ACMEAccountPrefix)
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
	}
	keyCiphertext, err := d.sealSecret(acmeAccountKeyContext(accountID), keyDER)
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: encrypt ACME account key: %w", err)
	}
	if existing.ID != "" {
		keyCiphertext = existing.AccountKeyCiphertext
	}
	row, err := queries.EnsureACMEAccount(ctx, controlstatedb.EnsureACMEAccountParams{
		ID: accountID, DirectoryUrl: directoryURL, ContactEmail: contactEmail,
		AccountKeyCiphertext: keyCiphertext, AccountKeyStorageKeyID: d.storageKey.CurrentID(), CreatedAt: timestamptz(now),
	})
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("controlstate: ensure ACME account: %w", err)
	}
	return d.acmeAccount(ctx, queries, row)
}

func validateCertificateCSR(directory, key string, der []byte) ([32]byte, error) {
	if !validStateText(directory) || !validStateText(key) ||
		len(key) > 128 || len(der) == 0 || len(der) > 65536 {
		return [32]byte{}, ErrCertificateIssuanceInvalid
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) == 0 || len(csr.EmailAddresses) != 0 ||
		len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || csr.Subject.String() != "" ||
		!certificateidentity.DNSNamesOnly(csr.Extensions, csr.DNSNames) {
		return [32]byte{}, ErrCertificateIssuanceInvalid
	}
	if _, err := canonicalCertificateIdentifiers(csr.DNSNames); err != nil {
		return [32]byte{}, ErrCertificateIssuanceInvalid
	}
	return sha256.Sum256(der), nil
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

func validInstalledCertificate(order controlstatedb.ControlAcmeOrder, hostname string, now time.Time) bool {
	digest := sha256.Sum256(order.CsrDer)
	if !bytes.Equal(digest[:], order.CsrDigest) || !order.NotBefore.Valid || !order.NotAfter.Valid {
		return false
	}
	leaf, err := certificateidentity.ValidateIssuedCertificate(order.CertificatePem, order.CsrDer, order.CertificateIdentifiers, now)
	return err == nil && leaf.VerifyHostname(hostname) == nil &&
		leaf.NotBefore.Equal(order.NotBefore.Time) && leaf.NotAfter.Equal(order.NotAfter.Time)
}

func loadCertificateIssuance(
	ctx context.Context,
	queries *controlstatedb.Queries,
	order controlstatedb.ControlAcmeOrder,
	now time.Time,
) (CertificateIssuance, error) {
	method := certificateidentity.ChallengeMethod(order.ChallengeMethod)
	state := ACMEOrderState(order.State)
	if !method.Valid() {
		return CertificateIssuance{}, errors.New("controlstate: invalid certificate challenge method")
	}
	if !state.valid() {
		return CertificateIssuance{}, errors.New("controlstate: invalid certificate issuance state")
	}
	result := CertificateIssuance{
		ID: order.ID, ServiceRunID: order.ServiceRunID, ServiceID: order.ServiceID, ServiceRunNumber: uint64(order.ServiceRunNumber),
		CertificatePlan: CertificatePlan{
			CacheKey: order.CertificateCacheKey, Scope: order.CertificateScope,
			Identifiers: slices.Clone(order.CertificateIdentifiers), ChallengeMethod: method,
		},
		State:          state,
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
	return result, nil
}

func (d *Database) acmeAccount(
	ctx context.Context,
	queries *controlstatedb.Queries,
	row controlstatedb.ControlAcmeAccount,
) (ACMEAccount, error) {
	key, previous, err := d.openSecret(row.AccountKeyStorageKeyID, acmeAccountKeyContext(row.ID), row.AccountKeyCiphertext)
	if err != nil {
		return ACMEAccount{}, errors.New("controlstate: ACME account key ciphertext is invalid")
	}
	if previous {
		rotated, err := d.sealSecret(acmeAccountKeyContext(row.ID), key)
		if err != nil {
			return ACMEAccount{}, fmt.Errorf("controlstate: re-encrypt ACME account key: %w", err)
		}
		if err := queries.RotateACMEAccountKey(ctx, controlstatedb.RotateACMEAccountKeyParams{
			AccountKeyCiphertext: rotated, AccountKeyStorageKeyID: d.storageKey.CurrentID(), UpdatedAt: timestamptz(time.Now()),
			AccountID: row.ID, PreviousKeyID: row.AccountKeyStorageKeyID, PreviousCiphertext: row.AccountKeyCiphertext,
		}); err != nil {
			return ACMEAccount{}, fmt.Errorf("controlstate: store re-encrypted ACME account key: %w", err)
		}
	}
	return ACMEAccount{
		ID: row.ID, DirectoryURL: row.DirectoryUrl, ContactEmail: row.ContactEmail,
		AccountKeyDER: key, AccountURL: row.AccountUrl.String,
		AcceptedTerms: row.AcceptedTermsUrl.String,
	}, nil
}
