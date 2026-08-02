package controlstate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var (
	ErrRelayServiceCertificateInvalid    = errors.New("controlstate: relay transport certificate is invalid")
	ErrRelayServiceCertificateNotFound   = errors.New("controlstate: relay transport certificate is not available")
	ErrRelayServiceCertificateLeaseStale = errors.New("controlstate: relay transport certificate lease is stale")
)

// RelayServiceCertificate contains a relay transport certificate and private
// key. It is returned only to a relay process with a current lease for the
// matching relay service.
type RelayServiceCertificate struct {
	RelayServiceID string
	TLSServerName  string
	CertificatePEM string
	PrivateKeyPEM  string
	Serial         string
	NotAfter       time.Time
}

// StoreRelayServiceCertificate validates and encrypts a new relay transport
// certificate and private key before storing them in PostgreSQL.
func (d *Database) StoreRelayServiceCertificate(
	ctx context.Context,
	relayServiceID, tlsServerName string,
	certificatePEM, privateKeyPEM []byte,
	now time.Time,
) (RelayServiceCertificate, error) {
	if !validStateText(relayServiceID) || !validStateText(tlsServerName) || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return RelayServiceCertificate{}, ErrRelayServiceCertificateInvalid
	}
	if err := d.requireOpen(); err != nil {
		return RelayServiceCertificate{}, err
	}
	keyPair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(keyPair.Certificate) == 0 {
		return RelayServiceCertificate{}, ErrRelayServiceCertificateInvalid
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil || leaf.VerifyHostname(tlsServerName) != nil || !leaf.NotAfter.After(now) {
		return RelayServiceCertificate{}, ErrRelayServiceCertificateInvalid
	}
	privateKeyCiphertext, err := d.sealSecret(relayTransportPrivateKeyContext(relayServiceID), privateKeyPEM)
	if err != nil {
		return RelayServiceCertificate{}, fmt.Errorf("controlstate: encrypt relay transport private key: %w", err)
	}
	row, err := controlstatedb.New(d.pool).StoreRelayServiceCertificate(ctx, controlstatedb.StoreRelayServiceCertificateParams{
		TransportCertificatePem: text(string(certificatePEM)), TransportPrivateKeyCiphertext: privateKeyCiphertext,
		TransportPrivateKeyStorageKeyID: text(d.storageKey.CurrentID()), TransportCertificateSerial: text(leaf.SerialNumber.String()),
		TransportCertificateExpiresAt: timestamptz(leaf.NotAfter), UpdatedAt: timestamptz(now),
		RelayServiceID: relayServiceID, TlsServerName: tlsServerName,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayServiceCertificate{}, ErrRelayServiceCertificateNotFound
	}
	if err != nil {
		return RelayServiceCertificate{}, fmt.Errorf("controlstate: store relay transport certificate: %w", err)
	}
	return relayServiceCertificate(ctx, d, controlstatedb.New(d.pool), row)
}

// GetRelayServiceCertificate returns decrypted material only while the exact
// requesting relay process lease is current.
func (d *Database) GetRelayServiceCertificate(
	ctx context.Context,
	identity RelayLeaseIdentity,
	now time.Time,
) (RelayServiceCertificate, error) {
	if err := validateRelayLeaseIdentity(identity); err != nil {
		return RelayServiceCertificate{}, err
	}
	if err := d.requireOpen(); err != nil {
		return RelayServiceCertificate{}, err
	}
	revision, _ := positiveInt64(identity.RelayLeaseRevision)
	queries := controlstatedb.New(d.pool)
	row, err := queries.GetRelayServiceCertificate(ctx, controlstatedb.GetRelayServiceCertificateParams{
		RelayServiceID: identity.RelayServiceID, Now: timestamptz(now), RelayID: identity.RelayID,
		RelayRunID: identity.RelayRunID, RelayLeaseRevision: revision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayServiceCertificate{}, ErrRelayServiceCertificateLeaseStale
	}
	if err != nil {
		return RelayServiceCertificate{}, fmt.Errorf("controlstate: get relay transport certificate: %w", err)
	}
	if !row.TransportCertificateExpiresAt.Valid || !row.TransportCertificateExpiresAt.Time.After(now) {
		return RelayServiceCertificate{}, ErrRelayServiceCertificateNotFound
	}
	return relayServiceCertificate(ctx, d, queries, row)
}

func relayServiceCertificate(
	ctx context.Context,
	database *Database,
	queries *controlstatedb.Queries,
	row controlstatedb.ControlRelayService,
) (RelayServiceCertificate, error) {
	if !row.TransportCertificatePem.Valid || !row.TransportPrivateKeyStorageKeyID.Valid ||
		!row.TransportCertificateSerial.Valid || !row.TransportCertificateExpiresAt.Valid {
		return RelayServiceCertificate{}, ErrRelayServiceCertificateNotFound
	}
	privateKey, previous, err := database.openSecret(
		row.TransportPrivateKeyStorageKeyID.String,
		relayTransportPrivateKeyContext(row.RelayServiceID),
		row.TransportPrivateKeyCiphertext,
	)
	if err != nil {
		return RelayServiceCertificate{}, errors.New("controlstate: relay service private key ciphertext is invalid")
	}
	if previous {
		rotated, err := database.sealSecret(relayTransportPrivateKeyContext(row.RelayServiceID), privateKey)
		if err != nil {
			return RelayServiceCertificate{}, fmt.Errorf("controlstate: re-encrypt relay service private key: %w", err)
		}
		if err := queries.RotateRelayServicePrivateKey(ctx, controlstatedb.RotateRelayServicePrivateKeyParams{
			TransportPrivateKeyCiphertext: rotated, TransportPrivateKeyStorageKeyID: text(database.storageKey.CurrentID()),
			UpdatedAt: timestamptz(time.Now()), RelayServiceID: row.RelayServiceID,
			PreviousKeyID: row.TransportPrivateKeyStorageKeyID, PreviousCiphertext: row.TransportPrivateKeyCiphertext,
		}); err != nil {
			return RelayServiceCertificate{}, fmt.Errorf("controlstate: store re-encrypted relay service private key: %w", err)
		}
	}
	return RelayServiceCertificate{
		RelayServiceID: row.RelayServiceID, TLSServerName: row.TlsServerName,
		CertificatePEM: row.TransportCertificatePem.String, PrivateKeyPEM: string(privateKey),
		Serial: row.TransportCertificateSerial.String, NotAfter: row.TransportCertificateExpiresAt.Time,
	}, nil
}
