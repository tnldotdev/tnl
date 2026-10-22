package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

var ErrIngressTransportCertificate = errors.New("controlstate: ingress transport certificate is unavailable")

type IngressTransportTrust struct {
	IngressLeaseIdentity
	TLSServerName, CertificatePEM, IssuerPEM, PublicKeySHA256, LeaseURI string
	IssuerRevision                                                      int64
	NotBefore, NotAfter, ValidUntil                                     time.Time
}

// private key material is returned only on the cluster-authenticated node API.
// visitor trust responses contain only IngressTransportTrust.
type IngressTransportCertificate struct {
	IngressTransportTrust
	PrivateKeyPEM string
}

func (IngressTransportCertificate) String() string   { return "ingress transport certificate" }
func (IngressTransportCertificate) GoString() string { return "ingress transport certificate" }

func ingressTransportIssuerContext(revision int64) string {
	return "ingress-transport-issuer:" + strconv.FormatInt(revision, 10)
}
func ingressTransportKeyContext(id, run string, revision int64, name string) string {
	encoded, _ := json.Marshal([]string{id, run, strconv.FormatInt(revision, 10), name})
	return "ingress-transport-key:" + string(encoded)
}

func ingressLeaseURI(identity IngressLeaseIdentity) string {
	u := url.URL{Scheme: "tnl", Host: "ingress", Path: "/" + identity.IngressID + "/" + identity.IngressRunID + "/" + strconv.FormatUint(identity.IngressLeaseRevision, 10)}
	u.RawPath = "/" + url.PathEscape(identity.IngressID) + "/" + url.PathEscape(identity.IngressRunID) + "/" + strconv.FormatUint(identity.IngressLeaseRevision, 10)
	return u.String()
}

func transportSerial() (*big.Int, error) {
	number, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err == nil && number.Sign() == 0 {
		number.SetInt64(1)
	}
	return number, err
}

func (d *Database) ensureIngressTransportIssuer(ctx context.Context, tx pgx.Tx, now time.Time) (controlstatedb.ControlIngressTransportIssuer, *x509.Certificate, ed25519.PrivateKey, error) {
	// both nodes and visitor trust reads lock their ingress lease first; issuer
	// work never takes another ingress lock after this serialization point.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(8390266017870570545)`); err != nil {
		return controlstatedb.ControlIngressTransportIssuer{}, nil, nil, err
	}
	q := controlstatedb.New(tx)
	row, err := q.LockIngressTransportIssuer(ctx)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return row, nil, nil, err
	}
	if err == nil && row.NotAfter.Time.After(now.Add(30*24*time.Hour)) {
		block, _ := pem.Decode([]byte(row.CertificatePem))
		if block == nil {
			return row, nil, nil, ErrIngressTransportCertificate
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !certificate.IsCA {
			return row, nil, nil, ErrIngressTransportCertificate
		}
		der, _, openErr := d.storageKey.Open(row.StorageKeyID, ingressTransportIssuerContext(row.Revision), row.PrivateKeyCiphertext)
		if openErr != nil {
			return row, nil, nil, ErrIngressTransportCertificate
		}
		value, parseErr := x509.ParsePKCS8PrivateKey(der)
		if parseErr != nil {
			return row, nil, nil, ErrIngressTransportCertificate
		}
		key, ok := value.(ed25519.PrivateKey)
		if !ok || !key.Public().(ed25519.PublicKey).Equal(certificate.PublicKey) {
			return row, nil, nil, ErrIngressTransportCertificate
		}
		return row, certificate, key, nil
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return row, nil, nil, err
	}
	serial, err := transportSerial()
	if err != nil {
		return row, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "tnl ingress transport"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		return row, nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return row, nil, nil, err
	}
	revision, err := q.NextIngressTransportIssuerRevision(ctx)
	if err != nil {
		return row, nil, nil, err
	}
	cipher, err := d.storageKey.Seal(ingressTransportIssuerContext(revision), private)
	if err != nil {
		return row, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return row, nil, nil, err
	}
	row, err = q.InsertIngressTransportIssuer(ctx, controlstatedb.InsertIngressTransportIssuerParams{Revision: revision, CertificatePem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKeyCiphertext: cipher, StorageKeyID: d.storageKey.CurrentID(), Now: timestamptz(now), NotAfter: timestamptz(parsed.NotAfter)})
	if err != nil {
		return row, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	return row, certificate, key, err
}

func (d *Database) ingressTransportMaterial(ctx context.Context, tx pgx.Tx, lease controlstatedb.ControlIngressLease, now time.Time) (result IngressTransportCertificate, retErr error) {
	name, err := naming.CanonicalizeHostname(lease.ConnectorTlsServerName)
	if err != nil || name != lease.ConnectorTlsServerName || strings.Contains(name, "*") || lease.ConnectorAddress == "" || lease.Draining {
		return result, ErrIngressTransportCertificate
	}
	issuer, ca, issuerKey, err := d.ensureIngressTransportIssuer(ctx, tx, now)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	row, err := q.LockIngressTransportCertificate(ctx, controlstatedb.LockIngressTransportCertificateParams{IngressID: lease.IngressID, IngressRunID: lease.IngressRunID, IngressLeaseRevision: lease.IngressLeaseRevision, TlsServerName: name})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	var key ed25519.PrivateKey
	var privatePEM []byte
	if err == nil {
		privatePEM, _, err = d.storageKey.Open(row.StorageKeyID, ingressTransportKeyContext(lease.IngressID, lease.IngressRunID, lease.IngressLeaseRevision, name), row.PrivateKeyCiphertext)
		if err != nil {
			return result, ErrIngressTransportCertificate
		}
		block, _ := pem.Decode(privatePEM)
		if block == nil {
			return result, ErrIngressTransportCertificate
		}
		value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return result, ErrIngressTransportCertificate
		}
		var ok bool
		key, ok = value.(ed25519.PrivateKey)
		if !ok {
			return result, ErrIngressTransportCertificate
		}
	}
	deadline := now.Add(time.Hour)
	if lease.LeaseExpiresAt.Time.Before(deadline) {
		deadline = lease.LeaseExpiresAt.Time
	}
	if ca.NotAfter.Before(deadline) {
		deadline = ca.NotAfter
	}
	deadline = deadline.Truncate(time.Second)
	if !deadline.After(now) {
		return result, ErrIngressLeaseStale
	}
	identity := IngressLeaseIdentity{IngressID: lease.IngressID, IngressRunID: lease.IngressRunID, IngressLeaseRevision: uint64(lease.IngressLeaseRevision)}
	uri := ingressLeaseURI(identity)
	if key == nil || row.IssuerRevision != issuer.Revision || !row.NotAfter.Time.Equal(deadline) {
		if key == nil {
			_, key, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return result, err
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return result, err
			}
			privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}
		serial, err := transportSerial()
		if err != nil {
			return result, err
		}
		peerURI, err := url.Parse(uri)
		if err != nil {
			return result, err
		}
		template := &x509.Certificate{SerialNumber: serial, DNSNames: []string{name}, URIs: []*url.URL{peerURI}, NotBefore: now.Add(-time.Minute).Truncate(time.Second), NotAfter: deadline,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(name); ip != nil {
			template.DNSNames = nil
			template.IPAddresses = []net.IP{ip}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), issuerKey)
		if err != nil {
			return result, err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return result, err
		}
		digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		cipher, err := d.storageKey.Seal(ingressTransportKeyContext(lease.IngressID, lease.IngressRunID, lease.IngressLeaseRevision, name), privatePEM)
		if err != nil {
			return result, err
		}
		row, err = q.StoreIngressTransportCertificate(ctx, controlstatedb.StoreIngressTransportCertificateParams{IngressID: lease.IngressID, IngressRunID: lease.IngressRunID, IngressLeaseRevision: lease.IngressLeaseRevision, TlsServerName: name,
			IssuerRevision: issuer.Revision, CertificatePem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyCiphertext: cipher, StorageKeyID: d.storageKey.CurrentID(),
			PublicKeySha256: hex.EncodeToString(digest[:]), NotBefore: timestamptz(template.NotBefore), NotAfter: timestamptz(deadline)})
		if err != nil {
			return result, err
		}
	}
	roots, err := q.ListIngressTransportIssuerCertificates(ctx, timestamptz(now))
	if err != nil {
		return result, err
	}
	block, rest := pem.Decode([]byte(row.CertificatePem))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return result, ErrIngressTransportCertificate
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return result, ErrIngressTransportCertificate
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return result, ErrIngressTransportCertificate
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if !key.Public().(ed25519.PublicKey).Equal(leaf.PublicKey) || hex.EncodeToString(pin[:]) != row.PublicKeySha256 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri || leaf.NotAfter.After(lease.LeaseExpiresAt.Time) {
		return result, ErrIngressTransportCertificate
	}
	result.IngressTransportTrust = IngressTransportTrust{IngressLeaseIdentity: identity, TLSServerName: name, CertificatePEM: row.CertificatePem, IssuerPEM: strings.Join(roots, ""), PublicKeySHA256: row.PublicKeySha256,
		LeaseURI: uri, IssuerRevision: row.IssuerRevision, NotBefore: row.NotBefore.Time, NotAfter: row.NotAfter.Time, ValidUntil: row.NotAfter.Time}
	result.PrivateKeyPEM = string(privatePEM)
	return result, nil
}

func (d *Database) GetIngressTransportCertificate(ctx context.Context, identity IngressLeaseIdentity, now time.Time) (result IngressTransportCertificate, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get ingress transport certificate", &retErr)()
	lease, err := lockCurrentIngressLease(ctx, controlstatedb.New(tx), identity, now)
	if err != nil {
		return result, err
	}
	result, err = d.ingressTransportMaterial(ctx, tx, lease, now)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func (d *Database) GetVisitorIngressTransportTrust(ctx context.Context, identityID, sessionID string, now time.Time) (result IngressTransportTrust, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get visitor ingress transport trust", &retErr)()
	var identity IngressLeaseIdentity
	var revision int64
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT session.assigned_ingress_id,session.assigned_ingress_run_id,session.assigned_ingress_lease_revision,session.expires_at
	    FROM control.connector_sessions session JOIN control.visitor_devices device ON device.id=session.device_id AND device.identity_id=session.identity_id
	    JOIN control.identities person ON person.id=device.identity_id WHERE session.id=$1 AND person.id=$2 AND person.disabled_at IS NULL
	    AND device.revoked_at IS NULL AND session.revoked_at IS NULL AND session.expires_at>$3 FOR SHARE OF session,device,person`, sessionID, identityID, now).
		Scan(&identity.IngressID, &identity.IngressRunID, &revision, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	identity.IngressLeaseRevision = uint64(revision)
	lease, err := lockCurrentIngressLease(ctx, controlstatedb.New(tx), identity, now)
	if err != nil {
		return result, err
	}
	material, err := d.ingressTransportMaterial(ctx, tx, lease, now)
	if err != nil {
		return result, err
	}
	result = material.IngressTransportTrust
	if expires.Before(result.ValidUntil) {
		result.ValidUntil = expires
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
