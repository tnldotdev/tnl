package clientstate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"golang.org/x/sys/unix"
)

const (
	certificatePhasePending = "pending"
	certificatePhaseCurrent = "current"
)

var ErrCertificateExpired = errors.New("clientstate: application certificate is expired")

type RouteCertificateHandle struct {
	store   *Store
	routeID string
	lock    *os.File
	once    sync.Once
}

type Pending struct {
	Key    *ecdsa.PrivateKey
	CSRDER []byte

	keyDER []byte
}

type Material struct {
	Certificate  tls.Certificate
	RenewAt      time.Time
	IssuanceID   string
	RouteVersion uint64
	Installed    bool
}

func (s *Store) OpenRoute(routeID string) (*RouteCertificateHandle, error) {
	if !validRouteID(routeID) {
		return nil, errors.New("clientstate: invalid route ID")
	}
	lock, err := openLock(filepath.Join(s.locksDir, routeID+".lock"), "route")
	if err != nil {
		return nil, err
	}
	return &RouteCertificateHandle{store: s, routeID: routeID, lock: lock.file}, nil
}

func (r *RouteCertificateHandle) Close() error {
	var result error
	r.once.Do(func() {
		result = errors.Join(unix.Flock(int(r.lock.Fd()), unix.LOCK_UN), r.lock.Close())
	})
	return result
}

func (r *RouteCertificateHandle) Current(ctx context.Context, hostname string) (Material, bool, error) {
	stored, err := r.store.database.queries.GetRouteCertificate(ctx, clientstatedb.GetRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhaseCurrent,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Material{}, false, nil
	}
	if err != nil {
		return Material{}, false, fmt.Errorf("clientstate: read current route certificate: %w", err)
	}
	if stored.Hostname != hostname || len(stored.CsrDer) == 0 || !stored.RenewAt.Valid ||
		stored.IssuanceID == "" || stored.RouteVersion <= 0 {
		return Material{}, true, errors.New("clientstate: current certificate metadata is invalid")
	}
	keyDER, err := r.store.secrets.Open(r.secretContext(), stored.KeyDer)
	if err != nil {
		return Material{}, true, err
	}
	certificate, err := certificate(keyDER, stored.CertificatePem, hostname)
	if err != nil {
		return Material{}, true, err
	}
	if err := validateCSR(stored.CsrDer, certificate.PrivateKey, hostname); err != nil {
		return Material{}, true, err
	}
	renewAt := unixNanoTime(stored.RenewAt.Int64)
	if !renewAt.After(certificate.Leaf.NotBefore) || !renewAt.Before(certificate.Leaf.NotAfter) {
		return Material{}, true, errors.New("clientstate: renewal time is outside certificate validity")
	}
	return Material{
		Certificate: certificate, RenewAt: renewAt, IssuanceID: stored.IssuanceID, RouteVersion: uint64(stored.RouteVersion),
		Installed: stored.Installed == 1,
	}, true, nil
}

// CertificateAttempt returns the key material for the server's idempotent
// issuance transaction. A pending CSR takes precedence; otherwise an
// unacknowledged current certificate reuses its CSR to recover response loss.
func (r *RouteCertificateHandle) CertificateAttempt(ctx context.Context, hostname string) (Pending, error) {
	stored, err := r.store.database.queries.GetRouteCertificate(ctx, clientstatedb.GetRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhasePending,
	})
	if err == nil {
		return r.pendingFromDB(stored, hostname)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Pending{}, fmt.Errorf("clientstate: read pending route certificate: %w", err)
	}
	current, found, err := r.Current(ctx, hostname)
	if err == nil && found && !current.Installed {
		return r.currentKey(ctx, hostname)
	}
	if err != nil && !errors.Is(err, ErrCertificateExpired) {
		return Pending{}, err
	}
	return r.NewPending(ctx, hostname)
}

func (r *RouteCertificateHandle) Pending(ctx context.Context, hostname string) (Pending, error) {
	stored, err := r.store.database.queries.GetRouteCertificate(ctx, clientstatedb.GetRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhasePending,
	})
	if err == nil {
		return r.pendingFromDB(stored, hostname)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Pending{}, fmt.Errorf("clientstate: read pending route certificate: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Pending{}, fmt.Errorf("clientstate: generate application key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Pending{}, fmt.Errorf("clientstate: encode application key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, key)
	if err != nil {
		return Pending{}, fmt.Errorf("clientstate: create application CSR: %w", err)
	}
	protectedKey, err := r.store.secrets.Seal(r.secretContext(), keyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := r.store.database.queries.UpsertRouteCertificate(ctx, clientstatedb.UpsertRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhasePending,
		Hostname: hostname, KeyDer: protectedKey, CsrDer: csrDER, IssuanceID: "", RouteVersion: 0,
		Installed: 0, UpdatedAt: r.store.database.now().UTC().UnixNano(),
	}); err != nil {
		return Pending{}, fmt.Errorf("clientstate: save pending route certificate: %w", err)
	}
	return Pending{Key: key, CSRDER: csrDER, keyDER: keyDER}, nil
}

func (r *RouteCertificateHandle) Commit(
	ctx context.Context,
	hostname string,
	pending Pending,
	certificatePEM []byte,
	renewAt time.Time,
	issuanceID string,
	routeVersion uint64,
) (Material, error) {
	versionValue, err := databaseVersion(routeVersion)
	if err != nil || pending.Key == nil || len(pending.keyDER) == 0 || len(pending.CSRDER) == 0 || renewAt.IsZero() ||
		issuanceID == "" || routeVersion == 0 {
		return Material{}, errors.New("clientstate: pending certificate material is incomplete")
	}
	installed, err := certificate(pending.keyDER, certificatePEM, hostname)
	if err != nil {
		return Material{}, err
	}
	if !renewAt.After(installed.Leaf.NotBefore) || !renewAt.Before(installed.Leaf.NotAfter) {
		return Material{}, errors.New("clientstate: renewal time is outside certificate validity")
	}
	protectedKey, err := r.store.secrets.Seal(r.secretContext(), pending.keyDER)
	if err != nil {
		return Material{}, err
	}
	tx, err := r.store.database.db.BeginTx(ctx, nil)
	if err != nil {
		return Material{}, fmt.Errorf("clientstate: begin route certificate commit: %w", err)
	}
	defer tx.Rollback()
	queries := r.store.database.queries.WithTx(tx)
	if err := queries.UpsertRouteCertificate(ctx, clientstatedb.UpsertRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhaseCurrent,
		Hostname: hostname, KeyDer: protectedKey, CsrDer: bytes.Clone(pending.CSRDER),
		CertificatePem: bytes.Clone(certificatePEM), RenewAt: sql.NullInt64{Int64: renewAt.UTC().UnixNano(), Valid: true},
		IssuanceID: issuanceID, RouteVersion: versionValue, Installed: 0,
		UpdatedAt: r.store.database.now().UTC().UnixNano(),
	}); err != nil {
		return Material{}, fmt.Errorf("clientstate: save current route certificate: %w", err)
	}
	if err := queries.DeleteRouteCertificate(ctx, clientstatedb.DeleteRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhasePending,
	}); err != nil {
		return Material{}, fmt.Errorf("clientstate: remove pending route certificate: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Material{}, fmt.Errorf("clientstate: commit route certificate: %w", err)
	}
	return Material{
		Certificate: installed, RenewAt: renewAt.UTC(), IssuanceID: issuanceID, RouteVersion: routeVersion,
	}, nil
}

func (r *RouteCertificateHandle) MarkInstalled(ctx context.Context, hostname, issuanceID string, routeVersion uint64) (Material, error) {
	stored, err := r.currentCertificate(ctx)
	if err != nil || stored.Hostname != hostname || stored.IssuanceID != issuanceID || stored.RouteVersion != int64(routeVersion) {
		return Material{}, errors.New("clientstate: installed certificate does not match current state")
	}
	stored.Installed = 1
	if err := r.saveCertificate(ctx, stored); err != nil {
		return Material{}, err
	}
	material, _, err := r.Current(ctx, hostname)
	return material, err
}

func (r *RouteCertificateHandle) currentKey(ctx context.Context, hostname string) (Pending, error) {
	stored, err := r.currentCertificate(ctx)
	if err != nil || stored.Hostname != hostname || len(stored.KeyDer) == 0 || len(stored.CsrDer) == 0 {
		return Pending{}, errors.New("clientstate: current certificate key is incomplete")
	}
	keyDER, err := r.store.secrets.Open(r.secretContext(), stored.KeyDer)
	if err != nil {
		return Pending{}, err
	}
	key, err := parseKey(keyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := validateCSR(stored.CsrDer, key, hostname); err != nil {
		return Pending{}, err
	}
	return Pending{Key: key, CSRDER: bytes.Clone(stored.CsrDer), keyDER: keyDER}, nil
}

func (r *RouteCertificateHandle) NewPending(ctx context.Context, hostname string) (Pending, error) {
	if err := r.store.database.queries.DeleteRouteCertificate(ctx, clientstatedb.DeleteRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhasePending,
	}); err != nil {
		return Pending{}, fmt.Errorf("clientstate: replace pending route certificate: %w", err)
	}
	return r.Pending(ctx, hostname)
}

func (r *RouteCertificateHandle) pendingFromDB(stored clientstatedb.RouteCertificate, hostname string) (Pending, error) {
	if stored.Hostname != hostname {
		return Pending{}, errors.New("clientstate: pending certificate metadata is invalid")
	}
	keyDER, err := r.store.secrets.Open(r.secretContext(), stored.KeyDer)
	if err != nil {
		return Pending{}, err
	}
	key, err := parseKey(keyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := validateCSR(stored.CsrDer, key, hostname); err != nil {
		return Pending{}, err
	}
	return Pending{Key: key, CSRDER: bytes.Clone(stored.CsrDer), keyDER: keyDER}, nil
}

func (r *RouteCertificateHandle) currentCertificate(ctx context.Context) (clientstatedb.RouteCertificate, error) {
	stored, err := r.store.database.queries.GetRouteCertificate(ctx, clientstatedb.GetRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhaseCurrent,
	})
	if err != nil {
		return clientstatedb.RouteCertificate{}, err
	}
	return stored, nil
}

func (r *RouteCertificateHandle) saveCertificate(ctx context.Context, stored clientstatedb.RouteCertificate) error {
	if err := r.store.database.queries.UpsertRouteCertificate(ctx, clientstatedb.UpsertRouteCertificateParams{
		ServerOrigin: stored.ServerOrigin, RouteID: stored.RouteID, Phase: stored.Phase,
		Hostname: stored.Hostname, KeyDer: stored.KeyDer, CsrDer: stored.CsrDer,
		CertificatePem: stored.CertificatePem, RenewAt: stored.RenewAt, IssuanceID: stored.IssuanceID,
		RouteVersion: stored.RouteVersion, Installed: stored.Installed, UpdatedAt: r.store.database.now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("clientstate: save route certificate: %w", err)
	}
	return nil
}

func (r *RouteCertificateHandle) secretContext() string { return "route-private-key:" + r.routeID }

func validateCSR(csrDER []byte, key any, hostname string) error {
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return errors.New("clientstate: pending CSR is invalid")
	}
	signer, signerOK := key.(crypto.Signer)
	if !signerOK {
		return errors.New("clientstate: pending CSR key is invalid")
	}
	publicKey, keyOK := request.PublicKey.(*ecdsa.PublicKey)
	expected, expectedOK := signer.Public().(*ecdsa.PublicKey)
	if request.CheckSignature() != nil || !keyOK || !expectedOK || !publicKey.Equal(expected) ||
		len(request.DNSNames) != 1 || request.DNSNames[0] != hostname || len(request.EmailAddresses) != 0 ||
		len(request.IPAddresses) != 0 || len(request.URIs) != 0 || request.Subject.String() != "" ||
		!certificateidentity.DNSNamesOnly(request.Extensions, request.DNSNames) {
		return errors.New("clientstate: pending CSR is invalid")
	}
	return nil
}

func certificate(keyDER, certificatePEM []byte, hostname string) (tls.Certificate, error) {
	key, err := parseKey(keyDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	result, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("clientstate: load application certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(result.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("clientstate: parse application certificate: %w", err)
	}
	if !leaf.NotAfter.After(time.Now()) {
		return tls.Certificate{}, ErrCertificateExpired
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hostname || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || leaf.IsCA ||
		leaf.NotBefore.After(time.Now().Add(5*time.Minute)) ||
		!certificateidentity.DNSNamesOnly(leaf.Extensions, leaf.DNSNames) {
		return tls.Certificate{}, errors.New("clientstate: application certificate identity or validity is invalid")
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !serverAuth {
		return tls.Certificate{}, errors.New("clientstate: application certificate is not valid for TLS servers")
	}
	if publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !publicKey.Equal(&key.PublicKey) {
		return tls.Certificate{}, errors.New("clientstate: application certificate key does not match")
	}
	result.Leaf = leaf
	return result, nil
}

func parseKey(keyDER []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("clientstate: parse application key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("clientstate: application key is not ECDSA P-256")
	}
	return key, nil
}

func databaseVersion(routeVersion uint64) (int64, error) {
	if routeVersion > math.MaxInt64 {
		return 0, errors.New("clientstate: route version exceeds database range")
	}
	return int64(routeVersion), nil
}

func unixNanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

func validRouteID(value string) bool {
	return opaqueid.Valid(value, "route_")
}

func LockRouteCertificates(ctx context.Context, store *Store, routeID string) (*RouteCertificateHandle, error) {
	if store == nil {
		return nil, errors.New("clientstate: state store is required")
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		route, err := store.OpenRoute(routeID)
		if !errors.Is(err, ErrLocked) {
			return route, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
