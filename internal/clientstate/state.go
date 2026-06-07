package clientstate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	tnlsqlite "github.com/tnldotdev/tnl/internal/sqlite"
	"golang.org/x/sys/unix"
)

const databaseName = "client.db"

const (
	certificatePhasePending = "pending"
	certificatePhaseCurrent = "current"
)

var (
	ErrLocked             = errors.New("clientstate: state is locked by another process")
	ErrCertificateExpired = errors.New("clientstate: application certificate is expired")
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Database owns the shared local client database.
type Database struct {
	root              string
	locksDir          string
	db                *sql.DB
	queries           *clientstatedb.Queries
	now               func() time.Time
	heartbeatInterval time.Duration
}

// Store scopes credentials, certificates, and locks to one server profile.
type Store struct {
	database        *Database
	controlEndpoint string
	locksDir        string
	secrets         secretProtector
}

type Lock struct {
	file *os.File
	once sync.Once
}

type RouteCertificateHandle struct {
	store   *Store
	routeID string
	lock    *os.File
	once    sync.Once
}

type Pending struct {
	Key          *ecdsa.PrivateKey
	CSRDER       []byte
	IssuanceID   string
	RouteVersion uint64

	keyDER []byte
}

type Material struct {
	Certificate  tls.Certificate
	CSRDER       []byte
	RenewAt      time.Time
	NotAfter     time.Time
	IssuanceID   string
	RouteVersion uint64
	Installed    bool
}

// DatabasePath returns the shared client database path within root.
func DatabasePath(root string) string { return filepath.Join(root, databaseName) }

func DefaultDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("clientstate: resolve user config directory: %w", err)
	}
	return filepath.Join(root, "tnl"), nil
}

// Open creates and migrates the shared local client database.
func Open(ctx context.Context, root string) (*Database, error) {
	root, err := prepareRoot(root)
	if err != nil {
		return nil, err
	}
	locksDir, err := privateSubdir(root, "locks")
	if err != nil {
		return nil, err
	}
	path := DatabasePath(root)
	migrationLock, err := openBlockingLock(filepath.Join(locksDir, "migrations.lock"), "migration")
	if err != nil {
		return nil, err
	}
	defer migrationLock.Close()
	if info, statErr := os.Lstat(path); statErr == nil {
		if err := validatePrivateFile(info, false); err != nil {
			return nil, fmt.Errorf("clientstate: database: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("clientstate: inspect database: %w", statErr)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("clientstate: load migrations: %w", err)
	}
	db, err := tnlsqlite.Open(ctx, path, migrations)
	if err != nil {
		return nil, fmt.Errorf("clientstate: %w", err)
	}
	return &Database{
		root: root, locksDir: locksDir, db: db, queries: clientstatedb.New(db), now: time.Now,
		heartbeatInterval: tunnelHeartbeatInterval,
	}, nil
}

func (d *Database) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

// Server returns state scoped to a canonical server origin.
func (d *Database) Server(ctx context.Context, serverOrigin string) (*Store, error) {
	serverOrigin, err := CanonicalServer(serverOrigin)
	if err != nil {
		return nil, err
	}
	now := d.now().UTC().UnixNano()
	if err := d.queries.UpsertServerProfile(ctx, clientstatedb.UpsertServerProfileParams{
		Origin: serverOrigin, Now: now,
	}); err != nil {
		return nil, fmt.Errorf("clientstate: save server profile: %w", err)
	}
	digest := sha256.Sum256([]byte(serverOrigin))
	locksDir, err := privateSubdir(d.locksDir, hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, err
	}
	profileDigest := sha256.Sum256([]byte(d.root + "\x00" + serverOrigin))
	return &Store{
		database: d, controlEndpoint: serverOrigin, locksDir: locksDir,
		secrets: newSecretProtector(
			hex.EncodeToString(profileDigest[:]), filepath.Join(locksDir, "keychain-initialization.lock"),
		),
	}, nil
}

// SavedServer returns the server selected by the last successful login.
func (d *Database) SavedServer(ctx context.Context) (string, bool, error) {
	selected, err := d.queries.GetSelectedServer(ctx)
	if err != nil {
		return "", false, fmt.Errorf("clientstate: read selected server: %w", err)
	}
	if !selected.Valid {
		return "", false, nil
	}
	server, err := CanonicalServer(selected.String)
	if err != nil || server != selected.String {
		return "", true, errors.New("clientstate: selected server is invalid")
	}
	return server, true, nil
}

// SaveServer records the server selected by a successful login.
func (d *Database) SaveServer(ctx context.Context, serverOrigin string) error {
	serverOrigin, err := CanonicalServer(serverOrigin)
	if err != nil {
		return err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clientstate: begin selected server update: %w", err)
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	if err := queries.UpsertServerProfile(ctx, clientstatedb.UpsertServerProfileParams{
		Origin: serverOrigin, Now: d.now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("clientstate: save server profile: %w", err)
	}
	if err := queries.SetSelectedServer(ctx, sql.NullString{String: serverOrigin, Valid: true}); err != nil {
		return fmt.Errorf("clientstate: select server: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("clientstate: commit selected server update: %w", err)
	}
	return nil
}

// CanonicalServer validates and normalizes a tnl server origin.
func CanonicalServer(value string) (string, error) {
	origin, err := url.Parse(value)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" && origin.Path != "/" {
		return "", errors.New("clientstate: server must be an HTTPS origin")
	}
	hostname := strings.ToLower(origin.Hostname())
	if hostname == "" {
		return "", errors.New("clientstate: server must be an HTTPS origin")
	}
	port := origin.Port()
	if port == "" || port == "443" {
		if strings.Contains(hostname, ":") {
			origin.Host = "[" + hostname + "]"
		} else {
			origin.Host = hostname
		}
	} else {
		origin.Host = net.JoinHostPort(hostname, port)
	}
	origin.Path = ""
	return origin.String(), nil
}

func (s *Store) LockHostname(hostname string) (*Lock, error) {
	if strings.TrimSpace(hostname) == "" {
		return nil, errors.New("clientstate: hostname is required")
	}
	digest := sha256.Sum256([]byte(hostname))
	return openLock(filepath.Join(s.locksDir, hex.EncodeToString(digest[:])+".lock"), "hostname")
}

func (s *Store) LockControlSession() (*Lock, error) {
	return openLock(filepath.Join(s.locksDir, "control-session.lock"), "control session")
}

func LockControlSessionContext(ctx context.Context, store *Store) (*Lock, error) {
	if store == nil {
		return nil, errors.New("clientstate: state store is required")
	}
	for {
		lock, err := store.LockControlSession()
		if !errors.Is(err, ErrLocked) {
			return lock, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
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

func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	var result error
	l.once.Do(func() {
		result = errors.Join(unix.Flock(int(l.file.Fd()), unix.LOCK_UN), l.file.Close())
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
		Certificate: certificate, CSRDER: bytes.Clone(stored.CsrDer), RenewAt: renewAt,
		NotAfter: certificate.Leaf.NotAfter, IssuanceID: stored.IssuanceID, RouteVersion: uint64(stored.RouteVersion),
		Installed: stored.Installed == 1,
	}, true, nil
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
		Certificate: installed, CSRDER: bytes.Clone(pending.CSRDER), RenewAt: renewAt.UTC(),
		NotAfter: installed.Leaf.NotAfter, IssuanceID: issuanceID, RouteVersion: routeVersion,
	}, nil
}

func (r *RouteCertificateHandle) RecordIssuance(
	ctx context.Context, hostname string, pending Pending, issuanceID string, routeVersion uint64,
) (Pending, error) {
	versionValue, err := databaseVersion(routeVersion)
	if err != nil || pending.Key == nil || len(pending.keyDER) == 0 || len(pending.CSRDER) == 0 ||
		issuanceID == "" || routeVersion == 0 {
		return Pending{}, errors.New("clientstate: pending certificate issuance is incomplete")
	}
	if err := validateCSR(pending.CSRDER, pending.Key, hostname); err != nil {
		return Pending{}, err
	}
	protectedKey, err := r.store.secrets.Seal(r.secretContext(), pending.keyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := r.store.database.queries.UpsertRouteCertificate(ctx, clientstatedb.UpsertRouteCertificateParams{
		ServerOrigin: r.store.controlEndpoint, RouteID: r.routeID, Phase: certificatePhasePending,
		Hostname: hostname, KeyDer: protectedKey, CsrDer: pending.CSRDER, IssuanceID: issuanceID,
		RouteVersion: versionValue, Installed: 0, UpdatedAt: r.store.database.now().UTC().UnixNano(),
	}); err != nil {
		return Pending{}, fmt.Errorf("clientstate: save pending route certificate: %w", err)
	}
	pending.IssuanceID, pending.RouteVersion = issuanceID, routeVersion
	return pending, nil
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

func (r *RouteCertificateHandle) RecordCurrentIssuance(
	ctx context.Context, hostname, issuanceID string, routeVersion uint64,
) (Material, error) {
	versionValue, versionErr := databaseVersion(routeVersion)
	stored, err := r.currentCertificate(ctx)
	if err != nil || versionErr != nil || stored.Hostname != hostname || issuanceID == "" || routeVersion == 0 {
		return Material{}, errors.New("clientstate: current certificate issuance is incomplete")
	}
	stored.IssuanceID, stored.RouteVersion, stored.Installed = issuanceID, versionValue, 0
	if err := r.saveCertificate(ctx, stored); err != nil {
		return Material{}, err
	}
	material, _, err := r.Current(ctx, hostname)
	return material, err
}

func (r *RouteCertificateHandle) CurrentKey(ctx context.Context, hostname string) (Pending, error) {
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
	return Pending{
		Key: key, CSRDER: bytes.Clone(stored.CsrDer), IssuanceID: stored.IssuanceID,
		RouteVersion: uint64(stored.RouteVersion), keyDER: keyDER,
	}, nil
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
		len(request.IPAddresses) != 0 || len(request.URIs) != 0 || request.Subject.String() != "" {
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
		leaf.NotBefore.After(time.Now().Add(5*time.Minute)) {
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

func prepareRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("clientstate: state directory is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("clientstate: resolve state directory: %w", err)
	}
	if info, statErr := os.Lstat(root); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("clientstate: state directory must not be a symlink")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("clientstate: inspect state directory: %w", statErr)
	}
	root, err = canonicalPath(root)
	if err != nil {
		return "", err
	}
	if err := validateTrustedAncestors(filepath.Dir(root)); err != nil {
		return "", err
	}
	if err := ensurePrivateDir(root); err != nil {
		return "", err
	}
	return root, nil
}

func canonicalPath(path string) (string, error) {
	cursor := filepath.Clean(path)
	var missing []string
	for {
		if _, err := os.Lstat(cursor); err == nil {
			resolved, err := filepath.EvalSymlinks(cursor)
			if err != nil {
				return "", fmt.Errorf("clientstate: resolve state directory: %w", err)
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("clientstate: inspect state directory: %w", err)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", errors.New("clientstate: no existing state directory ancestor")
		}
		missing = append(missing, filepath.Base(cursor))
		cursor = parent
	}
}

func validateTrustedAncestors(path string) error {
	cursor := filepath.Clean(path)
	for {
		info, err := os.Lstat(cursor)
		if errors.Is(err, os.ErrNotExist) {
			parent := filepath.Dir(cursor)
			if parent == cursor {
				return errors.New("clientstate: no existing state directory ancestor")
			}
			cursor = parent
			continue
		}
		if err != nil {
			return fmt.Errorf("clientstate: inspect state directory ancestor: %w", err)
		}
		writable := info.Mode().Perm()&0o022 != 0
		sticky := info.Mode()&os.ModeSticky != 0
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || writable && !sticky {
			return errors.New("clientstate: state directory has an untrusted writable ancestor")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return errors.New("clientstate: state directory has an untrusted owner")
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return nil
		}
		cursor = parent
	}
}

func openLock(path, kind string) (*Lock, error) {
	return openLockOperation(path, kind, unix.LOCK_EX|unix.LOCK_NB)
}

func openBlockingLock(path, kind string) (*Lock, error) {
	return openLockOperation(path, kind, unix.LOCK_EX)
}

func openLockOperation(path, kind string, operation int) (*Lock, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("clientstate: open %s lock: %w", kind, err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("clientstate: inspect %s lock: %w", kind, err)
	}
	if err := validatePrivateFile(info, false); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("clientstate: %s lock: %w", kind, err)
	}
	if err := unix.Flock(descriptor, operation); err != nil {
		_ = file.Close()
		if operation&unix.LOCK_NB != 0 && errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("clientstate: lock %s state: %w", kind, err)
	}
	return &Lock{file: file}, nil
}

func ensurePrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if err := validatePrivateFile(info, true); err != nil {
			return fmt.Errorf("clientstate: state directory: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clientstate: inspect state directory: %w", err)
	} else if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("clientstate: create state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("clientstate: inspect state directory: %w", err)
	}
	return validatePrivateFile(info, true)
}

func privateSubdir(parent, name string) (string, error) {
	path := filepath.Join(parent, name)
	if info, err := os.Lstat(path); err == nil {
		if err := validatePrivateFile(info, true); err != nil {
			return "", fmt.Errorf("clientstate: state path: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("clientstate: inspect state path: %w", err)
	} else if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("clientstate: create state path: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("clientstate: inspect state path: %w", err)
	}
	if err := validatePrivateFile(info, true); err != nil {
		return "", fmt.Errorf("clientstate: state path: %w", err)
	}
	return path, nil
}

func validatePrivateFile(info os.FileInfo, directory bool) error {
	wantMode := os.FileMode(0o600)
	if directory {
		wantMode = 0o700
	}
	if info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("not a real private file")
	}
	if info.Mode().Perm() != wantMode {
		return fmt.Errorf("permissions are %04o, want %04o", info.Mode().Perm(), wantMode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("not owned by the current user")
	}
	return nil
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

func LockHostnameContext(ctx context.Context, store *Store, hostname string) (*Lock, error) {
	for {
		lock, err := store.LockHostname(hostname)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, ErrLocked) {
			return nil, err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
