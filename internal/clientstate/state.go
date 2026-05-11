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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	stateSchemaVersion = 2
	maxStateBytes      = 128 << 10
)

var (
	ErrLocked             = errors.New("clientstate: state is locked by another process")
	ErrCertificateExpired = errors.New("clientstate: application certificate is expired")
)

type Store struct {
	serverDir          string
	routesDir          string
	locksDir           string
	controlEndpoint    string
	controlSessionPath string
	secrets            secretProtector
}

type Lock struct {
	file *os.File
	once sync.Once
}

type Route struct {
	dir           string
	lock          *os.File
	secretContext string
	secrets       secretProtector
	once          sync.Once
}

type Pending struct {
	Key        *ecdsa.PrivateKey
	CSRDER     []byte
	IssuanceID string
	Version    uint64

	keyDER []byte
}

type Material struct {
	Certificate tls.Certificate
	CSRDER      []byte
	RenewAt     time.Time
	NotAfter    time.Time
	IssuanceID  string
	Version     uint64
	Installed   bool
}

type pendingFile struct {
	SchemaVersion int    `json:"schema_version"`
	Hostname      string `json:"hostname"`
	KeyDER        []byte `json:"key_der"`
	CSRDER        []byte `json:"csr_der"`
	IssuanceID    string `json:"issuance_id,omitempty"`
	Version       uint64 `json:"version,omitempty"`
}

type currentFile struct {
	SchemaVersion  int       `json:"schema_version"`
	Hostname       string    `json:"hostname"`
	KeyDER         []byte    `json:"key_der"`
	CSRDER         []byte    `json:"csr_der"`
	CertificatePEM []byte    `json:"certificate_pem"`
	RenewAt        time.Time `json:"renew_at"`
	IssuanceID     string    `json:"issuance_id"`
	Version        uint64    `json:"version"`
	Installed      bool      `json:"installed"`
}

type selectedServerFile struct {
	SchemaVersion int    `json:"schema_version"`
	Server        string `json:"server"`
}

func DefaultDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("clientstate: resolve user config directory: %w", err)
	}
	return filepath.Join(root, "tnl"), nil
}

func New(root, serverOrigin string) (*Store, error) {
	serverOrigin, err := CanonicalServer(serverOrigin)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(serverOrigin))
	root, err = prepareRoot(root)
	if err != nil {
		return nil, err
	}
	servers, err := privateSubdir(root, "servers")
	if err != nil {
		return nil, err
	}
	server, err := privateSubdir(servers, hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, err
	}
	routes, err := privateSubdir(server, "routes")
	if err != nil {
		return nil, err
	}
	locks, err := privateSubdir(server, "locks")
	if err != nil {
		return nil, err
	}
	profileDigest := sha256.Sum256([]byte(root + "\x00" + serverOrigin))
	return &Store{
		serverDir: server, routesDir: routes, locksDir: locks,
		controlEndpoint: serverOrigin, controlSessionPath: filepath.Join(server, "control-session.json"),
		secrets: newSecretProtector(
			hex.EncodeToString(profileDigest[:]), filepath.Join(locks, "keychain-initialization.lock"),
		),
	}, nil
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

// SavedServer returns the server selected by the last successful login.
func SavedServer(root string) (string, bool, error) {
	root, err := prepareRoot(root)
	if err != nil {
		return "", false, err
	}
	var stored selectedServerFile
	found, err := readJSON(filepath.Join(root, "selected-server.json"), &stored)
	if err != nil || !found {
		return "", found, err
	}
	server, err := CanonicalServer(stored.Server)
	if err != nil || stored.SchemaVersion != stateSchemaVersion || server != stored.Server {
		return "", true, errors.New("clientstate: selected server is invalid")
	}
	return server, true, nil
}

// SaveServer records the server only after a successful login.
func SaveServer(root, server string) error {
	server, err := CanonicalServer(server)
	if err != nil {
		return err
	}
	root, err = prepareRoot(root)
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(root, "selected-server.json"), selectedServerFile{
		SchemaVersion: stateSchemaVersion,
		Server:        server,
	})
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

func (s *Store) OpenRoute(routeID string) (*Route, error) {
	if !validRouteID(routeID) {
		return nil, errors.New("clientstate: invalid route ID")
	}
	dir, err := privateSubdir(s.routesDir, routeID)
	if err != nil {
		return nil, err
	}
	lock, err := openLock(filepath.Join(dir, "lock"), "route")
	if err != nil {
		return nil, err
	}
	if err := cleanupTemps(dir); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return &Route{
		dir: dir, lock: lock.file, secrets: s.secrets,
		secretContext: "route-private-key:" + routeID,
	}, nil
}

func (r *Route) Close() error {
	var result error
	r.once.Do(func() {
		result = errors.Join(unix.Flock(int(r.lock.Fd()), unix.LOCK_UN), r.lock.Close())
	})
	return result
}

func (l *Lock) Close() error {
	var result error
	l.once.Do(func() {
		result = errors.Join(unix.Flock(int(l.file.Fd()), unix.LOCK_UN), l.file.Close())
	})
	return result
}

func (r *Route) Current(hostname string) (Material, bool, error) {
	var stored currentFile
	found, err := readJSON(filepath.Join(r.dir, "current.json"), &stored)
	if err != nil || !found {
		return Material{}, found, err
	}
	if stored.SchemaVersion != stateSchemaVersion || stored.Hostname != hostname || len(stored.CSRDER) == 0 ||
		stored.RenewAt.IsZero() || stored.IssuanceID == "" || stored.Version == 0 {
		return Material{}, true, errors.New("clientstate: current certificate metadata is invalid")
	}
	keyDER, err := r.secrets.Open(r.secretContext, stored.KeyDER)
	if err != nil {
		return Material{}, true, err
	}
	certificate, err := certificate(keyDER, stored.CertificatePEM, hostname)
	if err != nil {
		return Material{}, true, err
	}
	if err := validateCSR(stored.CSRDER, certificate.PrivateKey, hostname); err != nil {
		return Material{}, true, err
	}
	if !stored.RenewAt.After(certificate.Leaf.NotBefore) || !stored.RenewAt.Before(certificate.Leaf.NotAfter) {
		return Material{}, true, errors.New("clientstate: renewal time is outside certificate validity")
	}
	return Material{
		Certificate: certificate, CSRDER: bytes.Clone(stored.CSRDER), RenewAt: stored.RenewAt,
		NotAfter: certificate.Leaf.NotAfter, IssuanceID: stored.IssuanceID, Version: stored.Version,
		Installed: stored.Installed,
	}, true, nil
}

func (r *Route) Pending(hostname string) (Pending, error) {
	var stored pendingFile
	found, err := readJSON(filepath.Join(r.dir, "pending.json"), &stored)
	if err != nil {
		return Pending{}, err
	}
	if found {
		if stored.SchemaVersion != stateSchemaVersion || stored.Hostname != hostname {
			return Pending{}, errors.New("clientstate: pending certificate metadata is invalid")
		}
		keyDER, err := r.secrets.Open(r.secretContext, stored.KeyDER)
		if err != nil {
			return Pending{}, err
		}
		key, err := parseKey(keyDER)
		if err != nil {
			return Pending{}, err
		}
		if err := validateCSR(stored.CSRDER, key, hostname); err != nil {
			return Pending{}, err
		}
		return Pending{
			Key: key, CSRDER: bytes.Clone(stored.CSRDER), IssuanceID: stored.IssuanceID,
			Version: stored.Version, keyDER: keyDER,
		}, nil
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
	protectedKey, err := r.secrets.Seal(r.secretContext, keyDER)
	if err != nil {
		return Pending{}, err
	}
	stored = pendingFile{SchemaVersion: stateSchemaVersion, Hostname: hostname, KeyDER: protectedKey, CSRDER: csrDER}
	if err := writeJSON(filepath.Join(r.dir, "pending.json"), stored); err != nil {
		return Pending{}, err
	}
	return Pending{Key: key, CSRDER: csrDER, keyDER: keyDER}, nil
}

func (r *Route) Commit(
	hostname string,
	pending Pending,
	certificatePEM []byte,
	renewAt time.Time,
	issuanceID string,
	version uint64,
) (Material, error) {
	if pending.Key == nil || len(pending.keyDER) == 0 || len(pending.CSRDER) == 0 || renewAt.IsZero() ||
		issuanceID == "" || version == 0 {
		return Material{}, errors.New("clientstate: pending certificate material is incomplete")
	}
	installed, err := certificate(pending.keyDER, certificatePEM, hostname)
	if err != nil {
		return Material{}, err
	}
	if !renewAt.After(installed.Leaf.NotBefore) || !renewAt.Before(installed.Leaf.NotAfter) {
		return Material{}, errors.New("clientstate: renewal time is outside certificate validity")
	}
	protectedKey, err := r.secrets.Seal(r.secretContext, pending.keyDER)
	if err != nil {
		return Material{}, err
	}
	stored := currentFile{
		SchemaVersion: stateSchemaVersion, Hostname: hostname, KeyDER: protectedKey, CSRDER: bytes.Clone(pending.CSRDER),
		CertificatePEM: bytes.Clone(certificatePEM), RenewAt: renewAt.UTC(), IssuanceID: issuanceID,
		Version: version,
	}
	if err := writeJSON(filepath.Join(r.dir, "current.json"), stored); err != nil {
		return Material{}, err
	}
	material := Material{
		Certificate: installed, CSRDER: bytes.Clone(stored.CSRDER), RenewAt: stored.RenewAt,
		NotAfter: installed.Leaf.NotAfter, IssuanceID: issuanceID, Version: version,
	}
	if err := os.Remove(filepath.Join(r.dir, "pending.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return material, fmt.Errorf("clientstate: remove pending certificate: %w", err)
	}
	if err := syncDir(r.dir); err != nil {
		return material, err
	}
	return material, nil
}

func (r *Route) RecordIssuance(hostname string, pending Pending, issuanceID string, version uint64) (Pending, error) {
	if pending.Key == nil || len(pending.keyDER) == 0 || len(pending.CSRDER) == 0 || issuanceID == "" || version == 0 {
		return Pending{}, errors.New("clientstate: pending certificate issuance is incomplete")
	}
	if err := validateCSR(pending.CSRDER, pending.Key, hostname); err != nil {
		return Pending{}, err
	}
	protectedKey, err := r.secrets.Seal(r.secretContext, pending.keyDER)
	if err != nil {
		return Pending{}, err
	}
	stored := pendingFile{
		SchemaVersion: stateSchemaVersion, Hostname: hostname, KeyDER: protectedKey, CSRDER: pending.CSRDER,
		IssuanceID: issuanceID, Version: version,
	}
	if err := writeJSON(filepath.Join(r.dir, "pending.json"), stored); err != nil {
		return Pending{}, err
	}
	pending.IssuanceID, pending.Version = issuanceID, version
	return pending, nil
}

func (r *Route) MarkInstalled(hostname, issuanceID string, version uint64) (Material, error) {
	var stored currentFile
	found, err := readJSON(filepath.Join(r.dir, "current.json"), &stored)
	if err != nil {
		return Material{}, err
	}
	if !found || stored.Hostname != hostname || stored.IssuanceID != issuanceID || stored.Version != version {
		return Material{}, errors.New("clientstate: installed certificate does not match current state")
	}
	stored.Installed = true
	if err := writeJSON(filepath.Join(r.dir, "current.json"), stored); err != nil {
		return Material{}, err
	}
	material, _, err := r.Current(hostname)
	return material, err
}

func (r *Route) RecordCurrentIssuance(hostname, issuanceID string, version uint64) (Material, error) {
	var stored currentFile
	found, err := readJSON(filepath.Join(r.dir, "current.json"), &stored)
	if err != nil {
		return Material{}, err
	}
	if !found || stored.Hostname != hostname || issuanceID == "" || version == 0 {
		return Material{}, errors.New("clientstate: current certificate issuance is incomplete")
	}
	stored.IssuanceID, stored.Version, stored.Installed = issuanceID, version, false
	if err := writeJSON(filepath.Join(r.dir, "current.json"), stored); err != nil {
		return Material{}, err
	}
	material, _, err := r.Current(hostname)
	return material, err
}

func (r *Route) CurrentKey(hostname string) (Pending, error) {
	var stored currentFile
	found, err := readJSON(filepath.Join(r.dir, "current.json"), &stored)
	if err != nil {
		return Pending{}, err
	}
	if !found || stored.Hostname != hostname || len(stored.KeyDER) == 0 || len(stored.CSRDER) == 0 {
		return Pending{}, errors.New("clientstate: current certificate key is incomplete")
	}
	keyDER, err := r.secrets.Open(r.secretContext, stored.KeyDER)
	if err != nil {
		return Pending{}, err
	}
	key, err := parseKey(keyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := validateCSR(stored.CSRDER, key, hostname); err != nil {
		return Pending{}, err
	}
	return Pending{Key: key, CSRDER: bytes.Clone(stored.CSRDER), keyDER: keyDER}, nil
}

func (r *Route) NewPending(hostname string) (Pending, error) {
	if err := os.Remove(filepath.Join(r.dir, "pending.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Pending{}, fmt.Errorf("clientstate: replace pending certificate: %w", err)
	}
	if err := syncDir(r.dir); err != nil {
		return Pending{}, err
	}
	return r.Pending(hostname)
}

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

func cleanupTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("clientstate: list route state: %w", err)
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clientstate: remove stale temporary state: %w", err)
		}
		removed = true
	}
	if removed {
		return syncDir(dir)
	}
	return nil
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

func readJSON(path string, destination any) (bool, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("clientstate: open state file: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("clientstate: inspect state file: %w", err)
	}
	if err := validatePrivateFile(info, false); err != nil {
		return false, fmt.Errorf("clientstate: state file: %w", err)
	}
	if info.Size() < 0 || info.Size() > maxStateBytes {
		return false, errors.New("clientstate: state file exceeds limit")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, fmt.Errorf("clientstate: decode state file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false, errors.New("clientstate: state file contains trailing data")
	}
	return true, nil
}

func writeJSON(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > maxStateBytes {
		return errors.New("clientstate: state file exceeds limit")
	}
	dir := filepath.Dir(path)
	// Sync before rename and sync the directory after for crash-safe replacement.
	temporary, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("clientstate: create temporary state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("clientstate: write temporary state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("clientstate: sync temporary state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("clientstate: close temporary state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("clientstate: replace state file: %w", err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("clientstate: open state directory: %w", err)
	}
	err = directory.Sync()
	closeErr := directory.Close()
	return errors.Join(err, closeErr)
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
	if len(value) != len("route_")+32 || !strings.HasPrefix(value, "route_") {
		return false
	}
	_, err := hex.DecodeString(value[len("route_"):])
	return err == nil
}

func LockContext(ctx context.Context, store *Store, routeID string) (*Route, error) {
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
