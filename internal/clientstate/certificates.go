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
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	json "encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const maxCertificateFileBytes = 512 << 10

var ErrCertificateExpired = errors.New("clientstate: application certificate is expired")

type CertificateCache struct {
	store       *Store
	files       *PrivateDirectory
	teamID      string
	publisherID string
	plan        controlv1.CertificatePlan
	planJSON    string
}

type Pending struct {
	Key    *ecdsa.PrivateKey
	CSRDER []byte
	keyDER []byte
	scope  string
}

type Material struct {
	Certificate tls.Certificate
	RenewAt     time.Time
	IssuanceID  string
}

type storedCertificate struct {
	PrivateKeyDER  []byte    `json:"private_key_der"`
	CSRDER         []byte    `json:"csr_der"`
	CertificatePEM []byte    `json:"certificate_pem,omitempty"`
	RenewAt        time.Time `json:"renew_at,omitempty"`
	IssuanceID     string    `json:"issuance_id,omitempty"`
}

type certificateFile struct {
	Version   int                       `json:"version"`
	Server    string                    `json:"server"`
	Team      string                    `json:"team_id"`
	Publisher string                    `json:"publisher_identity_id"`
	Plan      controlv1.CertificatePlan `json:"plan"`
	Pending   *storedCertificate        `json:"pending,omitempty"`
	Current   *storedCertificate        `json:"current,omitempty"`
}

func (storedCertificate) String() string   { return "private publisher certificate material" }
func (storedCertificate) GoString() string { return "private publisher certificate material" }
func (certificateFile) String() string     { return "private publisher certificate file" }
func (certificateFile) GoString() string   { return "private publisher certificate file" }

func (f *certificateFile) destroy() {
	if f.Pending != nil {
		clear(f.Pending.PrivateKeyDER)
	}
	if f.Current != nil {
		clear(f.Current.PrivateKeyDER)
	}
}

func (s *Store) Certificates(teamID string, plan controlv1.CertificatePlan) (*CertificateCache, error) {
	return s.certificateCache(teamID, "", plan)
}

// CertificatesForPublisher uses the same durable filesystem in development and
// deployed publishers. neither SQLite nor its wrapping key owns TLS material.
func (s *Store) CertificatesForPublisher(teamID, publisherID string, plan controlv1.CertificatePlan) (*CertificateCache, error) {
	if !opaqueid.Valid(publisherID, opaqueid.PublisherIdentityPrefix) {
		return nil, errors.New("clientstate: enrolled publisher identity is required for certificate cache")
	}
	return s.certificateCache(teamID, publisherID, plan)
}

func (s *Store) certificateCache(teamID, publisherID string, plan controlv1.CertificatePlan) (*CertificateCache, error) {
	if s == nil || teamID == "" || strings.TrimSpace(teamID) != teamID {
		return nil, errors.New("clientstate: certificate state store and team are required")
	}
	plan, err := certificateidentity.CanonicalPlan(plan)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	files, err := s.PublisherIdentityFiles(teamID, publisherID)
	if err != nil {
		return nil, err
	}
	return &CertificateCache{store: s, files: files, teamID: teamID, publisherID: publisherID, plan: plan, planJSON: string(encoded)}, nil
}

func certificateFilename(plan string) string {
	digest := sha256.Sum256([]byte(plan))
	return "certificate-" + hex.EncodeToString(digest[:]) + ".json"
}

// Lock serializes issuance across tasks sharing this durable directory. a
// separate short mutation lock lets readers observe complete atomic snapshots.
func (r *CertificateCache) Lock(ctx context.Context) (*Lock, error) {
	digest := sha256.Sum256([]byte(r.plan.CacheKey))
	return r.files.Lock(ctx, fmt.Sprintf("issuance-%x.lock", digest))
}

func LockPublisherHostnameContext(ctx context.Context, store *Store, hostname, publisherID string) (*Lock, error) {
	if store == nil || !opaqueid.Valid(publisherID, opaqueid.PublisherIdentityPrefix) {
		return nil, errors.New("clientstate: state store and enrolled publisher identity are required")
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return nil, errors.New("clientstate: canonical publisher hostname is required")
	}
	files, err := store.PublisherIdentityFiles("", publisherID)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(hostname))
	return files.Lock(ctx, fmt.Sprintf("hostname-%x.lock", digest))
}

func (r *CertificateCache) read() (certificateFile, error) {
	var value certificateFile
	data, found, err := r.files.Read(certificateFilename(r.planJSON), maxCertificateFileBytes)
	defer clear(data)
	if err != nil {
		return value, err
	}
	plans, err := r.checkpoints()
	if err != nil {
		return value, err
	}
	checkpointed := false
	for _, plan := range plans {
		if certificateidentity.SamePlan(plan, r.plan) {
			checkpointed = true
		}
	}
	if found != checkpointed {
		return value, identityFileError(ErrPublisherStateConflict)
	}
	if !found {
		return certificateFile{Version: 1, Server: r.store.controlEndpoint, Team: r.teamID, Publisher: r.publisherID, Plan: r.plan}, nil
	}
	if json.Unmarshal(data, &value, json.RejectUnknownMembers(true)) != nil || value.Version != 1 || value.Server != r.store.controlEndpoint || value.Team != r.teamID || value.Publisher != r.publisherID || !certificateidentity.SamePlan(value.Plan, r.plan) || value.Pending == nil && value.Current == nil {
		value.destroy()
		return certificateFile{}, identityFileError(ErrPublisherStateConflict)
	}
	for _, material := range []*storedCertificate{value.Pending, value.Current} {
		if material != nil {
			if err := validateStoredCertificate(material, r.plan, material == value.Current); err != nil {
				value.destroy()
				return certificateFile{}, identityFileError(err)
			}
		}
	}
	return value, nil
}

func (r *CertificateCache) write(value certificateFile) error {
	data, err := json.Marshal(value)
	defer clear(data)
	if err != nil {
		return identityFileError(err)
	}
	if len(data) > maxCertificateFileBytes {
		return identityFileError(ErrPublisherStateConflict)
	}
	return r.files.Write(certificateFilename(r.planJSON), data)
}

func (r *CertificateCache) material(hostname string, staged bool) (Material, bool, error) {
	value, err := r.read()
	if err != nil {
		return Material{}, false, err
	}
	defer value.destroy()
	stored := value.Current
	if staged {
		stored = value.Pending
	}
	if stored == nil || len(stored.CertificatePEM) == 0 {
		return Material{}, false, nil
	}
	loaded, err := certificate(stored.PrivateKeyDER, stored.CertificatePEM, hostname, r.plan.Identifiers)
	if err == nil && staged {
		err = r.files.Sync(certificateFilename(r.planJSON))
	}
	if err != nil {
		return Material{}, true, err
	}
	return Material{Certificate: loaded, RenewAt: stored.RenewAt, IssuanceID: stored.IssuanceID}, true, err
}

func (r *CertificateCache) Current(_ context.Context, hostname string) (Material, bool, error) {
	return r.material(hostname, false)
}
func (r *CertificateCache) Staged(_ context.Context, hostname string) (Material, bool, error) {
	return r.material(hostname, true)
}

func (r *CertificateCache) pending(ctx context.Context, hostname string, replace bool) (Pending, error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return Pending{}, errors.New("clientstate: certificate plan does not cover hostname")
	}
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return Pending{}, err
	}
	defer lock.Close()
	checkpointLock, err := r.files.Lock(ctx, "certificate-plans.lock")
	if err != nil {
		return Pending{}, err
	}
	defer checkpointLock.Close()
	value, err := r.read()
	if err != nil {
		return Pending{}, err
	}
	defer value.destroy()
	if value.Pending == nil || replace {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return Pending{}, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return Pending{}, err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: r.plan.Identifiers}, key)
		if err != nil {
			clear(der)
			return Pending{}, err
		}
		if value.Pending != nil {
			clear(value.Pending.PrivateKeyDER)
		}
		value.Pending = &storedCertificate{PrivateKeyDER: der, CSRDER: csr}
		if err := r.write(value); err != nil {
			return Pending{}, err
		}
	}
	key, err := parseKey(value.Pending.PrivateKeyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := r.files.Sync(certificateFilename(r.planJSON)); err != nil {
		return Pending{}, err
	}
	// the complete plan checkpoint is durable before a CSR can leave this process.
	if err := r.checkpoint(); err != nil {
		return Pending{}, err
	}
	return Pending{Key: key, CSRDER: bytes.Clone(value.Pending.CSRDER), keyDER: bytes.Clone(value.Pending.PrivateKeyDER), scope: r.pendingScope()}, nil
}

func (r *CertificateCache) Pending(ctx context.Context, hostname string) (Pending, error) {
	return r.pending(ctx, hostname, false)
}
func (r *CertificateCache) NewPending(ctx context.Context, hostname string) (Pending, error) {
	return r.pending(ctx, hostname, true)
}

// Stage persists issued material alongside the current certificate before the
// caller acknowledges installation to control.
func (r *CertificateCache) Stage(ctx context.Context, hostname string, pending Pending, certificatePEM []byte, renewAt time.Time, issuanceID string) (Material, error) {
	if pending.Key == nil || pending.scope != r.pendingScope() || len(pending.keyDER) == 0 || issuanceID == "" {
		return Material{}, errors.New("clientstate: pending certificate scope or material is invalid")
	}
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return Material{}, err
	}
	defer lock.Close()
	value, err := r.read()
	if err != nil {
		return Material{}, err
	}
	defer value.destroy()
	if value.Pending == nil || !bytes.Equal(value.Pending.CSRDER, pending.CSRDER) || !bytes.Equal(value.Pending.PrivateKeyDER, pending.keyDER) {
		return Material{}, errors.New("clientstate: pending certificate changed before staging")
	}
	staged := &storedCertificate{PrivateKeyDER: bytes.Clone(pending.keyDER), CSRDER: bytes.Clone(pending.CSRDER), CertificatePEM: bytes.Clone(certificatePEM), RenewAt: renewAt.UTC(), IssuanceID: issuanceID}
	defer clear(staged.PrivateKeyDER)
	if err := validateStoredCertificate(staged, r.plan, true); err != nil {
		return Material{}, err
	}
	loaded, err := certificate(staged.PrivateKeyDER, staged.CertificatePEM, hostname, r.plan.Identifiers)
	if err != nil {
		return Material{}, err
	}
	if !pending.Key.PublicKey.Equal(loaded.PrivateKey.(*ecdsa.PrivateKey).Public()) {
		return Material{}, errors.New("clientstate: pending certificate key does not match")
	}
	clear(value.Pending.PrivateKeyDER)
	value.Pending = staged
	if err := r.write(value); err != nil {
		return Material{}, err
	}
	return Material{Certificate: loaded, RenewAt: staged.RenewAt, IssuanceID: staged.IssuanceID}, nil
}

func (r *CertificateCache) Promote(ctx context.Context, hostname, issuanceID string) error {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return errors.New("clientstate: certificate plan does not cover hostname")
	}
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	value, err := r.read()
	if err != nil {
		return err
	}
	defer value.destroy()
	if value.Pending == nil && value.Current != nil && value.Current.IssuanceID == issuanceID {
		return r.files.Sync(certificateFilename(r.planJSON))
	}
	if value.Pending == nil || value.Pending.IssuanceID != issuanceID || len(value.Pending.CertificatePEM) == 0 {
		return errors.New("clientstate: acknowledged certificate does not match staged material")
	}
	if _, err = certificate(value.Pending.PrivateKeyDER, value.Pending.CertificatePEM, hostname, r.plan.Identifiers); err != nil {
		return err
	}
	if value.Current != nil {
		clear(value.Current.PrivateKeyDER)
	}
	value.Current, value.Pending = value.Pending, nil
	return r.write(value)
}

func (r *CertificateCache) pendingScope() string {
	encoded, _ := json.Marshal([]string{r.store.controlEndpoint, r.teamID, r.publisherID, r.planJSON})
	return string(encoded)
}

func validateStoredCertificate(material *storedCertificate, plan controlv1.CertificatePlan, issued bool) error {
	if len(material.PrivateKeyDER) == 0 || len(material.PrivateKeyDER) > 1024 || len(material.CSRDER) == 0 || len(material.CSRDER) > 8192 || len(material.CertificatePEM) > 128<<10 {
		return ErrPublisherStateConflict
	}
	key, err := parseKey(material.PrivateKeyDER)
	if err != nil || validateCSR(material.CSRDER, key, plan.Identifiers) != nil {
		return ErrPublisherStateConflict
	}
	if len(material.CertificatePEM) == 0 {
		if issued || !material.RenewAt.IsZero() || material.IssuanceID != "" {
			return ErrPublisherStateConflict
		}
		return nil
	}
	block, _ := pem.Decode(material.CertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || material.IssuanceID == "" || len(material.IssuanceID) > 128 {
		return ErrPublisherStateConflict
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !material.RenewAt.After(leaf.NotBefore) || !material.RenewAt.Before(leaf.NotAfter) {
		return ErrPublisherStateConflict
	}
	// expired material is still a valid recovery record. usability is checked
	// against the real clock when a caller requests its TLS certificate.
	_, err = certificateidentity.ValidateIssuedCertificate(material.CertificatePEM, material.CSRDER, plan.Identifiers, leaf.NotBefore.Add(time.Second))
	return err
}

func (s *Store) PublisherCertificateMaterialExists(ctx context.Context, team, publisher string) (bool, error) {
	files, err := s.PublisherIdentityFiles(team, publisher)
	if err != nil {
		return false, err
	}
	entries, err := os.ReadDir(files.Path())
	if err != nil {
		return false, identityFileError(err)
	}
	foundAny := false
	plans := map[string]bool{}
	for _, entry := range entries {
		if entry.Name() == "certificate-plans-v1.json" {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "certificate-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, _, err := files.Read(entry.Name(), maxCertificateFileBytes)
		if err != nil {
			return false, err
		}
		var value certificateFile
		err = json.Unmarshal(data, &value, json.RejectUnknownMembers(true))
		clear(data)
		if err != nil {
			value.destroy()
			return false, identityFileError(err)
		}
		cache, err := s.CertificatesForPublisher(team, publisher, value.Plan)
		value.destroy()
		if err != nil {
			return false, err
		}
		if entry.Name() != certificateFilename(cache.planJSON) {
			return false, identityFileError(ErrPublisherStateConflict)
		}
		checked, err := cache.read()
		found := checked.Pending != nil || checked.Current != nil
		checked.destroy()
		if err != nil {
			return false, err
		}
		if found {
			foundAny = true
			plans[cache.planJSON] = true
		}
	}
	probe := &CertificateCache{store: s, files: files, teamID: team, publisherID: publisher}
	checkpoint, err := probe.checkpoints()
	if err != nil {
		return false, err
	}
	for _, plan := range checkpoint {
		if err := ctx.Err(); err != nil {
			return false, context.Cause(ctx)
		}
		data, _ := json.Marshal(plan)
		if !plans[string(data)] {
			return false, identityFileError(ErrPublisherStateConflict)
		}
	}
	return foundAny && len(checkpoint) != 0 && len(plans) == len(checkpoint), nil
}

// RequirePublisherCertificatePlans checks control's monotonic plan inventory, so
// restoring an entire older local checkpoint cannot hide a newer missing plan.
func (s *Store) RequirePublisherCertificatePlans(ctx context.Context, team, publisher string, plans []controlv1.CertificatePlan) error {
	if len(plans) == 0 || len(plans) > 1024 {
		return identityFileError(ErrPublisherStateConflict)
	}
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		cache, err := s.CertificatesForPublisher(team, publisher, plan)
		if err != nil {
			return err
		}
		value, err := cache.read()
		found := value.Pending != nil || value.Current != nil
		value.destroy()
		if err != nil {
			return err
		}
		if !found {
			return identityFileError(ErrPublisherStateConflict)
		}
	}
	return nil
}

type certificateCheckpoints struct {
	Version   int                         `json:"version"`
	Server    string                      `json:"server"`
	Team      string                      `json:"team_id"`
	Publisher string                      `json:"publisher_identity_id"`
	Plans     []controlv1.CertificatePlan `json:"plans"`
}

func (r *CertificateCache) checkpoints() ([]controlv1.CertificatePlan, error) {
	data, found, err := r.files.Read("certificate-plans-v1.json", maxCertificateFileBytes)
	if err != nil || !found {
		return nil, err
	}
	var checkpoint certificateCheckpoints
	if json.Unmarshal(data, &checkpoint, json.RejectUnknownMembers(true)) != nil || checkpoint.Version != 1 || checkpoint.Server != r.store.controlEndpoint || checkpoint.Team != r.teamID || checkpoint.Publisher != r.publisherID || len(checkpoint.Plans) == 0 || len(checkpoint.Plans) > 1024 {
		return nil, identityFileError(ErrPublisherStateConflict)
	}
	seen := map[string]bool{}
	for _, plan := range checkpoint.Plans {
		canonical, err := certificateidentity.CanonicalPlan(plan)
		encoded, _ := json.Marshal(canonical)
		if err != nil || !certificateidentity.SamePlan(canonical, plan) || seen[string(encoded)] {
			return nil, identityFileError(ErrPublisherStateConflict)
		}
		seen[string(encoded)] = true
	}
	return checkpoint.Plans, nil
}

// checkpoint runs under certificate-plans.lock after the key/CSR file is synced.
func (r *CertificateCache) checkpoint() error {
	plans, err := r.checkpoints()
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if certificateidentity.SamePlan(plan, r.plan) {
			return r.files.Sync("certificate-plans-v1.json")
		}
	}
	if len(plans) >= 1024 {
		return identityFileError(ErrPublisherStateConflict)
	}
	plans = append(plans, r.plan)
	data, err := json.Marshal(certificateCheckpoints{Version: 1, Server: r.store.controlEndpoint, Team: r.teamID, Publisher: r.publisherID, Plans: plans})
	if err != nil || len(data) > maxCertificateFileBytes {
		return identityFileError(ErrPublisherStateConflict)
	}
	return r.files.Write("certificate-plans-v1.json", data)
}

func validateCSR(csrDER []byte, key any, identifiers []string) error {
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
	if request.CheckSignature() != nil || !keyOK || !expectedOK || !publicKey.Equal(expected) || len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 || len(request.URIs) != 0 || request.Subject.String() != "" || !certificateidentity.Matches(request.Extensions, request.DNSNames, identifiers) {
		return errors.New("clientstate: pending CSR is invalid")
	}
	return nil
}

func certificate(keyDER, certificatePEM []byte, hostname string, identifiers []string) (tls.Certificate, error) {
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	result, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("clientstate: load application certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(result.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	if !leaf.NotAfter.After(time.Now()) {
		return tls.Certificate{}, ErrCertificateExpired
	}
	leaf, err = certificateidentity.ValidateCertificate(result, hostname, identifiers)
	if err != nil {
		return tls.Certificate{}, err
	}
	result.Leaf = leaf
	return result, nil
}

func parseKey(keyDER []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("clientstate: application key is not ECDSA P-256")
	}
	return key, nil
}

func databaseVersion(publishRunNumber uint64) (int64, error) {
	if publishRunNumber > math.MaxInt64 {
		return 0, errors.New("clientstate: publish run number exceeds database range")
	}
	return int64(publishRunNumber), nil
}

func unixNanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

func validPublicURLID(value string) bool { return opaqueid.Valid(value, opaqueid.PublicURLPrefix) }
