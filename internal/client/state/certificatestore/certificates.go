package certificatestore

import (
	"bytes"
	"context"
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
	"io"
	"strings"
	"time"

	json "encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const maxCertificateFileBytes = 512 << 10

var ErrCertificateExpired = errors.New("clientstate: application certificate is expired")

type CertificateCache struct {
	server              string
	files               Storage
	teamID              string
	publisherIdentityID string
	plan                controlv1.CertificatePlan
	planJSON            string
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

// New binds the shared certificate engine to one protected storage scope.
// storage is already isolated to this exact server, team and publisher.
func New(files Storage, scope Scope, plan controlv1.CertificatePlan) (*CertificateCache, error) {
	if !opaqueid.Valid(scope.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) {
		return nil, errors.New("clientstate: enrolled publisher identity is required for certificate cache")
	}
	server, err := naming.CanonicalControlURL(scope.ControlURL)
	if files == nil || err != nil || server != scope.ControlURL || strings.TrimSpace(scope.TeamID) != scope.TeamID {
		return nil, errors.New("clientstate: certificate state store and exact ownership are required")
	}
	// guest publishers have no team. the real publisher identity, server, and
	// approved plan still isolate their durable material without a synthetic owner.
	plan, err = certificateidentity.CanonicalPlan(plan)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	return &CertificateCache{server: server, files: files, teamID: scope.TeamID, publisherIdentityID: scope.PublisherIdentityID, plan: plan, planJSON: string(encoded)}, nil
}

func certificateFilename(plan string) string {
	digest := sha256.Sum256([]byte(plan))
	return "certificate-" + hex.EncodeToString(digest[:]) + ".json"
}

// Lock serializes issuance across tasks sharing this durable directory. a
// separate short mutation lock lets readers observe complete atomic snapshots.
func (r *CertificateCache) Lock(ctx context.Context) (io.Closer, error) {
	digest := sha256.Sum256([]byte(r.plan.CacheKey))
	return r.files.Lock(ctx, fmt.Sprintf("issuance-%x.lock", digest))
}

func (r *CertificateCache) read(ctx context.Context) (certificateFile, error) {
	var value certificateFile
	data, found, err := r.files.Read(ctx, certificateFilename(r.planJSON), maxCertificateFileBytes)
	defer clear(data)
	if err != nil {
		return value, err
	}
	plans, err := r.checkpoints(ctx)
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
		return certificateFile{Version: 1, Server: r.server, Team: r.teamID, Publisher: r.publisherIdentityID, Plan: r.plan}, nil
	}
	if json.Unmarshal(data, &value, json.RejectUnknownMembers(true)) != nil || value.Version != 1 || value.Server != r.server || value.Team != r.teamID || value.Publisher != r.publisherIdentityID || !certificateidentity.SamePlan(value.Plan, r.plan) || value.Pending == nil && value.Current == nil {
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

func (r *CertificateCache) write(ctx context.Context, value certificateFile) error {
	data, err := json.Marshal(value)
	defer clear(data)
	if err != nil {
		return identityFileError(err)
	}
	if len(data) > maxCertificateFileBytes {
		return identityFileError(ErrPublisherStateConflict)
	}
	return r.files.Write(ctx, certificateFilename(r.planJSON), data)
}

func (r *CertificateCache) material(ctx context.Context, hostname string, staged bool) (result Material, found bool, resultErr error) {
	// the first write and its plan checkpoint are separate atomic records.
	// join the short mutation, not the issuance lock held during control calls.
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return Material{}, false, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Close(), context.Cause(ctx))
		if resultErr != nil {
			result = Material{}
		}
	}()
	value, err := r.read(ctx)
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
		err = r.files.Sync(ctx, certificateFilename(r.planJSON))
	}
	if err != nil {
		return Material{}, true, err
	}
	return Material{Certificate: loaded, RenewAt: stored.RenewAt, IssuanceID: stored.IssuanceID}, true, err
}

func (r *CertificateCache) Current(ctx context.Context, hostname string) (Material, bool, error) {
	return r.material(ctx, hostname, false)
}
func (r *CertificateCache) Staged(ctx context.Context, hostname string) (Material, bool, error) {
	return r.material(ctx, hostname, true)
}

func (r *CertificateCache) pending(ctx context.Context, hostname string, replace bool) (result Pending, resultErr error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return Pending{}, errors.New("clientstate: certificate plan does not cover hostname")
	}
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return Pending{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Close(), context.Cause(ctx))
		if resultErr != nil {
			clear(result.keyDER)
			result = Pending{}
		}
	}()
	checkpointLock, err := r.files.Lock(ctx, "certificate-plans.lock")
	if err != nil {
		return Pending{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, checkpointLock.Close()) }()
	value, err := r.read(ctx)
	if err != nil {
		return Pending{}, err
	}
	defer value.destroy()
	persist := ctx
	if value.Pending == nil || replace {
		first := value.Pending == nil && value.Current == nil
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
		if err := r.write(ctx, value); err != nil {
			return Pending{}, err
		}
		if first {
			// a confirmed first write must finish its checkpoint under the
			// same locks. cancellation still withholds the key from the caller.
			var stop context.CancelFunc
			persist, stop = context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer stop()
		}
	}
	key, err := parseKey(value.Pending.PrivateKeyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := r.files.Sync(persist, certificateFilename(r.planJSON)); err != nil {
		return Pending{}, err
	}
	// the complete plan checkpoint is durable before a CSR can leave this process.
	if err := r.checkpoint(persist); err != nil {
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
func (r *CertificateCache) Stage(ctx context.Context, hostname string, pending Pending, certificatePEM []byte, renewAt time.Time, issuanceID string) (result Material, resultErr error) {
	if pending.Key == nil || pending.scope != r.pendingScope() || len(pending.keyDER) == 0 || issuanceID == "" {
		return Material{}, errors.New("clientstate: pending certificate scope or material is invalid")
	}
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return Material{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Close(), context.Cause(ctx))
		if resultErr != nil {
			result = Material{}
		}
	}()
	value, err := r.read(ctx)
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
	if err := r.write(ctx, value); err != nil {
		return Material{}, err
	}
	return Material{Certificate: loaded, RenewAt: staged.RenewAt, IssuanceID: staged.IssuanceID}, nil
}

func (r *CertificateCache) Promote(ctx context.Context, hostname, issuanceID string) (result error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return errors.New("clientstate: certificate plan does not cover hostname")
	}
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close(), context.Cause(ctx)) }()
	value, err := r.read(ctx)
	if err != nil {
		return err
	}
	defer value.destroy()
	if value.Pending == nil && value.Current != nil && value.Current.IssuanceID == issuanceID {
		return r.files.Sync(ctx, certificateFilename(r.planJSON))
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
	return r.write(ctx, value)
}

func (r *CertificateCache) pendingScope() string {
	encoded, _ := json.Marshal([]string{r.server, r.teamID, r.publisherIdentityID, r.planJSON})
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

// MaterialExists checks a complete host-supplied record inventory against the
// durable plan checkpoint. the inventory must include every certificate record.
func MaterialExists(ctx context.Context, files Storage, scope Scope, entries []string) (bool, error) {
	foundAny := false
	plans := map[string]bool{}
	for _, entry := range entries {
		if entry == "certificate-plans-v1.json" {
			continue
		}
		if !strings.HasPrefix(entry, "certificate-") || !strings.HasSuffix(entry, ".json") {
			continue
		}
		data, _, err := files.Read(ctx, entry, maxCertificateFileBytes)
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
		cache, err := New(files, scope, value.Plan)
		value.destroy()
		if err != nil {
			return false, err
		}
		if entry != certificateFilename(cache.planJSON) {
			return false, identityFileError(ErrPublisherStateConflict)
		}
		checked, err := cache.read(ctx)
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
	probe := &CertificateCache{server: scope.ControlURL, files: files, teamID: scope.TeamID, publisherIdentityID: scope.PublisherIdentityID}
	checkpoint, err := probe.checkpoints(ctx)
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

// RequirePlans checks control's monotonic plan inventory, so
// restoring an entire older local checkpoint cannot hide a newer missing plan.
func RequirePlans(ctx context.Context, files Storage, scope Scope, plans []controlv1.CertificatePlan) error {
	if len(plans) == 0 || len(plans) > 1024 {
		return identityFileError(ErrPublisherStateConflict)
	}
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		cache, err := New(files, scope, plan)
		if err != nil {
			return err
		}
		value, err := cache.read(ctx)
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

func (r *CertificateCache) checkpoints(ctx context.Context) ([]controlv1.CertificatePlan, error) {
	data, found, err := r.files.Read(ctx, "certificate-plans-v1.json", maxCertificateFileBytes)
	if err != nil || !found {
		return nil, err
	}
	var checkpoint certificateCheckpoints
	if json.Unmarshal(data, &checkpoint, json.RejectUnknownMembers(true)) != nil || checkpoint.Version != 1 || checkpoint.Server != r.server || checkpoint.Team != r.teamID || checkpoint.Publisher != r.publisherIdentityID || len(checkpoint.Plans) == 0 || len(checkpoint.Plans) > 1024 {
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
func (r *CertificateCache) checkpoint(ctx context.Context) error {
	plans, err := r.checkpoints(ctx)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if certificateidentity.SamePlan(plan, r.plan) {
			return r.files.Sync(ctx, "certificate-plans-v1.json")
		}
	}
	if len(plans) >= 1024 {
		return identityFileError(ErrPublisherStateConflict)
	}
	plans = append(plans, r.plan)
	data, err := json.Marshal(certificateCheckpoints{Version: 1, Server: r.server, Team: r.teamID, Publisher: r.publisherIdentityID, Plans: plans})
	if err != nil || len(data) > maxCertificateFileBytes {
		return identityFileError(ErrPublisherStateConflict)
	}
	return r.files.Write(ctx, "certificate-plans-v1.json", data)
}

func validateCSR(csrDER []byte, key *ecdsa.PrivateKey, identifiers []string) error {
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return errors.New("clientstate: pending CSR is invalid")
	}
	if key == nil {
		return errors.New("clientstate: pending CSR key is invalid")
	}
	publicKey, keyOK := request.PublicKey.(*ecdsa.PublicKey)
	if request.CheckSignature() != nil || !keyOK || !publicKey.Equal(&key.PublicKey) || len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 || len(request.URIs) != 0 || request.Subject.String() != "" || !certificateidentity.Matches(request.Extensions, request.DNSNames, identifiers) {
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
