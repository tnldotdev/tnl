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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type certificatePhase string

const (
	certificatePhasePending certificatePhase = "pending"
	certificatePhaseCurrent certificatePhase = "current"
)

var ErrCertificateExpired = errors.New("clientstate: application certificate is expired")

type CertificateCache struct {
	store    *Store
	teamID   string
	plan     controlv1.CertificatePlan
	planJSON string
}

type Pending struct {
	Key    *ecdsa.PrivateKey
	CSRDER []byte

	keyDER []byte
}

type Material struct {
	Certificate tls.Certificate
	RenewAt     time.Time
	IssuanceID  string
}

func (s *Store) Certificates(teamID string, plan controlv1.CertificatePlan) (*CertificateCache, error) {
	if teamID == "" || strings.TrimSpace(teamID) != teamID {
		return nil, errors.New("clientstate: certificate team is required")
	}
	plan, err := certificateidentity.CanonicalPlan(plan)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	return &CertificateCache{store: s, teamID: teamID, plan: plan, planJSON: string(encoded)}, nil
}

// Lock serializes a certificate transaction, not the tunnel using its material.
func (r *CertificateCache) Lock(ctx context.Context) (*Lock, error) {
	encoded, _ := json.Marshal([]string{r.teamID, r.plan.CacheKey})
	digest := sha256.Sum256(encoded)
	path := filepath.Join(r.store.locksDir, fmt.Sprintf("certificate-%x.lock", digest))
	return openLockContext(ctx, path, "certificate")
}

func (r *CertificateCache) Current(ctx context.Context, hostname string) (Material, bool, error) {
	return r.material(ctx, hostname, certificatePhaseCurrent)
}

func (r *CertificateCache) Staged(ctx context.Context, hostname string) (Material, bool, error) {
	return r.material(ctx, hostname, certificatePhasePending)
}

func (r *CertificateCache) material(ctx context.Context, hostname string, phase certificatePhase) (Material, bool, error) {
	stored, err := r.record(ctx, phase)
	if errors.Is(err, sql.ErrNoRows) {
		return Material{}, false, nil
	}
	if err != nil {
		return Material{}, false, fmt.Errorf("clientstate: read public URL certificate: %w", err)
	}
	if phase == certificatePhasePending && len(stored.CertificatePem) == 0 {
		return Material{}, false, nil
	}
	if len(stored.CsrDer) == 0 || !stored.RenewAt.Valid || stored.IssuanceID == "" {
		return Material{}, true, errors.New("clientstate: certificate metadata is invalid")
	}
	keyDER, err := r.store.secrets.Open(ctx, r.secretContext(), stored.KeyDer)
	if err != nil {
		return Material{}, true, err
	}
	certificate, err := certificate(keyDER, stored.CertificatePem, hostname, r.plan.Identifiers)
	if err != nil {
		return Material{}, true, err
	}
	if err := validateCSR(stored.CsrDer, certificate.PrivateKey, r.plan.Identifiers); err != nil {
		return Material{}, true, err
	}
	renewAt := unixNanoTime(stored.RenewAt.Int64)
	if !renewAt.After(certificate.Leaf.NotBefore) || !renewAt.Before(certificate.Leaf.NotAfter) {
		return Material{}, true, errors.New("clientstate: renewal time is outside certificate validity")
	}
	return Material{
		Certificate: certificate, RenewAt: renewAt, IssuanceID: stored.IssuanceID,
	}, true, nil
}

func (r *CertificateCache) Pending(ctx context.Context, hostname string) (Pending, error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return Pending{}, errors.New("clientstate: certificate plan does not cover hostname")
	}
	stored, err := r.record(ctx, certificatePhasePending)
	if err == nil {
		return r.pendingFromDB(ctx, stored, hostname)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Pending{}, fmt.Errorf("clientstate: read pending public URL certificate: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Pending{}, fmt.Errorf("clientstate: generate application key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Pending{}, fmt.Errorf("clientstate: encode application key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: r.plan.Identifiers}, key)
	if err != nil {
		return Pending{}, fmt.Errorf("clientstate: create application CSR: %w", err)
	}
	protectedKey, err := r.store.secrets.Seal(ctx, r.secretContext(), keyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := r.store.database.queries.UpsertCertificateMaterial(ctx, clientstatedb.UpsertCertificateMaterialParams{
		ServerOrigin: r.store.controlEndpoint, TeamID: r.teamID, CacheKey: r.plan.CacheKey, Plan: r.planJSON, Phase: string(certificatePhasePending),
		KeyDer: protectedKey, CsrDer: csrDER, IssuanceID: "",
		UpdatedAt: r.store.database.now().UTC().UnixNano(),
	}); err != nil {
		return Pending{}, fmt.Errorf("clientstate: save pending public URL certificate: %w", err)
	}
	return Pending{Key: key, CSRDER: csrDER, keyDER: keyDER}, nil
}

// Stage retains issued material without replacing the last acknowledged certificate.
// the caller holds Lock through staging, control acknowledgement, and promotion.
func (r *CertificateCache) Stage(
	ctx context.Context,
	hostname string,
	pending Pending,
	certificatePEM []byte,
	renewAt time.Time,
	issuanceID string,
) (Material, error) {
	if pending.Key == nil || len(pending.keyDER) == 0 || len(pending.CSRDER) == 0 || renewAt.IsZero() || issuanceID == "" {
		return Material{}, errors.New("clientstate: pending certificate material is incomplete")
	}
	installed, err := certificate(pending.keyDER, certificatePEM, hostname, r.plan.Identifiers)
	if err != nil {
		return Material{}, err
	}
	if err := validateCSR(pending.CSRDER, installed.PrivateKey, r.plan.Identifiers); err != nil {
		return Material{}, err
	}
	if !pending.Key.PublicKey.Equal(installed.PrivateKey.(*ecdsa.PrivateKey).Public()) {
		return Material{}, errors.New("clientstate: pending certificate key does not match")
	}
	if !renewAt.After(installed.Leaf.NotBefore) || !renewAt.Before(installed.Leaf.NotAfter) {
		return Material{}, errors.New("clientstate: renewal time is outside certificate validity")
	}
	protectedKey, err := r.store.secrets.Seal(ctx, r.secretContext(), pending.keyDER)
	if err != nil {
		return Material{}, err
	}
	if err := r.store.database.queries.UpsertCertificateMaterial(ctx, clientstatedb.UpsertCertificateMaterialParams{
		ServerOrigin: r.store.controlEndpoint, TeamID: r.teamID, CacheKey: r.plan.CacheKey, Plan: r.planJSON, Phase: string(certificatePhasePending),
		KeyDer: protectedKey, CsrDer: bytes.Clone(pending.CSRDER),
		CertificatePem: bytes.Clone(certificatePEM), RenewAt: sql.NullInt64{Int64: renewAt.UTC().UnixNano(), Valid: true},
		IssuanceID: issuanceID,
		UpdatedAt:  r.store.database.now().UTC().UnixNano(),
	}); err != nil {
		return Material{}, fmt.Errorf("clientstate: stage public URL certificate: %w", err)
	}
	return Material{
		Certificate: installed, RenewAt: renewAt.UTC(), IssuanceID: issuanceID,
	}, nil
}

func (r *CertificateCache) Promote(ctx context.Context, hostname, issuanceID string) error {
	material, found, err := r.Staged(ctx, hostname)
	if err != nil {
		return err
	}
	if !found || material.IssuanceID != issuanceID {
		return errors.New("clientstate: acknowledged certificate does not match staged material")
	}
	tx, err := r.store.database.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := r.store.database.queries.WithTx(tx)
	identity := clientstatedb.GetCertificateMaterialParams{
		ServerOrigin: r.store.controlEndpoint, TeamID: r.teamID, CacheKey: r.plan.CacheKey, Plan: r.planJSON, Phase: string(certificatePhasePending),
	}
	stored, err := queries.GetCertificateMaterial(ctx, identity)
	if err != nil {
		return err
	}
	if stored.IssuanceID != issuanceID {
		return errors.New("clientstate: staged certificate changed before promotion")
	}
	if err := queries.UpsertCertificateMaterial(ctx, clientstatedb.UpsertCertificateMaterialParams{
		ServerOrigin: stored.ServerOrigin, TeamID: stored.TeamID, CacheKey: stored.CacheKey, Plan: stored.Plan, Phase: string(certificatePhaseCurrent),
		KeyDer: stored.KeyDer, CsrDer: stored.CsrDer, CertificatePem: stored.CertificatePem,
		RenewAt: stored.RenewAt, IssuanceID: stored.IssuanceID, UpdatedAt: r.store.database.now().UTC().UnixNano(),
	}); err != nil {
		return err
	}
	if err := queries.DeleteCertificateMaterial(ctx, clientstatedb.DeleteCertificateMaterialParams(identity)); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *CertificateCache) NewPending(ctx context.Context, hostname string) (Pending, error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return Pending{}, errors.New("clientstate: certificate plan does not cover hostname")
	}
	if err := r.store.database.queries.DeleteCertificateMaterial(ctx, clientstatedb.DeleteCertificateMaterialParams{
		ServerOrigin: r.store.controlEndpoint, TeamID: r.teamID, CacheKey: r.plan.CacheKey, Plan: r.planJSON, Phase: string(certificatePhasePending),
	}); err != nil {
		return Pending{}, fmt.Errorf("clientstate: replace pending public URL certificate: %w", err)
	}
	return r.Pending(ctx, hostname)
}

func (r *CertificateCache) pendingFromDB(ctx context.Context, stored clientstatedb.CertificateMaterial, hostname string) (Pending, error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return Pending{}, errors.New("clientstate: pending certificate metadata is invalid")
	}
	keyDER, err := r.store.secrets.Open(ctx, r.secretContext(), stored.KeyDer)
	if err != nil {
		return Pending{}, err
	}
	key, err := parseKey(keyDER)
	if err != nil {
		return Pending{}, err
	}
	if err := validateCSR(stored.CsrDer, key, r.plan.Identifiers); err != nil {
		return Pending{}, err
	}
	return Pending{Key: key, CSRDER: bytes.Clone(stored.CsrDer), keyDER: keyDER}, nil
}

func (r *CertificateCache) record(ctx context.Context, phase certificatePhase) (clientstatedb.CertificateMaterial, error) {
	return r.store.database.queries.GetCertificateMaterial(ctx, clientstatedb.GetCertificateMaterialParams{
		ServerOrigin: r.store.controlEndpoint, TeamID: r.teamID, CacheKey: r.plan.CacheKey, Plan: r.planJSON, Phase: string(phase),
	})
}

func (r *CertificateCache) secretContext() string {
	encoded, _ := json.Marshal([]string{r.teamID, r.planJSON})
	return "certificate-private-key:" + string(encoded)
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
	if request.CheckSignature() != nil || !keyOK || !expectedOK || !publicKey.Equal(expected) ||
		len(request.EmailAddresses) != 0 ||
		len(request.IPAddresses) != 0 || len(request.URIs) != 0 || request.Subject.String() != "" ||
		!certificateidentity.Matches(request.Extensions, request.DNSNames, identifiers) {
		return errors.New("clientstate: pending CSR is invalid")
	}
	return nil
}

func certificate(keyDER, certificatePEM []byte, hostname string, identifiers []string) (tls.Certificate, error) {
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
		return nil, fmt.Errorf("clientstate: parse application key: %w", err)
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

func validPublicURLID(value string) bool {
	return opaqueid.Valid(value, "public_url_")
}
