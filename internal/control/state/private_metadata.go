package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// private metadata contains public trust material only, never a target address,
// target credential, local path, remote bundle URL, or publisher private key.
type PrivateServiceTLS struct {
	Hostname string `json:"hostname"`
	System   bool   `json:"system"`
	PEM      string `json:"pem,omitempty"`
	Digest   string `json:"digest"`
}

type PrivateServiceMetadata struct {
	Protocol      string             `json:"protocol"`
	TLS           *PrivateServiceTLS `json:"target_tls,omitempty"`
	PublisherPool bool               `json:"publisher_pool"`
	TrustRevision int64              `json:"trust_revision"`
	ManagedTLS    *ManagedServiceTLS `json:"managed_tls,omitempty"`
}

type ManagedServiceTLS struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Public   bool   `json:"public"`
}

func (m PrivateServiceMetadata) Validate() error {
	if m.Protocol != "http" && m.Protocol != "tcp" && m.Protocol != "mysql" && m.Protocol != "postgres" && m.Protocol != "kubernetes" {
		return ErrPrivateServiceConflict
	}
	if m.TLS == nil {
		return nil
	}
	s := m.TLS
	mode := "pem"
	if s.System {
		mode = "system"
	}
	digest := sha256.Sum256([]byte(s.Hostname + "\x00" + mode + "\x00" + s.PEM))
	if s.Digest != hex.EncodeToString(digest[:]) {
		return ErrPrivateServiceConflict
	}
	return validateServiceTrustRoots(s.Hostname, s.PEM, s.System)
}

// applied and saved-service snapshots use the same CA and hostname rules.
func validateServiceTrustRoots(hostname, caPEM string, system bool) error {
	host, err := naming.CanonicalizeHostname(hostname)
	if ip, ipErr := netip.ParseAddr(hostname); ipErr == nil {
		host, err = ip.String(), nil
	}
	if err != nil || host != hostname || len(caPEM) > 1<<20 || system == (caPEM != "") {
		return ErrPrivateServiceConflict
	}
	if system {
		return nil
	}
	remaining := []byte(caPEM)
	count := 0
	for len(bytes.TrimSpace(remaining)) != 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(remaining), []byte("-----BEGIN CERTIFICATE-----")) {
			return ErrPrivateServiceConflict
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return ErrPrivateServiceConflict
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrPrivateServiceConflict
		}
		count++
		if count > 32 {
			return ErrPrivateServiceConflict
		}
		remaining = rest
	}
	if count == 0 {
		return ErrPrivateServiceConflict
	}
	return nil
}

func checkedPrivateMetadata(row controlstatedb.ControlPrivateService) (PrivateServiceMetadata, error) {
	m, err := decodePrivateMetadata(row.Protocol, row.TlsMetadata, row.PublisherPool, row.TrustRevision)
	if err != nil {
		return m, err
	}
	if row.CertificateHostname != "" && row.ServicePort.Valid {
		m.ManagedTLS = managedServiceTLS(row.CertificateHostname, int(row.ServicePort.Int32), row.Public)
	}
	return m, nil
}

func managedServiceTLS(hostname string, port int, public bool) *ManagedServiceTLS {
	if hostname == "" || port == 0 {
		return nil
	}
	return &ManagedServiceTLS{Hostname: hostname, Port: port, Public: public}
}

func privateMetadataMatches(saved PrivateServiceMetadata, declared PrivateServiceMetadata) bool {
	if saved.Validate() != nil || declared.Validate() != nil {
		return false
	}
	if saved.Protocol != declared.Protocol || (saved.TLS == nil) != (declared.TLS == nil) {
		return false
	}
	return saved.TLS == nil || *saved.TLS == *declared.TLS
}

// metadata approval serializes with admission and publication. changing trust
// closes every old run so a visitor cannot receive bytes using old trust.
func (d *Database) ConfigurePrivateService(ctx context.Context, serviceID, actorID string, metadata PrivateServiceMetadata, now time.Time) (result PrivateServiceRecord, retErr error) {
	if err := metadata.Validate(); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "configure private service", &retErr)()
	row, err := lockManagedPrivateService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	if err = rejectProjectManagedDefinition(ctx, tx, serviceID); err != nil {
		return result, err
	}
	saved, err := checkedPrivateMetadata(row)
	if err != nil {
		return result, err
	}
	if metadata.TrustRevision != saved.TrustRevision {
		return result, ErrPrivateServiceConflict
	}
	changed := !privateMetadataMatches(saved, metadata)
	configurationChanged := changed || saved.PublisherPool != metadata.PublisherPool
	if configurationChanged {
		if _, err = nextPrivateRevision(saved.TrustRevision); err != nil {
			return result, err
		}
	}
	if !metadata.PublisherPool && saved.PublisherPool {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.private_service_runs WHERE private_service_id=$1 AND closed_at IS NULL AND publisher_expires_at>$2`, serviceID, now).Scan(&count); err != nil {
			return result, err
		}
		if count > 1 {
			return result, ErrPrivateServiceConflict
		}
	}
	var encoded []byte
	if metadata.TLS != nil {
		encoded, err = json.Marshal(metadata.TLS)
		if err != nil {
			return result, err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE control.private_services SET protocol=$2, tls_metadata=convert_from($3::bytea,'UTF8')::jsonb, publisher_pool=$4,
	    trust_revision=trust_revision+CASE WHEN $5 THEN 1 ELSE 0 END, updated_at=$6 WHERE id=$1`, serviceID, metadata.Protocol, encoded, metadata.PublisherPool, configurationChanged, now)
	if err != nil {
		return result, err
	}
	if changed {
		if _, err = tx.Exec(ctx, `UPDATE control.private_service_runs SET state='closed', closed_at=$2 WHERE private_service_id=$1 AND closed_at IS NULL`, serviceID, now); err != nil {
			return result, err
		}
		if err = privateRoutingTombstone(ctx, controlstatedb.New(tx), serviceID, now); err != nil {
			return result, err
		}
	}
	row, err = controlstatedb.New(tx).LockPrivateService(ctx, serviceID)
	if err != nil {
		return result, err
	}
	if configurationChanged {
		if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "service.update", strconv.FormatInt(row.TrustRevision, 10), now); err != nil {
			return result, err
		}
	}
	if changed {
		if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "trust.update", strconv.FormatInt(row.TrustRevision, 10), now); err != nil {
			return result, err
		}
	}
	result, err = checkedPrivateServiceRecord(row)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

var ErrPrivateServiceMetadata = errors.New("saved private service trust is invalid")

func decodePrivateMetadata(protocol string, encoded []byte, pool bool, revision int64) (PrivateServiceMetadata, error) {
	m := PrivateServiceMetadata{Protocol: protocol, PublisherPool: pool, TrustRevision: revision}
	if len(encoded) > 0 {
		if err := json.Unmarshal(encoded, &m.TLS); err != nil {
			return PrivateServiceMetadata{}, ErrPrivateServiceMetadata
		}
	}
	if revision < 1 || m.Validate() != nil {
		return PrivateServiceMetadata{}, ErrPrivateServiceMetadata
	}
	return m, nil
}

type LocalServiceSource struct {
	ProjectKey        string `json:"project_key"`
	SourceFingerprint string `json:"source_fingerprint"`
	Service           string `json:"service"`
	WorktreeKey       string `json:"worktree_key"`
}

func (d *Database) GetPrivateServiceForPublisher(ctx context.Context, id string, publisher PublisherIdentity, now time.Time) (result PrivateServiceRecord, retErr error) {
	if !privatePublisherMatches(publisher, id) {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read publisher private service", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, id); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).SelectPrivateServiceForPublisher(ctx, controlstatedb.SelectPrivateServiceForPublisherParams{PrivateServiceID: id, PublisherIdentityID: publisher.ID, PublisherGrantID: publisher.GrantID, Now: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	result, err = checkedPrivateServiceRecord(row)
	if err != nil {
		return result, err
	}
	settings, err := d.managedHTTPSettings(ctx, controlstatedb.New(tx), id)
	if err != nil {
		return result, err
	}
	if settings != nil && settings.Limits != nil {
		result.HTTPLimits = settings.Limits.HTTP
	}
	if err = privateServiceSource(ctx, controlstatedb.New(tx), &result); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
