package state

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
type ServiceTargetTLS struct {
	Hostname string `json:"hostname"`
	System   bool   `json:"system"`
	PEM      string `json:"pem,omitempty"`
	Digest   string `json:"digest"`
}

type ServiceMetadata struct {
	Protocol      string            `json:"protocol"`
	TLS           *ServiceTargetTLS `json:"target_tls,omitempty"`
	PublisherPool bool              `json:"publisher_pool"`
	TrustRevision int64             `json:"trust_revision"`
	Endpoint      *ServiceEndpoint  `json:"endpoint,omitempty"`
}

type ServiceEndpoint struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Public   bool   `json:"public"`
}

func (m ServiceMetadata) Validate() error {
	if m.Protocol != "http" && m.Protocol != "tcp" && m.Protocol != "mysql" && m.Protocol != "postgres" && m.Protocol != "kubernetes" {
		return ErrServiceConflict
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
		return ErrServiceConflict
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
		return ErrServiceConflict
	}
	if system {
		return nil
	}
	remaining := []byte(caPEM)
	count := 0
	for len(bytes.TrimSpace(remaining)) != 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(remaining), []byte("-----BEGIN CERTIFICATE-----")) {
			return ErrServiceConflict
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return ErrServiceConflict
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrServiceConflict
		}
		count++
		if count > 32 {
			return ErrServiceConflict
		}
		remaining = rest
	}
	if count == 0 {
		return ErrServiceConflict
	}
	return nil
}

func checkedServiceMetadata(row controlstatedb.ControlService) (ServiceMetadata, error) {
	m, err := decodeServiceMetadata(row.Protocol, row.TlsMetadata, row.PublisherPool, row.TrustRevision)
	if err != nil {
		return m, err
	}
	if row.CertificateHostname != "" && row.ServicePort.Valid {
		m.Endpoint = managedServiceTLS(row.CertificateHostname, int(row.ServicePort.Int32), row.Public)
	}
	return m, nil
}

func managedServiceTLS(hostname string, port int, public bool) *ServiceEndpoint {
	if hostname == "" || port == 0 {
		return nil
	}
	return &ServiceEndpoint{Hostname: hostname, Port: port, Public: public}
}

func serviceMetadataMatches(saved ServiceMetadata, declared ServiceMetadata) bool {
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
func (d *Database) ConfigureService(ctx context.Context, serviceID, actorID string, metadata ServiceMetadata, now time.Time) (result ServiceRecord, retErr error) {
	if err := metadata.Validate(); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "configure service", &retErr)()
	row, err := lockService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	if err = rejectProjectManagedDefinition(ctx, tx, serviceID); err != nil {
		return result, err
	}
	saved, err := checkedServiceMetadata(row)
	if err != nil {
		return result, err
	}
	if metadata.TrustRevision != saved.TrustRevision {
		return result, ErrServiceConflict
	}
	changed := !serviceMetadataMatches(saved, metadata)
	configurationChanged := changed || saved.PublisherPool != metadata.PublisherPool
	if configurationChanged {
		if _, err = nextPrivateRevision(saved.TrustRevision); err != nil {
			return result, err
		}
	}
	if !metadata.PublisherPool && saved.PublisherPool {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL AND publisher_expires_at>$2`, serviceID, now).Scan(&count); err != nil {
			return result, err
		}
		if count > 1 {
			return result, ErrServiceConflict
		}
	}
	var encoded []byte
	if metadata.TLS != nil {
		encoded, err = json.Marshal(metadata.TLS)
		if err != nil {
			return result, err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2, tls_metadata=convert_from($3::bytea,'UTF8')::jsonb, publisher_pool=$4,
	    trust_revision=trust_revision+CASE WHEN $5 THEN 1 ELSE 0 END, updated_at=$6 WHERE id=$1`, serviceID, metadata.Protocol, encoded, metadata.PublisherPool, configurationChanged, now)
	if err != nil {
		return result, err
	}
	if changed {
		if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET state='closed', closed_at=$2 WHERE service_id=$1 AND closed_at IS NULL`, serviceID, now); err != nil {
			return result, err
		}
		if err = serviceRoutingTombstone(ctx, controlstatedb.New(tx), serviceID, now); err != nil {
			return result, err
		}
	}
	row, err = controlstatedb.New(tx).LockService(ctx, serviceID)
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
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

var ErrServiceMetadata = errors.New("saved service trust is invalid")

func decodeServiceMetadata(protocol string, encoded []byte, pool bool, revision int64) (ServiceMetadata, error) {
	m := ServiceMetadata{Protocol: protocol, PublisherPool: pool, TrustRevision: revision}
	if len(encoded) > 0 {
		if err := json.Unmarshal(encoded, &m.TLS); err != nil {
			return ServiceMetadata{}, ErrServiceMetadata
		}
	}
	if revision < 1 || m.Validate() != nil {
		return ServiceMetadata{}, ErrServiceMetadata
	}
	return m, nil
}

type LocalServiceSource struct {
	ProjectKey        string `json:"project_key"`
	SourceFingerprint string `json:"source_fingerprint"`
	Service           string `json:"service"`
	WorktreeKey       string `json:"worktree_key"`
}

func (d *Database) GetServiceForPublisher(ctx context.Context, id string, publisher PublisherIdentity, now time.Time) (result ServiceRecord, retErr error) {
	if !servicePublisherMatches(publisher, id) {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read publisher service", &retErr)()
	if err = lockServiceAdmission(ctx, tx, id); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).SelectServiceForPublisher(ctx, controlstatedb.SelectServiceForPublisherParams{ServiceID: id, PublisherIdentityID: publisher.ID, PublisherGrantID: publisher.GrantID, Now: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	settings, err := d.serviceHTTPSettings(ctx, controlstatedb.New(tx), id)
	if err != nil {
		return result, err
	}
	if settings != nil && settings.Limits != nil {
		limits := settings.Limits
		result.HTTPLimits = &ProjectHTTPApplicationLimits{Total: limits.Total, Concurrency: limits.Concurrency}
		if limits.Rate != nil {
			result.HTTPLimits.Rate = &ProjectApplicationRate{Count: *limits.Rate.Count, Per: limits.Rate.Per.Value().String(), Burst: limits.Rate.Burst}
		}
	}
	if err = serviceSource(ctx, controlstatedb.New(tx), &result); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
