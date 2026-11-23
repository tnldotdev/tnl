package state

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
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
	TrustRevision int64             `json:"trust_revision,string"`
	Endpoint      *ServiceEndpoint  `json:"endpoint,omitempty"`
}

type ServiceEndpoint struct {
	Hostname string `json:"hostname"`
	// HTTP uses shared 443; zero means a non-HTTP service has no reservation.
	// neither value selects a local connector listener or enables public access.
	Port   int  `json:"port"`
	Public bool `json:"public"`
}

func (m ServiceMetadata) Validate() error {
	if m.Protocol != "http" && m.Protocol != "tcp" && m.Protocol != "mysql" && m.Protocol != "postgres" && m.Protocol != "kubernetes" {
		return ErrServiceConflict
	}
	if m.TLS == nil {
		return nil
	}
	s := m.TLS
	if (targettrust.Snapshot{Hostname: s.Hostname, PEM: []byte(s.PEM), System: s.System, Digest: s.Digest}).Validate() != nil {
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
		m.Endpoint = managedServiceTLS(row.Protocol, row.CertificateHostname, int(row.ServicePort.Int32), row.Public)
	}
	return m, nil
}

func managedServiceTLS(protocol, hostname string, port int, public bool) *ServiceEndpoint {
	if !serviceendpoint.Valid(protocol, hostname, port, public) {
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

// update conditions describe observed state, independently of desired settings.
type ServiceUpdateConditions struct {
	ConfigurationDigest        string
	UnconditionalConfiguration bool
	PublisherPool              *bool
}

// metadata approval serializes with admission and publication. changing trust
// closes every old run so a visitor cannot receive bytes using old trust.
func (d *Database) ConfigureService(ctx context.Context, serviceID, actorID string, metadata ServiceMetadata, configuration *ProjectServiceConfiguration, conditions ServiceUpdateConditions, now time.Time) (result ServiceRecord, retErr error) {
	if conditions.PublisherPool != nil {
		conditions.PublisherPool = new(*conditions.PublisherPool)
	}
	clock := newAuthorizationClock(now)
	if err := conditions.ValidateConfiguration(configuration != nil); err != nil {
		return result, err
	}
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
	// allocations retain their immutable invocation intent even if storage is
	// damaged. project-owned declarations can only change through their owner.
	var allocated bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_namespace_allocations WHERE service_id=$1)`, serviceID).Scan(&allocated); err != nil {
		return result, err
	}
	if allocated {
		return result, ErrServiceConflict
	}
	saved, err := checkedServiceMetadata(row)
	if err != nil {
		return result, err
	}
	if metadata.TrustRevision != saved.TrustRevision ||
		conditions.PublisherPool != nil && *conditions.PublisherPool != saved.PublisherPool {
		return result, ErrServiceConflict
	}
	previous, err := d.serviceConfiguration(ctx, controlstatedb.New(tx), serviceID)
	if err != nil {
		return result, err
	}
	if conditions.ConfigurationDigest != "" {
		digest, err := serviceConfigurationDigest(previous)
		if err != nil {
			return result, err
		}
		if digest != conditions.ConfigurationDigest {
			return result, ErrServiceConflict
		}
	}
	declaration := previous
	if configuration != nil {
		declaration, err = normalizeServiceConfiguration(row.Name, configuration)
		if err != nil {
			return result, err
		}
	}
	if declaration != nil {
		trust, err := appliedServiceTargetTrust(declaration.TargetTLS)
		if err != nil {
			return result, err
		}
		if !serviceMetadataMatches(metadata, ServiceMetadata{Protocol: declaration.Protocol, TLS: trust}) {
			return result, ErrServiceConflict
		}
	}
	declarationChanged := !reflect.DeepEqual(previous, declaration)
	if declarationChanged {
		if err := requireServiceDeclarationEdit(ctx, tx, row, actorID, clock.current()); err != nil {
			return result, err
		}
	}
	changed := !serviceMetadataMatches(saved, metadata)
	if err := requireServiceProtocolChange(ctx, tx, row, metadata.Protocol); err != nil {
		return result, err
	}
	metadataChanged := changed || saved.PublisherPool != metadata.PublisherPool
	if changed {
		if _, err = nextPrivateRevision(saved.TrustRevision); err != nil {
			return result, err
		}
	}
	if !metadata.PublisherPool && saved.PublisherPool {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL AND publisher_expires_at>$2`, serviceID, clock.current()).Scan(&count); err != nil {
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
	now = clock.current()
	_, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2, tls_metadata=convert_from($3::bytea,'UTF8')::jsonb, publisher_pool=$4,
	    service_port=CASE WHEN protocol<>$2 THEN CASE WHEN $2='http' THEN 443 ELSE 0 END ELSE service_port END,
	    trust_revision=trust_revision+CASE WHEN $5 THEN 1 ELSE 0 END, updated_at=$6 WHERE id=$1`, serviceID, metadata.Protocol, encoded, metadata.PublisherPool, changed, now)
	if err != nil {
		return result, err
	}
	if configuration != nil {
		if err = d.saveServiceConfiguration(ctx, tx, serviceID, *declaration); err != nil {
			return result, err
		}
		if err = d.configureStandaloneServiceEndpoint(ctx, tx, row, actorID, *declaration, clock.current()); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.services SET ephemeral=$2,require_post_quantum=$3 WHERE id=$1`,
			serviceID, declaration.Ephemeral, declaration.RequirePostQuantum != nil && *declaration.RequirePostQuantum); err != nil {
			return result, err
		}
	}
	visitorTLSChanged := configuration != nil && row.RequirePostQuantum != (declaration.RequirePostQuantum != nil && *declaration.RequirePostQuantum)
	if changed || visitorTLSChanged {
		if err = closeServiceRuns(ctx, tx, serviceID, now); err != nil {
			return result, err
		}
	}
	row, err = controlstatedb.New(tx).LockService(ctx, serviceID)
	if err != nil {
		return result, err
	}
	if metadataChanged || declarationChanged {
		// several pool or declaration edits can share one trust revision.
		request, err := opaqueid.New(opaqueid.RequestPrefix)
		if err != nil {
			return result, err
		}
		if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "service.update", request, now); err != nil {
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

// the caller has checked current management and locked the service. cleanup and
// metadata management do not confer another member's declaration ownership.
func requireServiceDeclarationEdit(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, actor string, now time.Time) error {
	denied := ErrServiceAccess
	if _, signed := serviceActor(ctx); signed {
		denied = ErrServiceManagerRequired
	}
	owner, err := storedServiceSourceOwner(ctx, tx, service, false)
	if err != nil {
		if err == ErrServiceAccess {
			return denied
		}
		return err
	}
	facts, err := serviceHostnameAuthority(ctx, tx, service.TeamID.String, actor, service.DomainID.String, now)
	if err != nil {
		if err == ErrServiceAccess {
			return denied
		}
		return err
	}
	switch owner.scope {
	case NamespaceScopeMember:
		if owner.membership != facts.ActorMembershipID {
			return denied
		}
	case NamespaceScopeShared:
		if facts.ActorRole != "owner" && facts.ActorRole != "admin" {
			return denied
		}
	default:
		return denied
	}
	return nil
}

func requireServiceProtocolChange(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlService, protocol string) error {
	if row.Protocol == protocol {
		return nil
	}
	if row.Public {
		return ErrServiceConflict
	}
	var held bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_port_claims WHERE service_id=$1 AND state='held')`, row.ID).Scan(&held); err != nil {
		return err
	}
	if held {
		return ErrServiceConflict
	}
	return nil
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
	clock := newAuthorizationClock(now)
	if !servicePublisherSelectionMatches(publisher, id) {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read publisher service", &retErr)()
	if err = lockServiceForRun(ctx, tx, id); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).SelectServiceForPublisher(ctx, controlstatedb.SelectServiceForPublisherParams{ServiceID: id, PublisherIdentityID: publisher.ID, PublisherGrantID: publisher.GrantID, Now: timestamptz(clock.current())})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if _, err = publisherServicePermission(ctx, tx, publisher.ID, publisher.GrantID, publisher.KeyID, id, clock.current()); err != nil {
		return result, err
	}
	result, err = d.publisherServiceRecord(ctx, tx, row)
	if err != nil {
		return result, err
	}
	if _, err = publisherServicePermission(ctx, tx, publisher.ID, publisher.GrantID, publisher.KeyID, id, clock.current()); err != nil {
		return ServiceRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRecord{}, err
	}
	return result, nil
}

func (d *Database) publisherServiceRecord(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlService) (ServiceRecord, error) {
	result, err := checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	settings, err := d.serviceHTTPSettings(ctx, controlstatedb.New(tx), row.ID)
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
	if settings != nil && settings.RequestBodyIdleTimeout != nil {
		result.HTTPRequestBodyIdleTimeout = new(settings.RequestBodyIdleTimeout.Value().String())
	}
	if err = serviceSource(ctx, controlstatedb.New(tx), &result); err != nil {
		return result, err
	}
	return result, nil
}
