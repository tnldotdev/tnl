package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

var (
	ErrEnvironmentInvalid  = errors.New("environment targets or definition are invalid")
	ErrEnvironmentStale    = errors.New("environment mutation revision changed")
	ErrEnvironmentNotFound = errors.New("environment or definition revision was not found in this project")
	ErrEnvironmentRetired  = errors.New("environment is retired; its creation key cannot be reused")
)

func environmentOperationError(err error) error {
	if errors.Is(err, ErrProjectConfigurationInvalid) || errors.Is(err, ErrServiceDefinitionInvalid) {
		return errors.Join(ErrEnvironmentInvalid, err)
	}
	if errors.Is(err, ErrProjectConfigurationStale) {
		return errors.Join(ErrEnvironmentStale, err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.Join(ErrEnvironmentNotFound, err)
	}
	return err
}

// TLS is a normalized declaration, not the public shorthand. callers must
// approve system-CA trust and the destination hostname before entering state.
type EnvironmentTarget struct {
	Address   string                  `json:"address"`
	TLS       *ProjectTargetTLS       `json:"tls,omitempty"`
	Discovery *ProjectTargetDiscovery `json:"discovery,omitempty"`
	HTTP      *EnvironmentServiceHTTP `json:"http,omitempty"`
}

type EnvironmentTargets map[string]EnvironmentTarget

type EnvironmentService struct {
	Service       string `json:"service"`
	ServiceID     string `json:"service_id"`
	Protocol      string `json:"protocol"`
	Hostname      string `json:"hostname"`
	Port          int    `json:"port"`
	Public        bool   `json:"public"`
	TrustRevision int64  `json:"trust_revision"`
}

type Environment struct {
	ID         string `json:"id"`
	TeamID     string `json:"team_id"`
	ProjectKey string `json:"project_key"`
	Name       string `json:"name"`
	DomainID   string `json:"domain_id"`
	Public     bool   `json:"public"`
	// state-only until the collection API shape is reviewed.
	CollectionID              string                       `json:"-"`
	AppliedDefinitionRevision int64                        `json:"applied_definition_revision"`
	MutationRevision          int64                        `json:"mutation_revision"`
	ConfigurationHash         string                       `json:"configuration_hash"`
	Retired                   bool                         `json:"retired"`
	Targets                   EnvironmentTargets           `json:"targets"`
	Services                  []EnvironmentService         `json:"services"`
	Members                   []EnvironmentPublisherStatus `json:"-"`
}

type CreateEnvironmentRequest struct {
	Manager                                                      EnvironmentPublisherManager
	TeamID, ProjectKey, SourceFingerprint, ProjectLabel, ActorID string
	Name, IdempotencyKey                                         string
	CollectionID                                                 string
	DomainID                                                     string
	Public                                                       bool
	// required with CollectionID for new creation; identical retries retain their
	// original selection even after the collection's default or revision changes.
	ExpectedCollectionRevision int64
	// zero uses the collection default; an explicit revision takes precedence.
	DefinitionRevision int64
	Targets            EnvironmentTargets
	DNSAutomation      bool
	Now                time.Time
}

type EnvironmentApplication struct {
	EnvironmentID      string
	ExpectedRevision   int64
	DefinitionRevision int64
	// nil retains existing approvals; a non-nil map replaces the complete set.
	Targets EnvironmentTargets
	Public  *bool
}

type ApplyEnvironmentRequest struct {
	Manager                     EnvironmentPublisherManager
	TeamID, ProjectKey, ActorID string
	EnvironmentApplication
	DNSAutomation bool
	Now           time.Time
}

type ApplyEnvironmentsRequest struct {
	Manager                     EnvironmentPublisherManager
	TeamID, ProjectKey, ActorID string
	Items                       []EnvironmentApplication
	DNSAutomation               bool
	Now                         time.Time
}

type RetireEnvironmentRequest struct {
	Manager                                    EnvironmentPublisherManager
	TeamID, ProjectKey, ActorID, EnvironmentID string
	ExpectedRevision                           int64
	Now                                        time.Time
}

func authorizeEnvironmentManager(ctx context.Context, tx pgx.Tx, team, actor string) error {
	if _, err := controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	return serviceManager(ctx, tx, team, actor)
}

func validEnvironmentName(name string) bool {
	return len(name) > 0 && len(name) <= 128 && strings.TrimSpace(name) == name && !strings.ContainsFunc(name, unicode.IsControl)
}

func validEnvironmentKey(key string) bool {
	return len(key) <= 256 && strings.TrimSpace(key) == key && !strings.ContainsFunc(key, unicode.IsControl)
}

func environmentBindingProtocols(definition ServiceDefinition) map[string]string {
	protocols := make(map[string]string, len(definition.Services))
	for name, s := range definition.Services {
		protocols[name] = s.Protocol
	}
	return protocols
}

func normalizeEnvironmentTargets(targets EnvironmentTargets, definition ServiceDefinition) (environmentBindings, error) {
	bindings := environmentBindings{}
	data, err := json.Marshal(targets)
	if err != nil || len(data) > 512<<10 || len(targets) != len(definition.Services) {
		return nil, ErrEnvironmentInvalid
	}
	for name, t := range targets {
		shape, found := definition.Services[name]
		if !found {
			return nil, ErrEnvironmentInvalid
		}
		service, err := normalizeEnvironmentService(EnvironmentServicePublication{Protocol: shape.Protocol, Target: t.Address, TargetTLS: t.TLS, TargetDiscovery: t.Discovery, HTTP: t.HTTP})
		if err != nil {
			return nil, err
		}
		bindings[name] = environmentTargetBinding{Target: service.Target, TargetTLS: service.TargetTLS, TargetDiscovery: service.TargetDiscovery, HTTP: service.HTTP, protocol: service.Protocol}
	}
	if err = validateEnvironmentBindings(bindings, definition); err != nil {
		return nil, err
	}
	return bindings, nil
}

func validateEnvironmentBindings(bindings environmentBindings, definition ServiceDefinition) error {
	if len(bindings) != len(definition.Services) {
		return ErrEnvironmentInvalid
	}
	for name, s := range definition.Services {
		b, found := bindings[name]
		if !found {
			return ErrEnvironmentInvalid
		}
		if _, err := bindEnvironmentService(s.Protocol, b); err != nil {
			return err
		}
	}
	return nil
}

func environmentTargets(bindings environmentBindings) EnvironmentTargets {
	result := EnvironmentTargets{}
	for name, b := range bindings {
		result[name] = EnvironmentTarget{Address: b.Target, TLS: b.TargetTLS, Discovery: b.TargetDiscovery, HTTP: b.HTTP}
	}
	return result
}

type environmentEndpointSettings struct {
	DomainID string `json:"domain_id"`
	Public   bool   `json:"public"`
}

func environmentConfigurationHash(definition ServiceDefinition, bindings environmentBindings, endpoint environmentEndpointSettings) string {
	data, _ := json.Marshal([]any{definition, environmentTargets(bindings), endpoint})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func environmentCreationDigest(name string, revision int64, bindings environmentBindings, collection string, expectedCollectionRevision int64, endpoint environmentEndpointSettings) []byte {
	data, _ := json.Marshal([]any{name, revision, environmentTargets(bindings), collection, expectedCollectionRevision, endpoint})
	digest := sha256.Sum256(data)
	return digest[:]
}

func (d *Database) CreateEnvironment(ctx context.Context, r CreateEnvironmentRequest) (result Environment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(r.ProjectKey) || !fingerprintPattern.MatchString(r.SourceFingerprint) || !validEnvironmentName(r.Name) || !validEnvironmentKey(r.IdempotencyKey) || r.DefinitionRevision < 0 || r.DomainID != "" && !opaqueid.Valid(r.DomainID, opaqueid.DomainPrefix) {
		return result, ErrProjectConfigurationInvalid
	}
	if r.CollectionID == "" {
		if r.DefinitionRevision == 0 || r.ExpectedCollectionRevision != 0 {
			return result, ErrProjectConfigurationInvalid
		}
	} else if !opaqueid.Valid(r.CollectionID, opaqueid.CollectionPrefix) || r.ExpectedCollectionRevision < 1 {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create environment", &retErr)()
	manager, err := environmentManagement(ctx, tx, r.TeamID, r.ActorID, r.Manager)
	if err != nil {
		return result, err
	}
	r.ActorID = manager.identityID
	project, err := d.ensureDefinitionProject(ctx, tx, r.TeamID, r.ProjectKey, r.SourceFingerprint, r.ProjectLabel, r.ActorID, r.Now)
	if err != nil {
		return result, err
	}
	var collection controlstatedb.ControlCollection
	if r.CollectionID != "" {
		collection, err = controlstatedb.New(tx).LockCollection(ctx, controlstatedb.LockCollectionParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: r.CollectionID})
		if err != nil {
			return result, collectionOperationError(err)
		}
	}
	var previous string
	err = tx.QueryRow(ctx, `SELECT environment.id FROM control.environments environment WHERE environment.team_id=$1 AND environment.project_key=$2 AND (environment.name=$3 OR EXISTS(SELECT 1 FROM control.environment_creations creation WHERE creation.environment_id=environment.id AND creation.idempotency_key=$4)) ORDER BY environment.id LIMIT 1`, r.TeamID, r.ProjectKey, r.Name, r.IdempotencyKey).Scan(&previous)
	if err == nil {
		row, e := controlstatedb.New(tx).LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: previous})
		if e != nil {
			return result, e
		}
		// normalize a retry under its original immutable definition, not under
		// the environment's current application or the project's newest shape.
		definition, e := loadServiceDefinition(ctx, tx, r.TeamID, r.ProjectKey, row.InitialDefinitionRevision)
		if e != nil {
			return result, e
		}
		bindings, e := normalizeEnvironmentTargets(r.Targets, definition.Definition)
		if e != nil || row.CollectionID.String != r.CollectionID || !bytes.Equal(environmentCreationDigest(r.Name, r.DefinitionRevision, bindings, r.CollectionID, r.ExpectedCollectionRevision, environmentEndpointSettings{DomainID: r.DomainID, Public: r.Public}), row.CreationDigest) {
			return result, ErrServiceConflict
		}
		if row.RetiredAt.Valid {
			return result, ErrEnvironmentRetired
		}
		if err = manager.authorize(ctx, tx, ProvisioningScope{Operation: ProvisioningCreate, TeamID: r.TeamID, ProjectKey: r.ProjectKey, CollectionID: r.CollectionID, Services: definitionServiceNames(definition.Definition)}, false); err != nil {
			return Environment{}, err
		}
		if err = d.authorizeEnvironmentCreationRetry(ctx, tx, manager, row); err != nil {
			return Environment{}, err
		}
		if err = recordEnvironmentCreationKey(ctx, tx, r, row.ID); err != nil {
			return result, err
		}
		result, err = d.environmentStatus(ctx, tx, row)
		if err != nil {
			return result, err
		}
		if err = manager.finish(ctx, tx, r.TeamID); err != nil {
			return Environment{}, err
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	revision := r.DefinitionRevision
	if r.CollectionID != "" {
		if collection.MutationRevision != r.ExpectedCollectionRevision {
			return result, ErrCollectionStale
		}
		if revision == 0 {
			revision = collection.DefaultDefinitionRevision
		}
	}
	definition, err := loadServiceDefinition(ctx, tx, r.TeamID, r.ProjectKey, revision)
	if err != nil {
		return result, err
	}
	if definition.SourceFingerprint != project.SourceFingerprint {
		return result, ErrProjectSourceConflict
	}
	bindings, err := normalizeEnvironmentTargets(r.Targets, definition.Definition)
	if err != nil {
		return result, err
	}
	if err = manager.authorize(ctx, tx, ProvisioningScope{Operation: ProvisioningCreate, TeamID: r.TeamID, ProjectKey: r.ProjectKey, CollectionID: r.CollectionID, Services: definitionServiceNames(definition.Definition)}, false); err != nil {
		return Environment{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.environments WHERE team_id=$1 AND project_key=$2 AND retired_at IS NULL`, r.TeamID, r.ProjectKey).Scan(&count); err != nil {
		return result, err
	}
	if count >= 1024 {
		return result, ErrProjectConfigurationInvalid
	}
	id, err := opaqueid.New(opaqueid.EnvironmentPrefix)
	if err != nil {
		return result, err
	}
	group, err := opaqueid.New("pgrp_")
	if err != nil {
		return result, err
	}
	// the human selector never becomes a DNS label or a group capability.
	groupName := "env-" + strings.ToLower(id[len(opaqueid.EnvironmentPrefix):])
	_, err = tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name) VALUES($1,$2,$3,$4)`, group, r.TeamID, r.ProjectKey, groupName)
	if err != nil {
		return result, err
	}
	domain := r.DomainID
	if domain == "" {
		if err = tx.QueryRow(ctx, `SELECT default_domain_id FROM control.teams WHERE id=$1`, r.TeamID).Scan(&domain); err != nil {
			return result, err
		}
	}
	apply := serviceResourceMutation{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, DNSAutomation: r.DNSAutomation, Now: r.Now}
	if err = setServiceAuditIssuer(ctx, tx, manager.issuer()); err != nil {
		return result, err
	}
	if err = d.ensureEnvironmentNamespace(ctx, tx, apply, group, groupName, environmentNamespace{DomainID: domain, Public: r.Public}); err != nil {
		return result, err
	}
	hash := environmentConfigurationHash(definition.Definition, bindings, environmentEndpointSettings{DomainID: domain, Public: r.Public})
	_, err = tx.Exec(ctx, `INSERT INTO control.environments(id,team_id,project_key,name,group_id,applied_definition_revision,mutation_revision,configuration_hash,initial_definition_revision,creation_digest,created_by_identity_id,created_at,updated_at,collection_id,created_by_machine_id,provisioning_grant_id) VALUES($1,$2,$3,$4,$5,$6,1,$7,$6,$8,NULLIF($9,''),$10,$10,NULLIF($11,''),NULLIF($12,''),NULLIF($13,''))`, id, r.TeamID, r.ProjectKey, r.Name, group, revision, hash, environmentCreationDigest(r.Name, r.DefinitionRevision, bindings, r.CollectionID, r.ExpectedCollectionRevision, environmentEndpointSettings{DomainID: r.DomainID, Public: r.Public}), r.ActorID, r.Now, r.CollectionID, manager.machineID, manager.provisioningGrantID)
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.project_publisher_groups SET environment_id=$2 WHERE id=$1`, group, id); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: id})
	if err != nil {
		return result, err
	}
	if err = d.materializeEnvironment(ctx, tx, row, definition.Definition, nil, bindings, apply, manager.issuer()); err != nil {
		return result, err
	}
	if err = recordEnvironmentCreationKey(ctx, tx, r, id); err != nil {
		return result, err
	}
	result, err = d.environmentStatus(ctx, tx, row)
	if err != nil {
		return result, err
	}
	if err = manager.finish(ctx, tx, r.TeamID); err != nil {
		return Environment{}, err
	}
	return result, tx.Commit(ctx)
}

func recordEnvironmentCreationKey(ctx context.Context, tx pgx.Tx, r CreateEnvironmentRequest, id string) error {
	if r.IdempotencyKey == "" {
		return nil
	}
	var saved string
	err := tx.QueryRow(ctx, `INSERT INTO control.environment_creations(team_id,project_key,idempotency_key,environment_id) VALUES($1,$2,$3,$4) ON CONFLICT(team_id,project_key,idempotency_key) DO UPDATE SET environment_id=EXCLUDED.environment_id WHERE control.environment_creations.environment_id=EXCLUDED.environment_id RETURNING environment_id`, r.TeamID, r.ProjectKey, r.IdempotencyKey, id).Scan(&saved)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceConflict
	}
	return err
}

// one pinned definition and one approved binding set are the only source of
// publication facts. a missing environment or binding row is never a fallback.
func (d *Database) environmentProjection(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlEnvironment) (ServiceDefinition, environmentBindings, map[string]EnvironmentServicePublication, error) {
	return d.environmentProjectionQueries(ctx, controlstatedb.New(tx), row)
}

func (d *Database) environmentProjectionQueries(ctx context.Context, q *controlstatedb.Queries, row controlstatedb.ControlEnvironment) (ServiceDefinition, environmentBindings, map[string]EnvironmentServicePublication, error) {
	stored, err := q.ReadServiceDefinition(ctx, controlstatedb.ReadServiceDefinitionParams{TeamID: row.TeamID, ProjectKey: row.ProjectKey, Revision: row.AppliedDefinitionRevision})
	if err != nil {
		return ServiceDefinition{}, nil, nil, err
	}
	definition, err := decodeServiceDefinition(stored.Definition, stored.ConfigurationHash)
	if err != nil {
		return ServiceDefinition{}, nil, nil, err
	}
	settings, err := q.GetPublisherGroupBindings(ctx, row.GroupID)
	if err != nil {
		return ServiceDefinition{}, nil, nil, err
	}
	bindings, err := d.openEnvironmentTargets(settings)
	if err != nil {
		return ServiceDefinition{}, nil, nil, err
	}
	if err = validateEnvironmentBindings(bindings, definition); err != nil {
		return ServiceDefinition{}, nil, nil, err
	}
	group, err := q.GetEnvironmentPublisherGroup(ctx, row.GroupID)
	if err != nil {
		return ServiceDefinition{}, nil, nil, err
	}
	if group.EnvironmentID.String != row.ID || group.TeamID != row.TeamID || group.ProjectKey != row.ProjectKey || !group.DomainID.Valid {
		return ServiceDefinition{}, nil, nil, ErrEnvironmentInvalid
	}
	if row.ConfigurationHash != environmentConfigurationHash(definition, bindings, environmentEndpointSettings{DomainID: group.DomainID.String, Public: group.Public}) {
		return ServiceDefinition{}, nil, nil, ErrEnvironmentStale
	}
	services := make(map[string]EnvironmentServicePublication, len(definition.Services))
	for logical, s := range definition.Services {
		binding := bindings[logical]
		service, e := normalizeEnvironmentService(EnvironmentServicePublication{Protocol: s.Protocol, Target: binding.Target, TargetTLS: binding.TargetTLS, TargetDiscovery: binding.TargetDiscovery, HTTP: binding.HTTP})
		if e != nil {
			return ServiceDefinition{}, nil, nil, e
		}
		services[logical] = service
	}
	return definition, bindings, services, nil
}

func (d *Database) environmentServiceConfiguration(ctx context.Context, q *controlstatedb.Queries, environmentID, group, logical string) (EnvironmentServicePublication, error) {
	row, mapped, err := publisherGroupEnvironment(ctx, q, group)
	if err != nil {
		return EnvironmentServicePublication{}, err
	}
	if !mapped || row.ID != environmentID || row.RetiredAt.Valid {
		return EnvironmentServicePublication{}, ErrServiceAccess
	}
	_, _, c, err := d.environmentProjectionQueries(ctx, q, row)
	if err != nil {
		return EnvironmentServicePublication{}, err
	}
	s, ok := c[logical]
	if !ok {
		return EnvironmentServicePublication{}, ErrServiceAccess
	}
	return s, nil
}

func (d *Database) ApplyEnvironment(ctx context.Context, r ApplyEnvironmentRequest) (Environment, error) {
	result, err := d.ApplyEnvironments(ctx, ApplyEnvironmentsRequest{Manager: r.Manager, TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Items: []EnvironmentApplication{r.EnvironmentApplication}, DNSAutomation: r.DNSAutomation, Now: r.Now})
	if err != nil {
		return Environment{}, err
	}
	return result[0], nil
}

func (d *Database) ApplyEnvironments(ctx context.Context, r ApplyEnvironmentsRequest) (result []Environment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(r.ProjectKey) || len(r.Items) == 0 || len(r.Items) > 128 {
		return nil, ErrProjectConfigurationInvalid
	}
	items := slices.Clone(r.Items)
	slices.SortFunc(items, func(a, b EnvironmentApplication) int { return strings.Compare(a.EnvironmentID, b.EnvironmentID) })
	for i, item := range items {
		if !opaqueid.Valid(item.EnvironmentID, opaqueid.EnvironmentPrefix) || item.ExpectedRevision < 1 || item.ExpectedRevision == 1<<63-1 || item.DefinitionRevision < 1 || i > 0 && item.EnvironmentID == items[i-1].EnvironmentID {
			return nil, ErrProjectConfigurationInvalid
		}
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "apply environments", &retErr)()
	manager, err := environmentManagement(ctx, tx, r.TeamID, r.ActorID, r.Manager)
	if err != nil {
		return nil, err
	}
	r.ActorID = manager.identityID
	q := controlstatedb.New(tx)
	project, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return nil, err
	}
	type approvedApplication struct {
		row        controlstatedb.ControlEnvironment
		definition ServiceDefinition
		old, next  environmentBindings
		endpoint   environmentEndpointSettings
	}
	approved := make([]approvedApplication, 0, len(items))
	// preflight every expected revision, definition and approval before touching
	// resources. the team guard fixes the set while locks are acquired by ID.
	for _, item := range items {
		row, e := q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: item.EnvironmentID})
		if e != nil {
			return nil, e
		}
		if row.RetiredAt.Valid {
			return nil, ErrEnvironmentRetired
		}
		if row.MutationRevision != item.ExpectedRevision {
			return nil, ErrProjectConfigurationStale
		}
		previousDefinition, old, _, e := d.environmentProjection(ctx, tx, row)
		if e != nil {
			return nil, e
		}
		if e = manager.authorize(ctx, tx, ProvisioningScope{Operation: ProvisioningUpdate, TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: row.ID, Services: definitionServiceNames(previousDefinition)}, false); e != nil {
			return nil, e
		}
		definition, e := loadServiceDefinition(ctx, tx, r.TeamID, r.ProjectKey, item.DefinitionRevision)
		if e != nil {
			return nil, e
		}
		if definition.SourceFingerprint != project.SourceFingerprint {
			return nil, ErrProjectSourceConflict
		}
		if e = manager.authorize(ctx, tx, ProvisioningScope{Operation: ProvisioningUpdate, TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: row.ID, Services: definitionServiceNames(definition.Definition)}, false); e != nil {
			return nil, e
		}
		next := environmentBindings{}
		if item.Targets != nil {
			next, e = normalizeEnvironmentTargets(item.Targets, definition.Definition)
		} else {
			for name := range definition.Definition.Services {
				if b, ok := old[name]; ok {
					next[name] = b
				}
			}
			e = validateEnvironmentBindings(next, definition.Definition)
		}
		if e != nil {
			return nil, e
		}
		group, e := q.GetEnvironmentPublisherGroup(ctx, row.GroupID)
		if e != nil {
			return nil, e
		}
		endpoint := environmentEndpointSettings{DomainID: group.DomainID.String, Public: group.Public}
		if item.Public != nil {
			endpoint.Public = *item.Public
		}
		approved = append(approved, approvedApplication{row: row, definition: definition.Definition, old: old, next: next, endpoint: endpoint})
	}
	ids := make([]string, 0, len(approved))
	for _, a := range approved {
		ids = append(ids, a.row.GroupID)
	}
	if _, err = tx.Exec(ctx, `SELECT id FROM control.project_publisher_groups WHERE id=ANY($1::text[]) ORDER BY id FOR UPDATE`, ids); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT service.id FROM control.services service JOIN control.applied_project_services binding ON binding.service_id=service.id WHERE binding.group_id=ANY($1::text[]) ORDER BY service.id FOR UPDATE OF service`, ids); err != nil {
		return nil, err
	}
	if err = setServiceAuditIssuer(ctx, tx, manager.issuer()); err != nil {
		return nil, err
	}
	byID := map[string]Environment{}
	for i, a := range approved {
		a.row.MutationRevision++
		a.row.AppliedDefinitionRevision = items[i].DefinitionRevision
		a.row.ConfigurationHash = environmentConfigurationHash(a.definition, a.next, a.endpoint)
		if _, err = tx.Exec(ctx, `UPDATE control.project_publisher_groups SET public=$2 WHERE id=$1`, a.row.GroupID, a.endpoint.Public); err != nil {
			return nil, err
		}
		apply := serviceResourceMutation{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, DNSAutomation: r.DNSAutomation, Now: r.Now}
		if err = d.materializeEnvironment(ctx, tx, a.row, a.definition, a.old, a.next, apply, manager.issuer()); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.environments SET applied_definition_revision=$2,mutation_revision=$3,configuration_hash=$4,updated_at=$5 WHERE id=$1`, a.row.ID, a.row.AppliedDefinitionRevision, a.row.MutationRevision, a.row.ConfigurationHash, r.Now); err != nil {
			return nil, err
		}
		v, e := d.environmentStatus(ctx, tx, a.row)
		if e != nil {
			return nil, e
		}
		byID[a.row.ID] = v
	}
	if err = manager.finish(ctx, tx, r.TeamID); err != nil {
		return nil, err
	}
	result = make([]Environment, 0, len(items))
	for _, item := range r.Items {
		result = append(result, byID[item.EnvironmentID])
	}
	return result, tx.Commit(ctx)
}

// environment materialization owns only this remote group's resources. it reuses
// resource/namespace/pool/endpoint mechanics without entering project apply or
// any visitor, workload, provisioning or publisher grant reconciliation.
func (d *Database) materializeEnvironment(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlEnvironment, definition ServiceDefinition, old, next environmentBindings, r serviceResourceMutation, issuer publisherIssuer) error {
	if err := lockAppliedPublicationReservations(ctx, tx); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	rows, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: row.TeamID, ProjectKey: row.ProjectKey})
	if err != nil {
		return err
	}
	saved := map[string]controlstatedb.ControlAppliedProjectService{}
	for _, s := range rows {
		if s.GroupID.String != row.GroupID {
			continue
		}
		name := appliedServiceName(s.Service)
		if _, exists := definition.Services[name]; !exists {
			if err = d.removeAppliedService(ctx, tx, q, s, r.Now); err != nil {
				return err
			}
		} else {
			saved[name] = s
		}
	}
	poolIDs, err := lockServicePortInventories(ctx, tx, nil)
	if err != nil {
		return err
	}
	retained := []string{}
	for _, s := range saved {
		retained = append(retained, s.ServiceID.String)
	}
	if err = ensurePublisherGroupIngressPool(ctx, tx, row.GroupID, len(definition.Services)-len(saved), retained, poolIDs); err != nil {
		return err
	}
	for _, name := range sortedProjectKeys(definition.Services) {
		service, e := bindEnvironmentService(definition.Services[name].Protocol, next[name])
		if e != nil {
			return e
		}
		entry, exists := saved[name]
		if !exists {
			key := publisherGroupServiceKey(row.GroupID, name)
			id, e := d.createEnvironmentServiceResource(ctx, tx, q, row, name, service, issuer, r.Now)
			if e != nil {
				return e
			}
			entry = controlstatedb.ControlAppliedProjectService{TeamID: row.TeamID, ProjectKey: row.ProjectKey, GroupID: text(row.GroupID), Service: key, ServiceID: text(id)}
			_, err = tx.Exec(ctx, `INSERT INTO control.applied_project_services(team_id,project_key,service,group_id,service_id,desired_revision) VALUES($1,$2,$3,$4,$5,$6)`, row.TeamID, row.ProjectKey, key, row.GroupID, id, row.MutationRevision)
		} else {
			if !reflect.DeepEqual(old[name], next[name]) {
				// close stale workers, but keep exact grants (including revocations).
				if err = closeEnvironmentServiceRuns(ctx, tx, q, entry.ServiceID.String, r.Now); err != nil {
					return err
				}
				if err = d.updateEnvironmentServiceResource(ctx, tx, q, entry.ServiceID.String, name, row.GroupID, service, r.Now); err != nil {
					return err
				}
			}
			_, err = tx.Exec(ctx, `UPDATE control.applied_project_services SET desired_revision=$4 WHERE team_id=$1 AND project_key=$2 AND service=$3`, row.TeamID, row.ProjectKey, entry.Service, row.MutationRevision)
		}
		if err != nil {
			return err
		}
		if err = d.ensureServiceEndpoint(ctx, tx, entry.ServiceID.String, row.GroupID, r.DNSAutomation, r.Now); err != nil {
			return err
		}
		if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: row.TeamID, ServiceID: entry.ServiceID.String, ServiceKind: "service", EventType: "apply", ActorIdentityID: issuer.IdentityID, ActorMachineID: issuer.MachineID, ActorProvisioningGrantID: issuer.ProvisioningGrantID, ConfigurationRevision: row.MutationRevision, OccurredAt: r.Now}, fmt.Sprintf("%s/%d", row.ID, row.MutationRevision)); err != nil {
			return err
		}
	}
	if err = d.saveEnvironmentTargets(ctx, tx, row.GroupID, next); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.publisher_group_members SET healthy=false,acknowledged_at=NULL WHERE group_id=$1`, row.GroupID)
	return err
}

func (d *Database) environmentStatus(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlEnvironment) (Environment, error) {
	definition, bindings, _, err := d.environmentProjection(ctx, tx, row)
	if err != nil {
		return Environment{}, err
	}
	result := Environment{ID: row.ID, TeamID: row.TeamID, ProjectKey: row.ProjectKey, Name: row.Name, CollectionID: row.CollectionID.String, AppliedDefinitionRevision: row.AppliedDefinitionRevision, MutationRevision: row.MutationRevision, ConfigurationHash: row.ConfigurationHash, Retired: row.RetiredAt.Valid, Targets: environmentTargets(bindings), Services: []EnvironmentService{}, Members: []EnvironmentPublisherStatus{}}
	group, err := controlstatedb.New(tx).GetEnvironmentPublisherGroup(ctx, row.GroupID)
	if err != nil {
		return result, err
	}
	result.DomainID, result.Public = group.DomainID.String, group.Public
	rows, err := tx.Query(ctx, `SELECT binding.service,service.id,service.protocol,service.certificate_hostname,service.service_port,service.public,service.trust_revision FROM control.applied_project_services binding JOIN control.services service ON service.id=binding.service_id WHERE binding.group_id=$1 ORDER BY binding.service`, row.GroupID)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var s EnvironmentService
		if err = rows.Scan(&s.Service, &s.ServiceID, &s.Protocol, &s.Hostname, &s.Port, &s.Public, &s.TrustRevision); err != nil {
			rows.Close()
			return result, err
		}
		s.Service = appliedServiceName(s.Service)
		shape, ok := definition.Services[s.Service]
		if !ok || shape.Protocol != s.Protocol {
			rows.Close()
			return result, ErrProjectConfigurationStale
		}
		result.Services = append(result.Services, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	members, err := listEnvironmentPublisherStatus(ctx, tx, row.TeamID, row.ProjectKey)
	if err != nil {
		return result, err
	}
	for _, m := range members {
		if m.EnvironmentID == row.ID {
			result.Members = append(result.Members, m)
		}
	}
	return result, nil
}

func (d *Database) GetEnvironment(ctx context.Context, team, project, id, actor string) (result Environment, retErr error) {
	return d.inspectEnvironment(ctx, team, project, id, actor, EnvironmentPublisherManager{})
}

func (d *Database) InspectEnvironment(ctx context.Context, team, project, id string, manager EnvironmentPublisherManager) (Environment, error) {
	return d.inspectEnvironment(ctx, team, project, id, "", manager)
}

func (d *Database) inspectEnvironment(ctx context.Context, team, project, id, actor string, manager EnvironmentPublisherManager) (result Environment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(project) || !opaqueid.Valid(id, opaqueid.EnvironmentPrefix) {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get environment", &retErr)()
	manager, err = environmentManagement(ctx, tx, team, actor, manager)
	if err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).GetEnvironment(ctx, controlstatedb.GetEnvironmentParams{TeamID: team, ProjectKey: project, ID: id})
	if err != nil {
		return result, err
	}
	result, err = d.environmentStatus(ctx, tx, row)
	if err != nil {
		return result, err
	}
	if err = d.authorizeEnvironmentProjection(ctx, tx, manager, row, ProvisioningRead); err != nil {
		return Environment{}, err
	}
	if err = manager.finish(ctx, tx, team); err != nil {
		return Environment{}, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) ListEnvironments(ctx context.Context, team, project, actor string) (result []Environment, retErr error) {
	return d.inspectEnvironments(ctx, team, project, actor, EnvironmentPublisherManager{})
}

func (d *Database) InspectEnvironments(ctx context.Context, team, project string, manager EnvironmentPublisherManager) ([]Environment, error) {
	return d.inspectEnvironments(ctx, team, project, "", manager)
}

func (d *Database) inspectEnvironments(ctx context.Context, team, project, actor string, manager EnvironmentPublisherManager) (result []Environment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(project) {
		return nil, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list environments", &retErr)()
	manager, err = environmentManagement(ctx, tx, team, actor, manager)
	if err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(tx).ListEnvironments(ctx, controlstatedb.ListEnvironmentsParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return nil, err
	}
	result = []Environment{}
	for _, row := range rows {
		if row.RetiredAt.Valid && manager.provisioningCredential != "" {
			continue
		}
		if err = d.authorizeEnvironmentProjection(ctx, tx, manager, row, ProvisioningRead); err != nil {
			if errors.Is(err, ErrMachineDenied) {
				continue
			}
			return nil, err
		}
		v, e := d.environmentStatus(ctx, tx, row)
		if e != nil {
			return nil, e
		}
		result = append(result, v)
	}
	if err = manager.finish(ctx, tx, team); err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) RetireEnvironment(ctx context.Context, r RetireEnvironmentRequest) (retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(r.ProjectKey) || !opaqueid.Valid(r.EnvironmentID, opaqueid.EnvironmentPrefix) || r.ExpectedRevision < 1 || r.ExpectedRevision == 1<<63-1 {
		return ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "retire environment", &retErr)()
	manager, err := environmentManagement(ctx, tx, r.TeamID, r.ActorID, r.Manager)
	if err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey}); err != nil {
		return err
	}
	row, err := q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: r.EnvironmentID})
	if err != nil {
		return err
	}
	if row.RetiredAt.Valid {
		return ErrEnvironmentRetired
	}
	if row.MutationRevision != r.ExpectedRevision {
		return ErrProjectConfigurationStale
	}
	if err = d.authorizeEnvironmentProjection(ctx, tx, manager, row, ProvisioningRetire); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT service.id FROM control.services service JOIN control.applied_project_services binding ON binding.service_id=service.id WHERE binding.group_id=$1 ORDER BY service.id FOR UPDATE OF service`, row.GroupID); err != nil {
		return err
	}
	if err = lockAppliedPublicationReservations(ctx, tx); err != nil {
		return err
	}
	if err = setServiceAuditIssuer(ctx, tx, manager.issuer()); err != nil {
		return err
	}
	services, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return err
	}
	for _, s := range services {
		if s.GroupID.String == row.GroupID {
			if err = d.removeAppliedService(ctx, tx, q, s, r.Now); err != nil {
				return err
			}
		}
	}
	if err = d.removePublisherGroup(ctx, tx, q, row.GroupID, r.Now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.environments SET retired_at=$2,updated_at=$2,mutation_revision=mutation_revision+1 WHERE id=$1`, row.ID, r.Now); err != nil {
		return err
	}
	if err = manager.finish(ctx, tx, r.TeamID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
