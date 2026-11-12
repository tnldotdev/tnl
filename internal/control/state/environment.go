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
	ID                        string                       `json:"id"`
	TeamID                    string                       `json:"team_id"`
	ProjectKey                string                       `json:"project_key"`
	Name                      string                       `json:"name"`
	AppliedDefinitionRevision int64                        `json:"applied_definition_revision"`
	MutationRevision          int64                        `json:"mutation_revision"`
	ConfigurationHash         string                       `json:"configuration_hash"`
	Retired                   bool                         `json:"retired"`
	Targets                   EnvironmentTargets           `json:"targets"`
	Services                  []EnvironmentService         `json:"services"`
	Members                   []PublisherGroupMemberStatus `json:"-"`
}

type CreateEnvironmentRequest struct {
	TeamID, ProjectKey, SourceFingerprint, ProjectLabel, ActorID string
	Name, IdempotencyKey                                         string
	DefinitionRevision                                           int64
	Targets                                                      EnvironmentTargets
	DNSAutomation                                                bool
	Now                                                          time.Time
}

type EnvironmentApplication struct {
	EnvironmentID      string
	ExpectedRevision   int64
	DefinitionRevision int64
	// nil retains existing approvals; a non-nil map replaces the complete set.
	Targets EnvironmentTargets
}

type ApplyEnvironmentRequest struct {
	TeamID, ProjectKey, ActorID string
	EnvironmentApplication
	DNSAutomation bool
	Now           time.Time
}

type ApplyEnvironmentsRequest struct {
	TeamID, ProjectKey, ActorID string
	Items                       []EnvironmentApplication
	DNSAutomation               bool
	Now                         time.Time
}

type RetireEnvironmentRequest struct {
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

func normalizeEnvironmentTargets(targets EnvironmentTargets, definition ServiceDefinition) (PublisherGroupBindings, error) {
	input := PublisherGroupBindings{}
	for name, t := range targets {
		input[name] = PublisherGroupTargetBinding{Target: t.Address, TargetTLS: t.TLS, TargetDiscovery: t.Discovery}
	}
	bindings, err := normalizePublisherGroupBindings(input, environmentBindingProtocols(definition))
	if err != nil {
		return nil, err
	}
	if err = validateEnvironmentBindings(bindings, definition); err != nil {
		return nil, err
	}
	return bindings, nil
}

func validateEnvironmentBindings(bindings PublisherGroupBindings, definition ServiceDefinition) error {
	if len(bindings) != len(definition.Services) {
		return ErrProjectConfigurationInvalid
	}
	for name, s := range definition.Services {
		b, found := bindings[name]
		if !found {
			return ErrProjectConfigurationInvalid
		}
		if _, err := bindPublisherGroupService(ProjectServiceConfiguration{Protocol: s.Protocol, PublisherGroup: "environment", Name: name}, b); err != nil {
			return err
		}
	}
	return nil
}

func environmentTargets(bindings PublisherGroupBindings) EnvironmentTargets {
	result := EnvironmentTargets{}
	for name, b := range bindings {
		result[name] = EnvironmentTarget{Address: b.Target, TLS: b.TargetTLS, Discovery: b.TargetDiscovery}
	}
	return result
}

func environmentConfigurationHash(definition ServiceDefinition, bindings PublisherGroupBindings) string {
	data, _ := json.Marshal([]any{definition, environmentTargets(bindings)})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func environmentCreationDigest(name string, revision int64, bindings PublisherGroupBindings) []byte {
	data, _ := json.Marshal([]any{name, revision, environmentTargets(bindings)})
	digest := sha256.Sum256(data)
	return digest[:]
}

func (d *Database) CreateEnvironment(ctx context.Context, r CreateEnvironmentRequest) (result Environment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(r.ProjectKey) || !fingerprintPattern.MatchString(r.SourceFingerprint) || !validEnvironmentName(r.Name) || !validEnvironmentKey(r.IdempotencyKey) || r.DefinitionRevision < 1 {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create environment", &retErr)()
	if err = authorizeEnvironmentManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	project, err := d.ensureDefinitionProject(ctx, tx, r.TeamID, r.ProjectKey, r.SourceFingerprint, r.ProjectLabel, r.ActorID, r.Now)
	if err != nil {
		return result, err
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
		if e != nil || r.DefinitionRevision != row.InitialDefinitionRevision || !bytes.Equal(environmentCreationDigest(r.Name, r.DefinitionRevision, bindings), row.CreationDigest) {
			return result, ErrServiceConflict
		}
		if row.RetiredAt.Valid {
			return result, ErrEnvironmentRetired
		}
		if err = recordEnvironmentCreationKey(ctx, tx, r, row.ID); err != nil {
			return result, err
		}
		result, err = d.environmentStatus(ctx, tx, row)
		if err != nil {
			return result, err
		}
		if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
			return Environment{}, err
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	definition, err := loadServiceDefinition(ctx, tx, r.TeamID, r.ProjectKey, r.DefinitionRevision)
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
	var domain string
	if err = tx.QueryRow(ctx, `SELECT default_domain_id FROM control.teams WHERE id=$1`, r.TeamID).Scan(&domain); err != nil {
		return result, err
	}
	apply := ApplyProjectConfigurationRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ProjectLabel: project.ProjectLabel, DNSAutomation: r.DNSAutomation, Now: r.Now}
	if err = setServiceAuditIssuer(ctx, tx, publisherIssuer{IdentityID: r.ActorID}); err != nil {
		return result, err
	}
	if err = d.ensureGroupNamespace(ctx, tx, apply, group, groupName, ProjectPublisherGroup{DomainID: domain}); err != nil {
		return result, err
	}
	hash := environmentConfigurationHash(definition.Definition, bindings)
	_, err = tx.Exec(ctx, `INSERT INTO control.environments(id,team_id,project_key,name,group_id,applied_definition_revision,mutation_revision,configuration_hash,initial_definition_revision,creation_digest,created_by_identity_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,1,$7,$6,$8,$9,$10,$10)`, id, r.TeamID, r.ProjectKey, r.Name, group, r.DefinitionRevision, hash, environmentCreationDigest(r.Name, r.DefinitionRevision, bindings), r.ActorID, r.Now)
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
	if err = d.materializeEnvironment(ctx, tx, row, definition.Definition, nil, bindings, apply); err != nil {
		return result, err
	}
	if err = recordEnvironmentCreationKey(ctx, tx, r, id); err != nil {
		return result, err
	}
	result, err = d.environmentStatus(ctx, tx, row)
	if err != nil {
		return result, err
	}
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
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
func (d *Database) environmentProjection(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlEnvironment) (ServiceDefinition, PublisherGroupBindings, ProjectConfiguration, error) {
	return d.environmentProjectionQueries(ctx, controlstatedb.New(tx), row)
}

func (d *Database) environmentProjectionQueries(ctx context.Context, q *controlstatedb.Queries, row controlstatedb.ControlEnvironment) (ServiceDefinition, PublisherGroupBindings, ProjectConfiguration, error) {
	stored, err := q.ReadServiceDefinition(ctx, controlstatedb.ReadServiceDefinitionParams{TeamID: row.TeamID, ProjectKey: row.ProjectKey, Revision: row.AppliedDefinitionRevision})
	if err != nil {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, err
	}
	definition, err := decodeServiceDefinition(stored.Definition, stored.ConfigurationHash)
	if err != nil {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, err
	}
	settings, err := q.GetPublisherGroupBindings(ctx, row.GroupID)
	if err != nil {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, err
	}
	bindings, err := d.openPublisherGroupBindings(settings)
	if err != nil {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, err
	}
	if err = validateEnvironmentBindings(bindings, definition); err != nil {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, err
	}
	if row.ConfigurationHash != environmentConfigurationHash(definition, bindings) {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, ErrProjectConfigurationStale
	}
	group, err := q.GetEnvironmentPublisherGroup(ctx, row.GroupID)
	if err != nil {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, err
	}
	if group.EnvironmentID.String != row.ID || group.TeamID != row.TeamID || group.ProjectKey != row.ProjectKey {
		return ServiceDefinition{}, nil, ProjectConfiguration{}, ErrProjectConfigurationInvalid
	}
	name := group.Name
	c := ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{}, PublisherGroups: map[string]ProjectPublisherGroup{name: {Description: group.Description, DomainID: group.DomainID.String, Public: group.Public}}}
	for logical, s := range definition.Services {
		service, e := bindPublisherGroupService(ProjectServiceConfiguration{Protocol: s.Protocol, Name: logical, PublisherGroup: name}, bindings[logical])
		if e != nil {
			return ServiceDefinition{}, nil, ProjectConfiguration{}, e
		}
		c.Services[publisherGroupServiceKey(row.GroupID, logical)] = service
	}
	return definition, bindings, c, nil
}

func (d *Database) environmentServiceConfiguration(ctx context.Context, q *controlstatedb.Queries, environmentID, group, logical string) (ProjectServiceConfiguration, error) {
	row, mapped, err := publisherGroupEnvironment(ctx, q, group)
	if err != nil {
		return ProjectServiceConfiguration{}, err
	}
	if !mapped || row.ID != environmentID || row.RetiredAt.Valid {
		return ProjectServiceConfiguration{}, ErrServiceAccess
	}
	_, _, c, err := d.environmentProjectionQueries(ctx, q, row)
	if err != nil {
		return ProjectServiceConfiguration{}, err
	}
	s, ok := c.Services[publisherGroupServiceKey(group, logical)]
	if !ok {
		return ProjectServiceConfiguration{}, ErrServiceAccess
	}
	return s, nil
}

func (d *Database) ApplyEnvironment(ctx context.Context, r ApplyEnvironmentRequest) (Environment, error) {
	result, err := d.ApplyEnvironments(ctx, ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Items: []EnvironmentApplication{r.EnvironmentApplication}, DNSAutomation: r.DNSAutomation, Now: r.Now})
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
	if err = authorizeEnvironmentManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return nil, err
	}
	q := controlstatedb.New(tx)
	project, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return nil, err
	}
	type approvedApplication struct {
		row        controlstatedb.ControlEnvironment
		definition ServiceDefinition
		old, next  PublisherGroupBindings
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
		_, old, _, e := d.environmentProjection(ctx, tx, row)
		if e != nil {
			return nil, e
		}
		definition, e := loadServiceDefinition(ctx, tx, r.TeamID, r.ProjectKey, item.DefinitionRevision)
		if e != nil {
			return nil, e
		}
		if definition.SourceFingerprint != project.SourceFingerprint {
			return nil, ErrProjectSourceConflict
		}
		next := PublisherGroupBindings{}
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
		approved = append(approved, approvedApplication{row: row, definition: definition.Definition, old: old, next: next})
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
	if err = setServiceAuditIssuer(ctx, tx, publisherIssuer{IdentityID: r.ActorID}); err != nil {
		return nil, err
	}
	byID := map[string]Environment{}
	for i, a := range approved {
		a.row.MutationRevision++
		a.row.AppliedDefinitionRevision = items[i].DefinitionRevision
		a.row.ConfigurationHash = environmentConfigurationHash(a.definition, a.next)
		apply := ApplyProjectConfigurationRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, DNSAutomation: r.DNSAutomation, Now: r.Now}
		if err = d.materializeEnvironment(ctx, tx, a.row, a.definition, a.old, a.next, apply); err != nil {
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
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
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
func (d *Database) materializeEnvironment(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlEnvironment, definition ServiceDefinition, old, next PublisherGroupBindings, r ApplyProjectConfigurationRequest) error {
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
	var groupName string
	if err = tx.QueryRow(ctx, `SELECT name FROM control.project_publisher_groups WHERE id=$1`, row.GroupID).Scan(&groupName); err != nil {
		return err
	}
	for _, name := range sortedProjectKeys(definition.Services) {
		service, e := bindPublisherGroupService(ProjectServiceConfiguration{Protocol: definition.Services[name].Protocol, Name: name, PublisherGroup: groupName}, next[name])
		if e != nil {
			return e
		}
		entry, exists := saved[name]
		if !exists {
			key := publisherGroupServiceKey(row.GroupID, name)
			id, e := d.createAppliedServiceResource(ctx, tx, q, r, key, row.GroupID, service, publisherIssuer{IdentityID: r.ActorID})
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
				if err = d.updateAppliedService(ctx, tx, q, entry.ServiceID.String, row.GroupID, service, r.Now); err != nil {
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
		if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: row.TeamID, ServiceID: entry.ServiceID.String, ServiceKind: "service", EventType: "apply", ActorIdentityID: r.ActorID, ConfigurationRevision: row.MutationRevision, OccurredAt: r.Now}, fmt.Sprintf("%s/%d", row.ID, row.MutationRevision)); err != nil {
			return err
		}
	}
	if err = d.savePublisherGroupBindings(ctx, tx, row.GroupID, next); err != nil {
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
	result := Environment{ID: row.ID, TeamID: row.TeamID, ProjectKey: row.ProjectKey, Name: row.Name, AppliedDefinitionRevision: row.AppliedDefinitionRevision, MutationRevision: row.MutationRevision, ConfigurationHash: row.ConfigurationHash, Retired: row.RetiredAt.Valid, Targets: environmentTargets(bindings), Services: []EnvironmentService{}, Members: []PublisherGroupMemberStatus{}}
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
	members, err := listPublisherGroupMemberStatus(ctx, tx, row.TeamID, row.ProjectKey)
	if err != nil {
		return result, err
	}
	for _, m := range members {
		if m.GroupID == row.GroupID {
			result.Members = append(result.Members, m)
		}
	}
	return result, nil
}

func (d *Database) GetEnvironment(ctx context.Context, team, project, id, actor string) (result Environment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(project) || !opaqueid.Valid(id, opaqueid.EnvironmentPrefix) {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get environment", &retErr)()
	if err = authorizeEnvironmentManager(ctx, tx, team, actor); err != nil {
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
	if err = serviceManager(ctx, tx, team, actor); err != nil {
		return Environment{}, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) ListEnvironments(ctx context.Context, team, project, actor string) (result []Environment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !naming.ValidProjectKey(project) {
		return nil, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list environments", &retErr)()
	if err = authorizeEnvironmentManager(ctx, tx, team, actor); err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(tx).ListEnvironments(ctx, controlstatedb.ListEnvironmentsParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return nil, err
	}
	result = []Environment{}
	for _, row := range rows {
		v, e := d.environmentStatus(ctx, tx, row)
		if e != nil {
			return nil, e
		}
		result = append(result, v)
	}
	if err = serviceManager(ctx, tx, team, actor); err != nil {
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
	if err = authorizeEnvironmentManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
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
	if _, err = tx.Exec(ctx, `SELECT service.id FROM control.services service JOIN control.applied_project_services binding ON binding.service_id=service.id WHERE binding.group_id=$1 ORDER BY service.id FOR UPDATE OF service`, row.GroupID); err != nil {
		return err
	}
	if err = lockAppliedPublicationReservations(ctx, tx); err != nil {
		return err
	}
	if err = setServiceAuditIssuer(ctx, tx, publisherIssuer{IdentityID: r.ActorID}); err != nil {
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
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
