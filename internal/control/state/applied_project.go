package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

var (
	ErrProjectConfigurationInvalid = errors.New("project configuration is invalid")
	ErrProjectConfigurationStale   = errors.New("project configuration revision changed")
	ErrProjectSourceConflict       = errors.New("project label belongs to another source")
	fingerprintPattern             = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type ProjectPublisherGroup struct {
	Description string `json:"description,omitempty"`
	DomainID    string `json:"domain_id,omitempty"`
	Public      bool   `json:"public,omitempty"`
}
type ProjectServicePublicURL struct {
	DomainID  string               `json:"domain_id,omitempty"`
	Hostname  string               `json:"hostname,omitempty"`
	Access    *ProjectPublicAccess `json:"access,omitempty"`
	Limits    *ProjectPublicLimits `json:"limits,omitempty"`
	Ephemeral bool                 `json:"ephemeral,omitempty"`
}
type ProjectPublicAccess struct {
	Mode string   `json:"mode,omitempty"`
	IP   []string `json:"ip,omitempty"`
}
type ProjectPublicLimits struct {
	HTTP    *ProjectHTTPApplicationLimits `json:"http,omitempty"`
	Traffic *trafficlimits.Selection      `json:"traffic,omitempty"`
}
type ProjectHTTPApplicationLimits struct {
	Total       *int                    `json:"total,omitempty"`
	Concurrency *int                    `json:"concurrency,omitempty"`
	Rate        *ProjectApplicationRate `json:"rate,omitempty"`
}
type ProjectApplicationRate struct {
	Count int    `json:"count"`
	Per   string `json:"per"`
	Burst *int   `json:"burst,omitempty"`
}
type ProjectTargetTLS struct {
	Hostname string `json:"hostname"`
	CAPEM    string `json:"ca_pem,omitempty"`
	Digest   string `json:"digest"`
}
type ProjectServiceAccess struct {
	Team bool `json:"team"`
}
type ProjectServiceConfiguration struct {
	TargetDiscovery *ProjectTargetDiscovery  `json:"target_discovery,omitempty"`
	PublisherGroup  string                   `json:"publisher_group,omitempty"`
	Name            string                   `json:"name,omitempty"`
	Protocol        string                   `json:"protocol,omitempty"`
	Target          string                   `json:"target"`
	PublicURL       *ProjectServicePublicURL `json:"public_url,omitempty"`
	TargetTLS       *ProjectTargetTLS        `json:"target_tls,omitempty"`
	Access          *ProjectServiceAccess    `json:"access,omitempty"`
	HTTP            *config.HTTPService      `json:"http,omitempty"`
}
type ProjectConfiguration struct {
	Workloads       map[string]ProjectWorkload             `json:"workloads,omitempty"`
	PublisherGroups map[string]ProjectPublisherGroup       `json:"publisher_groups"`
	Services        map[string]ProjectServiceConfiguration `json:"services"`
	OAuth           bool                                   `json:"oauth"`
	Webhooks        map[string]ProjectWebhook              `json:"webhooks"`
}
type ProjectWebhook struct {
	Service   string   `json:"service"`
	Path      string   `json:"path"`
	Provider  string   `json:"provider"`
	Delivery  string   `json:"delivery,omitempty"`
	Methods   []string `json:"methods,omitempty"`
	SourceIPs []string `json:"source_ips,omitempty"`
}
type ApplyProjectConfigurationRequest struct {
	TeamID, ProjectKey, SourceFingerprint, ActorID string
	ProjectLabel                                   string
	ExpectedRevision                               int64
	Configuration                                  ProjectConfiguration
	DNSAutomation                                  bool
	TrafficDefaults, TrafficCeiling                trafficlimits.Limits
	Now                                            time.Time
}
type AppliedProjectService struct {
	Service         string `json:"service"`
	PublisherGroup  string `json:"publisher_group"`
	Kind            string `json:"service_kind"`
	ServiceID       string `json:"service_id,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	DesiredRevision int64  `json:"desired_revision"`
	TrustRevision   int64  `json:"trust_revision"`
	Port            int    `json:"port,omitempty"`
	Public          bool   `json:"public,omitempty"`
}
type AppliedPublisherGroup struct {
	GroupNames []string `json:"group_names"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Namespace  string   `json:"namespace"`
	DomainID   string   `json:"domain_id"`
	Public     bool     `json:"public"`
}
type AppliedProjectConfiguration struct {
	TeamID            string                       `json:"team_id"`
	ProjectKey        string                       `json:"project_key"`
	SourceFingerprint string                       `json:"source_fingerprint"`
	Revision          int64                        `json:"revision"`
	ConfigurationHash string                       `json:"configuration_hash"`
	Configuration     ProjectConfiguration         `json:"configuration"`
	Services          []AppliedProjectService      `json:"services"`
	Members           []PublisherGroupMemberStatus `json:"members"`
	Groups            []AppliedPublisherGroup      `json:"groups"`
}

// normalize a declarative value only. server code never evaluates project files.
func NormalizeProjectConfiguration(input ProjectConfiguration) (ProjectConfiguration, string, error) {
	for _, w := range input.Webhooks {
		if w.SourceIPs != nil && len(w.SourceIPs) == 0 {
			return ProjectConfiguration{}, "", ErrProjectConfigurationInvalid
		}
	}
	for _, s := range input.Services {
		if s.PublicURL != nil && s.PublicURL.Access != nil && s.PublicURL.Access.IP != nil && len(s.PublicURL.Access.IP) == 0 {
			return ProjectConfiguration{}, "", ErrProjectConfigurationInvalid
		}
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > 512<<10 {
		return ProjectConfiguration{}, "", ErrProjectConfigurationInvalid
	}
	var c ProjectConfiguration
	if err = json.Unmarshal(data, &c); err != nil {
		return c, "", err
	}
	if len(c.PublisherGroups) > 32 || len(c.Services) > 128 {
		return c, "", ErrProjectConfigurationInvalid
	}
	if c.PublisherGroups == nil {
		c.PublisherGroups = map[string]ProjectPublisherGroup{}
	}
	if c.Services == nil {
		c.Services = map[string]ProjectServiceConfiguration{}
	}
	for name, g := range c.PublisherGroups {
		if name == "local" || !serviceName.MatchString(name) || len(g.Description) > 1024 || strings.ContainsAny(g.Description, "\x00\r") {
			return c, "", ErrProjectConfigurationInvalid
		}
	}
	for key, s := range c.Services {
		if !serviceName.MatchString(key) {
			return c, "", ErrProjectConfigurationInvalid
		}
		if s.PublisherGroup == "" {
			s.PublisherGroup = "local"
		}
		if s.PublisherGroup != "local" {
			if _, ok := c.PublisherGroups[s.PublisherGroup]; !ok {
				return c, "", ErrProjectConfigurationInvalid
			}
		}
		if s.Name == "" {
			s.Name = key
		}
		if !serviceName.MatchString(s.Name) {
			return c, "", ErrProjectConfigurationInvalid
		}
		if s.Protocol == "" {
			s.Protocol = "http"
		}
		if (ServiceMetadata{Protocol: s.Protocol}).Validate() != nil || s.Access != nil && !s.Access.Team || (len(s.Target) == 0 && s.TargetDiscovery == nil) || len(s.Target) > 8192 || strings.ContainsAny(s.Target, "\x00\r\n") {
			return c, "", ErrProjectConfigurationInvalid
		}
		if err := normalizeAppliedProjectService(&s); err != nil {
			return c, "", err
		}
		c.Services[key] = s
	}
	if err = normalizeAppliedProjectIntegrations(&c); err != nil {
		return c, "", err
	}
	if err = normalizeProjectWorkloads(&c); err != nil {
		return c, "", err
	}
	data, err = json.Marshal(c)
	if err != nil {
		return c, "", err
	}
	if len(data) > 512<<10 {
		return c, "", ErrProjectConfigurationInvalid
	}
	hash := sha256.Sum256(data)
	return c, hex.EncodeToString(hash[:]), nil
}

func appliedProjectContext(team, key string) string { return "applied-project/" + team + "/" + key }

func (d *Database) openAppliedProject(row controlstatedb.ControlAppliedProject) (ProjectConfiguration, error) {
	var c ProjectConfiguration
	data, _, err := d.storageKey.Open(row.StorageKeyID, appliedProjectContext(row.TeamID, row.ProjectKey), row.ConfigurationCiphertext)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("decode applied project: %w", err)
	}
	return c, nil
}

func (d *Database) ApplyProjectConfiguration(ctx context.Context, r ApplyProjectConfigurationRequest) (result AppliedProjectConfiguration, retErr error) {
	if !naming.ValidProjectKey(r.ProjectKey) || !fingerprintPattern.MatchString(r.SourceFingerprint) || r.ExpectedRevision < 0 || r.ExpectedRevision == 1<<63-1 {
		return result, ErrProjectConfigurationInvalid
	}
	c, _, err := NormalizeProjectConfiguration(r.Configuration)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "apply project configuration", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	if err = checkLocalProjectSource(ctx, tx, r.TeamID, r.ProjectKey, r.SourceFingerprint); err != nil {
		return result, err
	}
	if r.ProjectLabel == "" {
		r.ProjectLabel = r.ProjectKey
	}
	if !validProjectDNSLabel(r.ProjectLabel) {
		return result, ErrProjectConfigurationInvalid
	}
	c, err = resolveManagedGroupDomains(ctx, tx, r.TeamID, r.ProjectKey, c)
	if err != nil {
		return result, err
	}
	if err = SetServiceAuditActor(ctx, tx, r.ActorID); err != nil {
		return result, err
	}
	c, hash, err := NormalizeProjectConfiguration(c)
	if err != nil {
		return result, err
	}
	defaults, ceiling := r.TrafficDefaults, r.TrafficCeiling
	if defaults == (trafficlimits.Limits{}) {
		defaults = trafficlimits.Default()
	}
	if ceiling == (trafficlimits.Limits{}) {
		ceiling = trafficlimits.Ceiling()
	}
	for _, s := range c.Services {
		if s.PublicURL != nil && s.PublicURL.Limits != nil && s.PublicURL.Limits.Traffic != nil {
			if _, err = s.PublicURL.Limits.Traffic.Resolve(defaults, ceiling); err != nil {
				return result, ErrProjectConfigurationInvalid
			}
		}
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if errors.Is(err, pgx.ErrNoRows) {
		if r.ExpectedRevision != 0 {
			return result, ErrProjectConfigurationStale
		}
		data, _ := json.Marshal(ProjectConfiguration{})
		sealed, e := d.storageKey.Seal(appliedProjectContext(r.TeamID, r.ProjectKey), data)
		if e != nil {
			return result, e
		}
		_, err = tx.Exec(ctx, `INSERT INTO control.applied_projects(team_id,project_key,source_fingerprint,configuration_ciphertext,storage_key_id,created_by_identity_id,updated_at,project_label) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.TeamID, r.ProjectKey, r.SourceFingerprint, sealed, d.storageKey.CurrentID(), r.ActorID, r.Now, r.ProjectLabel)
		if err != nil {
			return result, err
		}
		row, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	}
	if err != nil {
		return result, err
	}
	if row.SourceFingerprint != r.SourceFingerprint {
		return result, ErrProjectSourceConflict
	}
	if row.ConfigurationHash == hash {
		if r.ExpectedRevision > row.Revision {
			return result, ErrProjectConfigurationStale
		}
		result, err = d.appliedProjectStatus(ctx, tx, row, c)
		if err != nil {
			return result, err
		}
		return result, tx.Commit(ctx)
	}
	if row.Revision != r.ExpectedRevision {
		return result, ErrProjectConfigurationStale
	}
	old, err := d.openAppliedProject(row)
	if err != nil {
		return result, err
	}
	next := row.Revision + 1
	if err = lockAppliedProjectPublications(ctx, tx, r.TeamID, r.ProjectKey); err != nil {
		return result, err
	}
	groups, err := q.ListProjectPublisherGroups(ctx, controlstatedb.ListProjectPublisherGroupsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, err
	}
	groupIDs := map[string]string{}
	changedGroups := map[string]bool{}
	for _, g := range groups {
		groupIDs[g.Name] = g.ID
	}
	for _, name := range sortedProjectKeys(c.PublisherGroups) {
		id := groupIDs[name]
		if id == "" {
			id, err = opaqueid.New("pgrp_")
			if err != nil {
				return result, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name,description) VALUES($1,$2,$3,$4,$5)`, id, r.TeamID, r.ProjectKey, name, c.PublisherGroups[name].Description)
		} else {
			_, err = tx.Exec(ctx, `UPDATE control.project_publisher_groups SET description=$2 WHERE id=$1`, id, c.PublisherGroups[name].Description)
		}
		if err != nil {
			return result, err
		}
		groupIDs[name] = id
		if err = d.ensureGroupNamespace(ctx, tx, r, id, name, c.PublisherGroups[name]); err != nil {
			return result, err
		}
		oldGroup, found := old.PublisherGroups[name]
		if !found || oldGroup != c.PublisherGroups[name] {
			changedGroups[id] = true
		}
	}
	existing, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, err
	}
	saved := map[string]controlstatedb.ControlAppliedProjectService{}
	for _, s := range existing {
		saved[s.Service] = s
	}
	for _, s := range existing {
		declared, ok := c.Services[s.Service]
		previous := old.Services[s.Service]
		if !ok || !sameAppliedResource(previous, declared) {
			if err = d.removeAppliedService(ctx, tx, q, s, r.Now); err != nil {
				return result, err
			}
			delete(saved, s.Service)
		} else if !reflect.DeepEqual(previous, declared) {
			if err = d.revokeAppliedServicePublishers(ctx, tx, q, s, r.Now); err != nil {
				return result, err
			}
		}
	}
	for _, key := range sortedProjectKeys(c.Services) {
		s := c.Services[key]
		entry, found := saved[key]
		changed := !found || !reflect.DeepEqual(old.Services[key], s)
		if !found {
			entry = controlstatedb.ControlAppliedProjectService{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Service: key}
			if s.PublisherGroup != "local" {
				entry.GroupID = text(groupIDs[s.PublisherGroup])
			}
			// local resources are created by the normal per-worktree runtime.
			if s.PublisherGroup != "local" {
				id, e := d.createAppliedService(ctx, tx, q, r, key, entry.GroupID.String, s)
				if e != nil {
					return result, e
				}
				entry.ServiceID = text(id)
			}
			_, err = tx.Exec(ctx, `INSERT INTO control.applied_project_services(team_id,project_key,service,group_id,service_id,public_url_id,desired_revision) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.TeamID, r.ProjectKey, key, entry.GroupID, entry.ServiceID, entry.PublicURLID, next)
			if err != nil {
				return result, err
			}
		} else {
			entry.GroupID = nullableText(groupIDs[s.PublisherGroup])
			if entry.ServiceID.Valid && changed {
				if err = d.updateAppliedService(ctx, tx, q, entry.ServiceID.String, entry.GroupID.String, s, r.Now); err != nil {
					return result, err
				}
			}
			_, err = tx.Exec(ctx, `UPDATE control.applied_project_services SET desired_revision=$4,group_id=$5 WHERE team_id=$1 AND project_key=$2 AND service=$3`, r.TeamID, r.ProjectKey, key, next, entry.GroupID)
			if err != nil {
				return result, err
			}
		}
		if err = d.reconcileAppliedVisitorGrant(ctx, tx, entry, r.ActorID, s.Access != nil && s.Access.Team, r.Now); err != nil {
			return result, err
		}
		if entry.ServiceID.Valid && entry.GroupID.Valid {
			if err = d.ensureServiceEndpoint(ctx, tx, entry.ServiceID.String, entry.GroupID.String, r.DNSAutomation, r.Now); err != nil {
				return result, err
			}
		}
		if entry.PublicURLID.Valid && changed {
			if err = d.reconcileAppliedPublicSettings(ctx, tx, q, entry.PublicURLID.String, s.PublicURL, r.Now); err != nil {
				return result, err
			}
		}
		if entry.GroupID.Valid {
			if err = d.reconcileAppliedPublisherGrants(ctx, tx, q, entry, r.ActorID, r.Now); err != nil {
				return result, err
			}
		}
		if entry.ServiceID.Valid || entry.PublicURLID.Valid {
			id, kind := entry.PublicURLID.String, "public_url"
			if entry.ServiceID.Valid {
				id, kind = entry.ServiceID.String, "service"
			}
			if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: r.TeamID, ServiceID: id, ServiceKind: kind, EventType: "apply", OccurredAt: r.Now, ActorIdentityID: r.ActorID, ConfigurationRevision: next}, fmt.Sprintf("%s/%d", r.ProjectKey, next)); err != nil {
				return result, err
			}
		}
	}
	for _, g := range groups {
		if _, ok := c.PublisherGroups[g.Name]; !ok {
			changedGroups[g.ID] = true
			if err = d.removePublisherGroup(ctx, tx, q, g.ID, r.Now); err != nil {
				return result, err
			}
		}
	}
	if err = d.reconcileProjectLocalRealizations(ctx, tx, q, r, old, c); err != nil {
		return result, err
	}
	newServices, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, err
	}
	if err = recordAppliedGroupConfiguration(ctx, tx, existing, newServices, changedGroups, r.ActorID, next, r.Now); err != nil {
		return result, err
	}
	if err = reconcileWorkloadPolicies(ctx, tx, r, c); err != nil {
		return result, err
	}
	data, _ := json.Marshal(c)
	sealed, err := d.storageKey.Seal(appliedProjectContext(r.TeamID, r.ProjectKey), data)
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `UPDATE control.applied_projects SET revision=$3,configuration_hash=$4,configuration_ciphertext=$5,storage_key_id=$6,updated_at=$7 WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey, next, hash, sealed, d.storageKey.CurrentID(), r.Now)
	if err != nil {
		return result, err
	}
	row.Revision, row.ConfigurationHash = next, hash
	result, err = d.appliedProjectStatus(ctx, tx, row, c)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func sortedProjectKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func sameAppliedResource(a, b ProjectServiceConfiguration) bool {
	// local resources belong to individual worktrees; named groups share one ID.
	if a.PublisherGroup != "local" && b.PublisherGroup != "local" {
		return true
	}
	if (a.PublisherGroup == "local") != (b.PublisherGroup == "local") || (a.PublicURL == nil) != (b.PublicURL == nil) {
		return false
	}
	if a.PublicURL == nil {
		return true
	}
	return a.PublicURL.DomainID == b.PublicURL.DomainID && a.PublicURL.Hostname == b.PublicURL.Hostname
}

func projectConstraintError(err error) error {
	var p *pgconn.PgError
	if errors.As(err, &p) && p.Code == "23505" {
		return ErrServiceConflict
	}
	return err
}

func (d *Database) GetProjectConfiguration(ctx context.Context, team, key, actor string) (result AppliedProjectConfiguration, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get project configuration", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = serviceManager(ctx, tx, team, actor); err != nil {
		return result, err
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: key})
	if err != nil {
		return result, err
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return result, err
	}
	result, err = d.appliedProjectStatus(ctx, tx, row, c)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) appliedProjectStatus(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlAppliedProject, c ProjectConfiguration) (AppliedProjectConfiguration, error) {
	result := AppliedProjectConfiguration{TeamID: row.TeamID, ProjectKey: row.ProjectKey, SourceFingerprint: row.SourceFingerprint, Revision: row.Revision, ConfigurationHash: row.ConfigurationHash, Configuration: c, Services: []AppliedProjectService{}, Members: []PublisherGroupMemberStatus{}, Groups: []AppliedPublisherGroup{}}
	rows, err := controlstatedb.New(tx).ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: row.TeamID, ProjectKey: row.ProjectKey})
	if err != nil {
		return result, err
	}
	for _, s := range rows {
		v := AppliedProjectService{Service: s.Service, PublisherGroup: c.Services[s.Service].PublisherGroup, Kind: "local", DesiredRevision: s.DesiredRevision}
		if s.ServiceID.Valid {
			v.Kind, v.ServiceID = "service", s.ServiceID.String
			if err = tx.QueryRow(ctx, `SELECT trust_revision,certificate_hostname,COALESCE(service_port,0),public FROM control.services WHERE id=$1`, v.ServiceID).Scan(&v.TrustRevision, &v.Hostname, &v.Port, &v.Public); err != nil {
				return result, err
			}
		} else if s.PublicURLID.Valid {
			v.Kind, v.ServiceID, v.Hostname = "public_url", s.PublicURLID.String, c.Services[s.Service].PublicURL.Hostname
		}
		result.Services = append(result.Services, v)
	}
	result.Members, err = listPublisherGroupMemberStatus(ctx, tx, row.TeamID, row.ProjectKey)
	if err != nil {
		return result, err
	}
	groups, err := controlstatedb.New(tx).ListProjectPublisherGroups(ctx, controlstatedb.ListProjectPublisherGroupsParams{TeamID: row.TeamID, ProjectKey: row.ProjectKey})
	for _, group := range groups {
		var names []string
		if err := tx.QueryRow(ctx, `SELECT array_agg(name ORDER BY name) FROM control.publisher_group_names WHERE group_id=$1`, group.ID).Scan(&names); err != nil {
			return result, err
		}
		result.Groups = append(result.Groups, AppliedPublisherGroup{ID: group.ID, Name: group.Name, GroupNames: names, Namespace: group.Namespace, DomainID: group.DomainID.String, Public: group.Public})
	}
	return result, err
}
