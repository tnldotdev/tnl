package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrPublisherTemplateInUse = errors.New("publisher template has dependent groups; remove those groups before removing or converting the template")
var ErrPublisherGroupRetired = errors.New("publisher group is retired; its creation key cannot be reused")

type PublisherGroupCreation struct {
	Name, Template string
	Bindings       PublisherGroupBindings
	IdempotencyKey string
	ID             string
}

// template instances share declarations, never service IDs or publisher keys.
// internal service bindings use the immutable group ID, so renaming a group
// cannot switch a visitor to another piece of equipment.
func publisherGroupServiceKey(groupID, service string) string { return groupID + "/" + service }

func appliedServiceName(key string) string {
	if _, name, ok := strings.Cut(key, "/"); ok {
		return name
	}
	return key
}

// expand only inside control. the stored configuration remains the declaration
// from Git, while this projection feeds the existing resource reconciler.
func publisherTemplateConfiguration(c ProjectConfiguration, groups []controlstatedb.ControlProjectPublisherGroup, omit string, bindings map[string]PublisherGroupBindings) (ProjectConfiguration, error) {
	result := c
	result.PublisherGroups = maps.Clone(c.PublisherGroups)
	result.Services = maps.Clone(c.Services)
	for name, group := range c.PublisherGroups {
		if group.Template {
			delete(result.PublisherGroups, name)
		}
	}
	for key, service := range c.Services {
		if c.PublisherGroups[service.PublisherGroup].Template {
			delete(result.Services, key)
		}
	}
	for _, instance := range groups {
		if instance.TemplateName == "" || instance.Name == omit {
			continue
		}
		definition, found := c.PublisherGroups[instance.TemplateName]
		if !found || !definition.Template {
			continue
		}
		definition.Template = false
		if err := validatePublisherGroupBindings(c, instance.TemplateName, bindings[instance.ID]); err != nil {
			return ProjectConfiguration{}, err
		}
		result.PublisherGroups[instance.Name] = definition
		for key, service := range c.Services {
			if service.PublisherGroup != instance.TemplateName {
				continue
			}
			service.PublisherGroup = instance.Name
			if service.TargetBinding == "group" {
				var err error
				service, err = bindPublisherGroupService(service, bindings[instance.ID][key])
				if err != nil {
					return ProjectConfiguration{}, err
				}
			}
			result.Services[publisherGroupServiceKey(instance.ID, key)] = service
		}
	}
	return result, nil
}

func validatePublisherTemplates(c ProjectConfiguration, groups []controlstatedb.ControlProjectPublisherGroup, omit string) error {
	for _, group := range groups {
		if group.TemplateName == "" || group.Name == omit {
			continue
		}
		if !c.PublisherGroups[group.TemplateName].Template {
			return ErrPublisherTemplateInUse
		}
		if _, declared := c.PublisherGroups[group.Name]; declared {
			return ErrServiceConflict
		}
	}
	return nil
}

func (d *Database) createTemplateGroup(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, c ProjectConfiguration) (created, replay bool, err error) {
	creation := r.CreateGroup
	if creation == nil {
		return false, false, nil
	}
	if len(creation.IdempotencyKey) > 256 || strings.TrimSpace(creation.IdempotencyKey) != creation.IdempotencyKey || strings.ContainsAny(creation.IdempotencyKey, "\x00\r\n") {
		return false, false, ErrProjectConfigurationInvalid
	}
	protocols := publisherGroupBindingProtocols(c, creation.Template)
	if creation.IdempotencyKey != "" {
		var previous []byte
		var encodedProtocols []byte
		var retired bool
		var actualTemplate string
		err := tx.QueryRow(ctx, `SELECT creation.request_digest,creation.group_id,creation.binding_protocols,g.deleted_at IS NOT NULL,g.template_name FROM control.publisher_group_creations creation JOIN control.project_publisher_groups g ON g.id=creation.group_id WHERE creation.team_id=$1 AND creation.project_key=$2 AND creation.idempotency_key=$3 FOR UPDATE OF g`, r.TeamID, r.ProjectKey, creation.IdempotencyKey).Scan(&previous, &creation.ID, &encodedProtocols, &retired, &actualTemplate)
		if err == nil {
			if actualTemplate != creation.Template {
				return false, false, ErrServiceConflict
			}
			protocols = nil
			if err = json.Unmarshal(encodedProtocols, &protocols); err != nil {
				return false, false, err
			}
			bindings, err := normalizePublisherGroupBindings(creation.Bindings, protocols)
			if err != nil {
				return false, false, ErrServiceConflict
			}
			request, _ := json.Marshal([]any{creation.Name, creation.Template, bindings})
			digest := sha256.Sum256(request)
			if !bytes.Equal(previous, digest[:]) {
				return false, false, ErrServiceConflict
			}
			if retired {
				return false, false, ErrPublisherGroupRetired
			}
			return false, true, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return false, false, err
		}
	}
	creation.Bindings, err = normalizePublisherGroupBindings(creation.Bindings, protocols)
	if err != nil {
		return false, false, err
	}
	request, _ := json.Marshal([]any{creation.Name, creation.Template, creation.Bindings})
	digest := sha256.Sum256(request)
	encodedProtocols, _ := json.Marshal(protocols)
	name := creation.Name
	if name == "" {
		id, err := opaqueid.New("pgrp_")
		if err != nil {
			return false, false, err
		}
		name = "group-" + strings.ToLower(id[len("pgrp_"):])
	}
	if !naming.ValidServiceName(name) || name == "local" || !c.PublisherGroups[creation.Template].Template {
		return false, false, ErrProjectConfigurationInvalid
	}
	if err := validatePublisherGroupBindings(c, creation.Template, creation.Bindings); err != nil {
		return false, false, err
	}
	if _, exists := c.PublisherGroups[name]; exists {
		return false, false, ErrServiceConflict
	}
	var template string
	err = tx.QueryRow(ctx, `SELECT g.template_name,g.id FROM control.publisher_group_names alias JOIN control.project_publisher_groups g ON g.id=alias.group_id WHERE alias.team_id=$1 AND alias.project_key=$2 AND alias.name=$3 AND g.deleted_at IS NULL`, r.TeamID, r.ProjectKey, name).Scan(&template, &creation.ID)
	if err == nil {
		if template != creation.Template {
			return false, false, ErrServiceConflict
		}
		groups, e := controlstatedb.New(tx).ListProjectPublisherGroups(ctx, controlstatedb.ListProjectPublisherGroupsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
		if e != nil {
			return false, false, e
		}
		bindings, e := d.loadPublisherGroupBindings(ctx, tx, groups)
		if e != nil {
			return false, false, e
		}
		a, _ := json.Marshal(bindings[creation.ID])
		b, _ := json.Marshal(creation.Bindings)
		if !bytes.Equal(a, b) {
			return false, false, ErrServiceConflict
		}
		if creation.IdempotencyKey != "" {
			_, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_creations(team_id,project_key,idempotency_key,request_digest,group_id,binding_protocols) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, r.TeamID, r.ProjectKey, creation.IdempotencyKey, digest[:], creation.ID, string(encodedProtocols))
		}
		return false, false, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, false, err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM control.project_publisher_groups WHERE team_id=$1 AND project_key=$2 AND template_name<>'' AND deleted_at IS NULL`, r.TeamID, r.ProjectKey).Scan(&count); err != nil {
		return false, false, err
	}
	if count >= 1024 {
		return false, false, ErrProjectConfigurationInvalid
	}
	id, err := opaqueid.New("pgrp_")
	if err != nil {
		return false, false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name,template_name) VALUES($1,$2,$3,$4,$5)`, id, r.TeamID, r.ProjectKey, name, creation.Template)
	if err != nil {
		return false, false, projectConstraintError(err)
	}
	creation.ID = id
	if err = d.savePublisherGroupBindings(ctx, tx, id, creation.Bindings); err != nil {
		return false, false, err
	}
	if creation.IdempotencyKey != "" {
		_, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_creations(team_id,project_key,idempotency_key,request_digest,group_id,binding_protocols) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, r.TeamID, r.ProjectKey, creation.IdempotencyKey, digest[:], id, string(encodedProtocols))
	}
	return err == nil, false, err
}

// create and remove reuse apply's transaction, revision fence, resource locks,
// grants, endpoint retirement and audit. they never mutate the Git declaration.
func (d *Database) CreatePublisherGroup(ctx context.Context, team, project, name, template, actor string, expected int64, dns bool, now time.Time) (AppliedProjectConfiguration, error) {
	return d.mutateTemplateGroup(ctx, team, project, actor, expected, dns, now, &PublisherGroupCreation{Name: name, Template: template}, "")
}

func (d *Database) RemovePublisherGroup(ctx context.Context, team, project, name, actor string, expected int64, dns bool, now time.Time) (AppliedProjectConfiguration, error) {
	return d.mutateTemplateGroup(ctx, team, project, actor, expected, dns, now, nil, name)
}

func (d *Database) mutateTemplateGroup(ctx context.Context, team, project, actor string, expected int64, dns bool, now time.Time, create *PublisherGroupCreation, remove string) (AppliedProjectConfiguration, error) {
	operation := ProvisioningRetire
	if create != nil {
		operation = ProvisioningCreate
	}
	result, _, err := d.mutateBoundPublisherGroup(ctx, GroupBindingMutationRequest{TeamID: team, ProjectKey: project, Group: remove, Caller: HumanGroupCaller(actor), ExpectedRevision: expected, DNSAutomation: dns, Now: now}, operation, create)
	return result, err
}
