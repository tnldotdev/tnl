package state

import (
	"context"
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

type PublisherGroupCreation struct {
	Name, Template string
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
func publisherTemplateConfiguration(c ProjectConfiguration, groups []controlstatedb.ControlProjectPublisherGroup, omit string) ProjectConfiguration {
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
		result.PublisherGroups[instance.Name] = definition
		for key, service := range c.Services {
			if service.PublisherGroup != instance.TemplateName {
				continue
			}
			service.PublisherGroup = instance.Name
			result.Services[publisherGroupServiceKey(instance.ID, key)] = service
		}
	}
	return result
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

func createTemplateGroup(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, c ProjectConfiguration) (bool, error) {
	creation := r.CreateGroup
	if creation == nil {
		return false, nil
	}
	if !naming.ValidServiceName(creation.Name) || creation.Name == "local" || !c.PublisherGroups[creation.Template].Template {
		return false, ErrProjectConfigurationInvalid
	}
	if _, exists := c.PublisherGroups[creation.Name]; exists {
		return false, ErrServiceConflict
	}
	var template string
	err := tx.QueryRow(ctx, `SELECT g.template_name FROM control.publisher_group_names alias JOIN control.project_publisher_groups g ON g.id=alias.group_id WHERE alias.team_id=$1 AND alias.project_key=$2 AND alias.name=$3 AND g.deleted_at IS NULL`, r.TeamID, r.ProjectKey, creation.Name).Scan(&template)
	if err == nil {
		if template != creation.Template {
			return false, ErrServiceConflict
		}
		return false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM control.project_publisher_groups WHERE team_id=$1 AND project_key=$2 AND template_name<>'' AND deleted_at IS NULL`, r.TeamID, r.ProjectKey).Scan(&count); err != nil {
		return false, err
	}
	if count >= 1024 {
		return false, ErrProjectConfigurationInvalid
	}
	id, err := opaqueid.New("pgrp_")
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name,template_name) VALUES($1,$2,$3,$4,$5)`, id, r.TeamID, r.ProjectKey, creation.Name, creation.Template)
	return err == nil, projectConstraintError(err)
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
	current, err := d.GetProjectConfiguration(ctx, team, project, actor)
	if err != nil {
		return current, err
	}
	if current.Revision != expected {
		return AppliedProjectConfiguration{}, ErrProjectConfigurationStale
	}
	return d.ApplyProjectConfiguration(ctx, ApplyProjectConfigurationRequest{
		TeamID: team, ProjectKey: project, SourceFingerprint: current.SourceFingerprint,
		ActorID: actor, ExpectedRevision: expected, Configuration: current.Configuration,
		DNSAutomation: dns, Now: now, CreateGroup: create, RemoveGroup: remove,
	})
}
