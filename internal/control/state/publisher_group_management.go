package state

import (
	"context"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// management resources contain saved instance settings, never enrollment secrets.
type PublisherGroupResource struct {
	ID       string                       `json:"id"`
	Name     string                       `json:"name"`
	From     string                       `json:"from"`
	Revision int64                        `json:"revision"`
	Retired  bool                         `json:"retired"`
	Bindings PublisherGroupBindings       `json:"bindings"`
	Services []AppliedProjectService      `json:"services"`
	Members  []PublisherGroupMemberStatus `json:"members"`
}

type CreateBoundPublisherGroupRequest struct {
	TeamID, ProjectKey, ActorID string
	Creation                    PublisherGroupCreation
	ExpectedRevision            int64
	DNSAutomation               bool
	Now                         time.Time
}

func PublisherGroupResources(project AppliedProjectConfiguration) []PublisherGroupResource {
	result := []PublisherGroupResource{}
	for _, group := range project.Groups {
		resource := PublisherGroupResource{ID: group.ID, Name: group.Name, From: group.Template, Revision: project.Revision, Retired: group.Retired, Bindings: group.Bindings, Services: []AppliedProjectService{}, Members: []PublisherGroupMemberStatus{}}
		if resource.Bindings == nil {
			resource.Bindings = PublisherGroupBindings{}
		}
		for _, service := range project.Services {
			if service.PublisherGroup == group.Name {
				resource.Services = append(resource.Services, service)
			}
		}
		for _, member := range project.Members {
			if member.GroupID == group.ID {
				resource.Members = append(resource.Members, member)
			}
		}
		result = append(result, resource)
	}
	return result
}

func publisherGroupResource(project AppliedProjectConfiguration, id string) (PublisherGroupResource, error) {
	for i, resource := range PublisherGroupResources(project) {
		if resource.ID == id || slices.Contains(project.Groups[i].GroupNames, id) {
			return resource, nil
		}
	}
	return PublisherGroupResource{}, pgx.ErrNoRows
}

func (d *Database) CreateBoundPublisherGroup(ctx context.Context, request CreateBoundPublisherGroupRequest) (PublisherGroupResource, error) {
	creation := request.Creation
	project, err := d.mutateTemplateGroup(ctx, request.TeamID, request.ProjectKey, request.ActorID, request.ExpectedRevision, request.DNSAutomation, request.Now, &creation, "")
	if err != nil {
		return PublisherGroupResource{}, err
	}
	return publisherGroupResource(project, creation.ID)
}

func (d *Database) GetManagedPublisherGroup(ctx context.Context, team, project, id, actor string) (result PublisherGroupResource, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get managed publisher group", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = serviceManager(ctx, tx, team, actor); err != nil {
		return result, err
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return result, err
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return result, err
	}
	status, err := d.appliedProjectStatus(ctx, tx, row, c)
	if err != nil {
		return result, err
	}
	if _, err = publisherGroupResource(status, id); err == pgx.ErrNoRows {
		if err = d.appendRetiredPublisherGroup(ctx, tx, &status, id); err != nil {
			return result, err
		}
	}
	result, err = publisherGroupResource(status, id)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) UpdatePublisherGroupBindings(ctx context.Context, team, project, id, actor string, expected int64, bindings PublisherGroupBindings, dns bool, now time.Time) (PublisherGroupResource, error) {
	current, err := d.GetProjectConfiguration(ctx, team, project, actor)
	if err != nil {
		return PublisherGroupResource{}, err
	}
	resource, err := publisherGroupResource(current, id)
	if err != nil {
		return PublisherGroupResource{}, err
	}
	if resource.From == "" {
		return PublisherGroupResource{}, ErrProjectManaged
	}
	result, err := d.ApplyProjectConfiguration(ctx, ApplyProjectConfigurationRequest{TeamID: team, ProjectKey: project, SourceFingerprint: current.SourceFingerprint, ActorID: actor, ExpectedRevision: expected, Configuration: current.Configuration, GroupBindings: map[string]PublisherGroupBindings{resource.ID: bindings}, DNSAutomation: dns, Now: now})
	if err != nil {
		return PublisherGroupResource{}, err
	}
	return publisherGroupResource(result, resource.ID)
}

func (d *Database) appendRetiredPublisherGroup(ctx context.Context, tx pgx.Tx, project *AppliedProjectConfiguration, id string) error {
	for _, group := range project.Groups {
		if group.ID == id {
			return nil
		}
	}
	var group AppliedPublisherGroup
	err := tx.QueryRow(ctx, `SELECT g.id,g.name,g.template_name,g.namespace,COALESCE(g.domain_id,''),g.public,g.deleted_at IS NOT NULL,COALESCE(g.ingress_pool_id,'') FROM control.project_publisher_groups g WHERE (g.id=$1 OR EXISTS(SELECT 1 FROM control.publisher_group_names alias WHERE alias.group_id=g.id AND alias.name=$1)) AND g.team_id=$2 AND g.project_key=$3`, id, project.TeamID, project.ProjectKey).Scan(&group.ID, &group.Name, &group.Template, &group.Namespace, &group.DomainID, &group.Public, &group.Retired, &group.IngressPoolID)
	if err != nil {
		return err
	}
	group.Bindings = PublisherGroupBindings{}
	settings, err := controlstatedb.New(tx).GetPublisherGroupBindings(ctx, group.ID)
	if err == nil {
		group.Bindings, err = d.openPublisherGroupBindings(settings)
		if err != nil {
			return err
		}
	} else if err != pgx.ErrNoRows {
		return err
	}
	group.GroupNames = []string{group.Name}
	project.Groups = append(project.Groups, group)
	return nil
}
