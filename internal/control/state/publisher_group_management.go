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
	Caller                      GroupCaller
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
	caller := request.Caller
	if request.ActorID != "" {
		if caller != (GroupCaller{}) {
			return PublisherGroupResource{}, ErrMachineDenied
		}
		caller = HumanGroupCaller(request.ActorID)
	}
	project, _, err := d.mutateBoundPublisherGroup(ctx, GroupBindingMutationRequest{TeamID: request.TeamID, ProjectKey: request.ProjectKey, Caller: caller, ExpectedRevision: request.ExpectedRevision, DNSAutomation: request.DNSAutomation, Now: request.Now}, ProvisioningCreate, &creation)
	if err != nil {
		return PublisherGroupResource{}, err
	}
	return publisherGroupResource(project, creation.ID)
}

func (d *Database) GetManagedPublisherGroup(ctx context.Context, team, project, id, actor string) (result PublisherGroupResource, retErr error) {
	return d.GetManagedPublisherGroupForCaller(ctx, team, project, id, HumanGroupCaller(actor), time.Now())
}

func (d *Database) UpdatePublisherGroupBindings(ctx context.Context, team, project, id, actor string, expected int64, bindings PublisherGroupBindings, dns bool, now time.Time) (PublisherGroupResource, error) {
	return d.UpdateBoundPublisherGroup(ctx, GroupBindingMutationRequest{TeamID: team, ProjectKey: project, Group: id, Caller: HumanGroupCaller(actor), ExpectedRevision: expected, Bindings: bindings, DNSAutomation: dns, Now: now})
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
