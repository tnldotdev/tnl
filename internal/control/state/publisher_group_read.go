package state

import (
	"context"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func (d *Database) ListManagedPublisherGroups(ctx context.Context, team, project string, caller GroupCaller, now time.Time) ([]PublisherGroupResource, error) {
	return d.readManagedPublisherGroups(ctx, team, project, "", caller, now)
}

func (d *Database) GetManagedPublisherGroupForCaller(ctx context.Context, team, project, selector string, caller GroupCaller, now time.Time) (PublisherGroupResource, error) {
	if selector == "" {
		return PublisherGroupResource{}, ErrProjectConfigurationInvalid
	}
	resources, err := d.readManagedPublisherGroups(ctx, team, project, selector, caller, now)
	if err != nil {
		return PublisherGroupResource{}, err
	}
	return resources[0], nil
}

func (d *Database) readManagedPublisherGroups(ctx context.Context, team, project, selector string, caller GroupCaller, now time.Time) (result []PublisherGroupResource, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "read managed publisher groups", &retErr)()
	a, err := d.authorizeGroupCaller(ctx, tx, caller, ProvisioningScope{TeamID: team, ProjectKey: project, Operation: ProvisioningRead}, selector, clock)
	if err != nil {
		return nil, err
	}
	q := controlstatedb.New(tx)
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return nil, err
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return nil, err
	}
	var allowed map[string]bool
	if a.issuer.MachineID != "" || selector != "" {
		allowed = map[string]bool{}
		if selector != "" {
			allowed[a.scope.GroupID] = true
		} else {
			groups, e := q.ListProjectPublisherGroups(ctx, controlstatedb.ListProjectPublisherGroupsParams{TeamID: team, ProjectKey: project})
			if e != nil {
				return nil, e
			}
			for _, group := range groups {
				if group.TemplateName != "" && slices.Contains(a.templates, group.TemplateName) {
					allowed[group.ID] = true
				}
			}
		}
	}
	status, err := d.appliedProjectStatusForGroups(ctx, tx, row, c, allowed)
	if err != nil {
		return nil, err
	}
	if selector != "" {
		if a.issuer.MachineID == "" {
			if err = d.appendRetiredPublisherGroup(ctx, tx, &status, a.scope.GroupID); err != nil {
				return nil, err
			}
		}
		resource, e := publisherGroupResource(status, a.scope.GroupID)
		if e != nil {
			return nil, e
		}
		result = []PublisherGroupResource{resource}
	} else {
		result = PublisherGroupResources(status)
	}
	if err = a.check(clock.current()); err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}
