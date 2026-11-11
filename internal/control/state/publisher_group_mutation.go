package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type GroupBindingMutationRequest struct {
	TeamID, ProjectKey, Group string
	Caller                    GroupCaller
	ExpectedRevision          int64
	Bindings                  PublisherGroupBindings
	DNSAutomation             bool
	Now                       time.Time
}

func (d *Database) UpdateBoundPublisherGroup(ctx context.Context, request GroupBindingMutationRequest) (PublisherGroupResource, error) {
	project, id, err := d.mutateBoundPublisherGroup(ctx, request, ProvisioningUpdate, nil)
	if err != nil {
		return PublisherGroupResource{}, err
	}
	return publisherGroupResource(project, id)
}

func (d *Database) RetireBoundPublisherGroup(ctx context.Context, request GroupBindingMutationRequest) error {
	_, _, err := d.mutateBoundPublisherGroup(ctx, request, ProvisioningRetire, nil)
	return err
}

// this boundary owns the transaction from current authorization through apply.
// only saved declarations enter reconciliation; submitted bindings select one
// concrete group, not arbitrary resources or template policy.
func (d *Database) mutateBoundPublisherGroup(ctx context.Context, request GroupBindingMutationRequest, operation ProvisioningOperation, creation *PublisherGroupCreation) (result AppliedProjectConfiguration, id string, retErr error) {
	clock := newAuthorizationClock(request.Now)
	if !naming.ValidProjectKey(request.ProjectKey) || request.ExpectedRevision < 1 || request.ExpectedRevision == 1<<63-1 || operation != ProvisioningCreate && request.Group == "" {
		return result, "", ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, "", err
	}
	defer rollback(ctx, tx, "mutate bound publisher group", &retErr)()
	scope := ProvisioningScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, Operation: operation}
	if creation != nil {
		scope.Template = creation.Template
	}
	a, err := d.authorizeGroupCaller(ctx, tx, request.Caller, scope, request.Group, clock)
	if err != nil {
		return result, "", err
	}
	if a.scope.Template == "" {
		return result, "", ErrProjectManaged
	}
	row, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: request.TeamID, ProjectKey: request.ProjectKey})
	if err != nil {
		return result, "", err
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return result, "", err
	}
	r := ApplyProjectConfigurationRequest{TeamID: request.TeamID, ProjectKey: request.ProjectKey, SourceFingerprint: row.SourceFingerprint, ProjectLabel: row.ProjectLabel, ActorID: a.issuer.IdentityID, Configuration: c, ExpectedRevision: request.ExpectedRevision, DNSAutomation: request.DNSAutomation, Now: request.Now}
	switch operation {
	case ProvisioningCreate:
		r.CreateGroup = creation
	case ProvisioningUpdate:
		r.GroupBindings = map[string]PublisherGroupBindings{a.scope.GroupID: request.Bindings}
	case ProvisioningRetire:
		r.RemoveGroup = a.groupName
	default:
		return result, "", ErrMachineDenied
	}
	result, err = d.applyProjectConfigurationTx(ctx, tx, r, c, authorizedProjectMutation{issuer: a.issuer, groupID: a.scope.GroupID})
	if err != nil {
		return result, "", err
	}
	id = a.scope.GroupID
	if creation != nil {
		id = creation.ID
	}
	if err = a.check(clock.current()); err != nil {
		return AppliedProjectConfiguration{}, "", err
	}
	return result, id, tx.Commit(ctx)
}
