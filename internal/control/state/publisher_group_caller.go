package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// group callers carry credentials, not reusable authorization decisions. each
// operation checks the caller again inside its own transaction.
type GroupCaller struct {
	identityID string
	credential string
}

func HumanGroupCaller(identityID string) GroupCaller { return GroupCaller{identityID: identityID} }
func ProvisioningGroupCaller(credential string) GroupCaller {
	return GroupCaller{credential: credential}
}

func (c GroupCaller) String() string {
	if c.credential != "" {
		return "provisioning caller"
	}
	return "human group caller"
}

type authorizedGroupOperation struct {
	issuer     publisherIssuer
	scope      ProvisioningScope
	groupName  string
	templates  []string
	validUntil time.Time
}

func (a authorizedGroupOperation) check(now time.Time) error {
	if !a.validUntil.IsZero() && !a.validUntil.After(now) {
		return ErrMachineDenied
	}
	return nil
}

func (d *Database) authorizeGroupCaller(ctx context.Context, tx pgx.Tx, caller GroupCaller, scope ProvisioningScope, selector string, clock authorizationClock) (a authorizedGroupOperation, err error) {
	if (caller.identityID == "") == (caller.credential == "") || !scope.Operation.Valid() {
		return a, ErrMachineDenied
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return a, publisherLookupError(err, ErrMachineDenied)
	}
	if caller.identityID != "" {
		if err = serviceManager(ctx, tx, scope.TeamID, caller.identityID); err != nil {
			return a, err
		}
	}
	if selector != "" {
		var retired bool
		err = tx.QueryRow(ctx, `SELECT g.id,g.name,g.template_name,g.deleted_at IS NOT NULL FROM control.project_publisher_groups g WHERE g.team_id=$1 AND g.project_key=$2 AND (g.id=$3 OR EXISTS(SELECT 1 FROM control.publisher_group_names alias WHERE alias.group_id=g.id AND alias.name=$3))`, scope.TeamID, scope.ProjectKey, selector).Scan(&scope.GroupID, &a.groupName, &scope.Template, &retired)
		if err != nil || retired && (caller.credential != "" || scope.Operation != ProvisioningRead) {
			if caller.credential != "" {
				if err != nil {
					return a, publisherLookupError(err, ErrMachineDenied)
				}
				return a, ErrMachineDenied
			}
			if err == nil {
				err = pgx.ErrNoRows
			}
			return a, err
		}
	}
	a.scope = scope
	if caller.credential != "" {
		if scope.GroupID != "" {
			var environment bool
			if err = tx.QueryRow(ctx, `SELECT environment_id IS NOT NULL OR EXISTS(SELECT 1 FROM control.environments reverse_owner WHERE reverse_owner.group_id=publisher_group.id) FROM control.project_publisher_groups publisher_group WHERE id=$1`, scope.GroupID).Scan(&environment); err != nil {
				return a, err
			}
			if environment {
				return a, ErrMachineDenied
			}
		}
		p, e := d.AuthorizeProvisioning(ctx, tx, caller.credential, scope, clock.current())
		if e != nil {
			return a, e
		}
		a.issuer = publisherIssuer{MachineID: p.MachineID, ProvisioningGrantID: p.GrantID}
		a.scope.Template, a.scope.GroupID = p.Template, p.GroupID
		a.templates, a.validUntil = p.Templates, p.ValidUntil
	} else {
		a.issuer = publisherIssuer{IdentityID: caller.identityID}
		if _, err = controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey}); err != nil {
			return a, err
		}
		if scope.GroupID != "" {
			if _, err = tx.Exec(ctx, `SELECT id FROM control.project_publisher_groups WHERE id=$1 FOR UPDATE`, scope.GroupID); err != nil {
				return a, err
			}
		}
	}
	return a, nil
}

// an apply authority is constructed only by the human apply entrypoint or an
// authorized group operation. machine authority never accepts a declaration.
type authorizedProjectMutation struct {
	issuer  publisherIssuer
	groupID string
}

func (a authorizedProjectMutation) permitsGroup(id string) bool {
	return a.issuer.MachineID == "" || id != "" && id == a.groupID
}
