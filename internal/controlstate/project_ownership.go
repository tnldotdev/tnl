package controlstate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// normal resource APIs cannot change definitions or grants owned by apply.
// extra visitor grants and operational publisher identity revocation are separate.
var ErrProjectManaged = errors.New("resource is managed by project configuration")

func rejectPublisherGroupGrantMutation(ctx context.Context, tx pgx.Tx, publisher string) error {
	var member bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_group_members WHERE publisher_identity_id=$1)`, publisher).Scan(&member); err != nil {
		return err
	}
	if member {
		return fmt.Errorf("change publisher group grant: %w", ErrProjectManaged)
	}
	return nil
}

func rejectProjectManagedDefinition(ctx context.Context, tx pgx.Tx, id string) error {
	var managed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.applied_project_services WHERE private_service_id=$1 OR public_url_id=$1)
	    OR EXISTS(SELECT 1 FROM control.local_project_services WHERE private_service_id=$1 OR public_url_id=$1)`, id).Scan(&managed)
	if err != nil {
		return err
	}
	if managed {
		return fmt.Errorf("change project service definition: %w", ErrProjectManaged)
	}
	return nil
}

func rejectProjectManagedGrant(ctx context.Context, tx pgx.Tx, id string) error {
	var managed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.applied_project_services WHERE visitor_grant_id=$1)
	    OR EXISTS(SELECT 1 FROM control.local_project_services WHERE visitor_grant_id=$1)
	    OR EXISTS(SELECT 1 FROM control.publisher_group_service_grants WHERE grant_id=$1)`, id).Scan(&managed)
	if err != nil {
		return err
	}
	if managed {
		return fmt.Errorf("change project service grant: %w", ErrProjectManaged)
	}
	return nil
}
