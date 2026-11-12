package state

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// assignment keys are internal resource bindings, never visitor selectors.
func publisherGroupServiceKey(groupID, service string) string { return groupID + "/" + service }

func appliedServiceName(key string) string {
	if _, name, ok := strings.Cut(key, "/"); ok {
		return name
	}
	return key
}

// materialization creates service resources only. owner, visitor and publisher
// permissions are separate mutations and are never repaired by definition apply.
func (d *Database) createEnvironmentServiceResource(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, environment controlstatedb.ControlEnvironment, name string, service EnvironmentServicePublication, issuer publisherIssuer, now time.Time) (string, error) {
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(environment.ID + "\x00" + name))
	_, err = q.InsertService(ctx, controlstatedb.InsertServiceParams{ID: id, TeamID: environment.TeamID, Name: name, NameScope: environment.GroupID, CreatedByIdentityID: nullableText(issuer.IdentityID), CreatedByMachineID: nullableText(issuer.MachineID), ProvisioningGrantID: nullableText(issuer.ProvisioningGrantID), IdempotencyKey: "environment/" + id, RequestDigest: digest[:], Now: timestamptz(now)})
	if err != nil {
		return "", projectConstraintError(err)
	}
	trust, err := appliedServiceTargetTrust(service.TargetTLS)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(trust)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=true WHERE id=$1`, id, service.Protocol, string(encoded)); err != nil {
		return "", err
	}
	return id, nil
}

func (d *Database) updateEnvironmentServiceResource(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, id, name, group string, service EnvironmentServicePublication, now time.Time) error {
	row, err := q.LockService(ctx, id)
	if err != nil {
		return err
	}
	trust, err := appliedServiceTargetTrust(service.TargetTLS)
	if err != nil {
		return err
	}
	metadata := ServiceMetadata{Protocol: service.Protocol, TLS: trust, PublisherPool: true}
	saved, err := checkedServiceMetadata(row)
	if err != nil {
		return err
	}
	changed := !serviceMetadataMatches(saved, metadata) || !row.PublisherPool
	encoded, err := json.Marshal(trust)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=true,trust_revision=trust_revision+CASE WHEN $4 THEN 1 ELSE 0 END,updated_at=$5,name=$6,name_scope=$7 WHERE id=$1`, id, service.Protocol, string(encoded), changed, now, name, group)
	return projectConstraintError(err)
}
