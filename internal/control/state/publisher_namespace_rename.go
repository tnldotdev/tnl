package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type RenamePublisherNamespaceRequest struct {
	TeamID, ProjectKey, Group, NamespaceLabel, ActorID, IdempotencyKey string
	ExpectedRevision                                                   int64
	DNSAutomation                                                      bool
	Now                                                                time.Time
}

// RenamePublisherNamespace changes DNS and publication authority in one
// transaction. a retry returns the original encrypted response, even after a
// later mutation. selector rename is deliberately a separate operation.
func (d *Database) RenamePublisherNamespace(ctx context.Context, r RenamePublisherNamespaceRequest) (result AppliedProjectConfiguration, retErr error) {
	if !naming.ValidProjectKey(r.ProjectKey) || !naming.ValidServiceName(r.Group) || r.Group == "local" || !naming.ValidServiceName(r.NamespaceLabel) || r.ExpectedRevision < 1 || r.ExpectedRevision == 1<<63-1 || !validStateText(r.IdempotencyKey) || len(r.IdempotencyKey) > 256 {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "rename publisher DNS namespace", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if err = privateServiceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	request, _ := json.Marshal(struct {
		Group, Label string
		Revision     int64
	}{r.Group, r.NamespaceLabel, r.ExpectedRevision})
	digest := sha256.Sum256(request)
	context := "publisher-namespace-rename/" + r.TeamID + "/" + r.ProjectKey + "/" + r.IdempotencyKey
	var savedDigest, ciphertext []byte
	var storageKey string
	err = tx.QueryRow(ctx, `SELECT request_digest,response_ciphertext,storage_key_id FROM control.publisher_namespace_renames WHERE team_id=$1 AND project_key=$2 AND idempotency_key=$3`, r.TeamID, r.ProjectKey, r.IdempotencyKey).Scan(&savedDigest, &ciphertext, &storageKey)
	if err == nil {
		if !bytes.Equal(savedDigest, digest[:]) {
			return result, ErrPrivateServiceConflict
		}
		data, _, err := d.storageKey.Open(storageKey, context, ciphertext)
		if err != nil {
			return result, err
		}
		if err = json.Unmarshal(data, &result); err != nil {
			return result, err
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if row.Revision != r.ExpectedRevision {
		return result, ErrProjectConfigurationStale
	}
	var id, name, namespace string
	err = tx.QueryRow(ctx, `SELECT g.id,g.name,g.namespace FROM control.project_publisher_groups g JOIN control.publisher_group_names alias ON alias.group_id=g.id WHERE alias.team_id=$1 AND alias.project_key=$2 AND alias.name=$3 AND g.deleted_at IS NULL FOR UPDATE OF g`, r.TeamID, r.ProjectKey, r.Group).Scan(&id, &name, &namespace)
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return result, err
	}
	if strings.SplitN(namespace, ".", 2)[0] == r.NamespaceLabel {
		return result, ErrProjectConfigurationInvalid
	}
	if err = SetServiceAuditActor(ctx, tx, r.ActorID); err != nil {
		return result, err
	}
	if err = retireManagedNamespace(ctx, tx, id, r.Now); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.project_publisher_groups SET namespace='' WHERE id=$1`, id); err != nil {
		return result, err
	}
	if err = d.ensureManagedGroupNamespace(ctx, tx, ApplyProjectConfigurationRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Now: r.Now}, id, name, c.Publishers[name], r.NamespaceLabel); err != nil {
		return result, err
	}
	services, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, err
	}
	for _, service := range services {
		if service.GroupID.String != id || !service.PrivateServiceID.Valid {
			continue
		}
		if err = d.revokeAppliedServicePublishers(ctx, tx, q, service, r.Now); err != nil {
			return result, err
		}
		if err = d.ensureManagedServiceEndpoint(ctx, tx, service.PrivateServiceID.String, id, r.DNSAutomation, r.Now); err != nil {
			return result, err
		}
		if err = d.reconcileAppliedPublisherGrants(ctx, tx, q, service, r.ActorID, r.Now); err != nil {
			return result, err
		}
	}
	row.Revision++
	if _, err = tx.Exec(ctx, `UPDATE control.applied_project_services SET desired_revision=$3 WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey, row.Revision); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.applied_projects SET revision=$3,updated_at=$4 WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey, row.Revision, r.Now); err != nil {
		return result, err
	}
	if err = recordPublisherGroupUpdate(ctx, tx, id, r.ActorID, "", "namespace-rename/"+r.IdempotencyKey, r.Now); err != nil {
		return result, err
	}
	result, err = d.appliedProjectStatus(ctx, tx, row, c)
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	ciphertext, err = d.storageKey.Seal(context, data)
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.publisher_namespace_renames(team_id,project_key,idempotency_key,request_digest,response_ciphertext,storage_key_id) VALUES($1,$2,$3,$4,$5,$6)`, r.TeamID, r.ProjectKey, r.IdempotencyKey, digest[:], ciphertext, d.storageKey.CurrentID()); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
