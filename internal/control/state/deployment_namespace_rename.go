package state

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
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type RenameDeploymentNamespaceRequest struct {
	TeamID, ProjectKey, Deployment, NamespaceLabel, ActorID, IdempotencyKey string
	ExpectedRevision                                                        int64
	DNSAutomation                                                           bool
	Now                                                                     time.Time
}

// RenameDeploymentNamespace changes DNS and publication authority in one
// transaction. a retry returns the original encrypted response, even after a
// later mutation. selector rename is deliberately a separate operation.
func (d *Database) RenameDeploymentNamespace(ctx context.Context, r RenameDeploymentNamespaceRequest) (result AppliedProjectConfiguration, retErr error) {
	if !naming.ValidProjectKey(r.ProjectKey) || !naming.ValidServiceName(r.Deployment) && !opaqueid.Valid(r.Deployment, "dpl_") || r.Deployment == "local" || !naming.ValidServiceName(r.NamespaceLabel) || r.ExpectedRevision < 1 || r.ExpectedRevision == 1<<63-1 || !validStateText(r.IdempotencyKey) || len(r.IdempotencyKey) > 256 {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "rename publisher DNS namespace", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	request, _ := json.Marshal(struct {
		Deployment, Label string
		Revision          int64
	}{r.Deployment, r.NamespaceLabel, r.ExpectedRevision})
	digest := sha256.Sum256(request)
	context := "publisher-namespace-rename/" + r.TeamID + "/" + r.ProjectKey + "/" + r.IdempotencyKey
	var savedDigest, ciphertext []byte
	var storageKey string
	err = tx.QueryRow(ctx, `SELECT request_digest,response_ciphertext,storage_key_id FROM control.deployment_namespace_renames WHERE team_id=$1 AND project_key=$2 AND idempotency_key=$3`, r.TeamID, r.ProjectKey, r.IdempotencyKey).Scan(&savedDigest, &ciphertext, &storageKey)
	if err == nil {
		if !bytes.Equal(savedDigest, digest[:]) {
			return result, ErrServiceConflict
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
	deployment, err := q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Selector: r.Deployment})
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	id, name, namespace := deployment.ID, deployment.Name, deployment.Namespace
	record, err := d.openAppliedProjectRecord(row)
	if err != nil {
		return result, err
	}
	c := record.Deployments[name]
	snapshot, err := d.openDeploymentConfiguration(deployment)
	if err != nil {
		return result, err
	}
	if strings.SplitN(namespace, ".", 2)[0] == r.NamespaceLabel {
		return result, ErrProjectConfigurationInvalid
	}
	if err = SetServiceAuditActor(ctx, tx, r.ActorID); err != nil {
		return result, err
	}
	if err = retireServiceNamespace(ctx, tx, id, r.Now); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.deployments SET namespace='' WHERE id=$1`, id); err != nil {
		return result, err
	}
	if err = d.ensureDeploymentNamespace(ctx, tx, ApplyProjectConfigurationRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Now: r.Now}, id, name, snapshot.Settings, r.NamespaceLabel); err != nil {
		return result, err
	}
	services, err := q.ListDeploymentPublisherServices(ctx, id)
	if err != nil {
		return result, err
	}
	for _, service := range services {
		if !service.ServiceID.Valid {
			continue
		}
		if err = d.revokeAppliedServicePublishers(ctx, tx, q, service, r.Now); err != nil {
			return result, err
		}
		if err = d.ensureServiceEndpoint(ctx, tx, service.ServiceID.String, id, r.DNSAutomation, r.Now); err != nil {
			return result, err
		}
		if err = d.reconcileAppliedPublisherGrants(ctx, tx, q, service, r.ActorID, r.Now); err != nil {
			return result, err
		}
	}
	row.Revision++
	deployment, err = q.LockDeploymentByID(ctx, id)
	if err != nil {
		return result, err
	}
	snapshot.Namespace = deployment.Namespace
	if err = d.writeDeploymentConfiguration(ctx, tx, deployment, snapshot); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.applied_projects SET revision=$3,updated_at=$4 WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey, row.Revision, r.Now); err != nil {
		return result, err
	}
	if err = recordDeploymentPublisherUpdate(ctx, tx, id, r.ActorID, "", "namespace-rename/"+r.IdempotencyKey, r.Now); err != nil {
		return result, err
	}
	result, err = d.appliedProjectStatus(ctx, tx, row, name, c)
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
	if _, err = tx.Exec(ctx, `INSERT INTO control.deployment_namespace_renames(team_id,project_key,idempotency_key,request_digest,response_ciphertext,storage_key_id) VALUES($1,$2,$3,$4,$5,$6)`, r.TeamID, r.ProjectKey, r.IdempotencyKey, digest[:], ciphertext, d.storageKey.CurrentID()); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
