package state

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrDeploymentPublisherNotFound = errors.New("deployment publisher not found")

type CreateDeploymentPublisherEnrollmentRequest struct {
	DeploymentScope
	Selector, IdempotencyKey string
	Services                 []string
	MaxMembers               int
	Lifetime                 time.Duration
	Now                      time.Time
}

type DeploymentPublisherEnrollment struct {
	Key          string            `json:"enrollment_key"`
	DeploymentID string            `json:"deployment_id"`
	ExpiresAt    time.Time         `json:"expires_at"`
	MaxMembers   int               `json:"max_members"`
	ID           string            `json:"enrollment_id"`
	Services     map[string]string `json:"services"`
}

type DeploymentPublisher struct {
	DeploymentPublisherStatus
	Services  map[string]string `json:"services"`
	RevokedAt *time.Time        `json:"revoked_at,omitempty"`
}

func deploymentPublisherEnrollmentContext(id string) string {
	return "deployment-publisher-enrollment/" + id
}

// enrollment captures exact saved bindings, not a rule that admits future names.
// recovery returns the original secret and deadline only while that approval is
// still usable. it never creates a replacement installation credential.
func (d *Database) CreateDeploymentPublisherEnrollment(ctx context.Context, r CreateDeploymentPublisherEnrollmentRequest) (result DeploymentPublisherEnrollment, retErr error) {
	clock := newAuthorizationClock(r.Now)
	if !validIdempotencyKey(r.IdempotencyKey) || len(r.Services) < 1 || len(r.Services) > 128 || r.MaxMembers < 1 || r.MaxMembers > 256 || r.Lifetime < time.Minute || r.Lifetime > 24*time.Hour {
		return result, ErrProjectConfigurationInvalid
	}
	names := slices.Clone(r.Services)
	slices.Sort(names)
	for i, name := range names {
		if !naming.ValidServiceName(name) || i > 0 && name == names[i-1] {
			return result, ErrProjectConfigurationInvalid
		}
	}
	data, err := json.Marshal(struct {
		Services   []string
		MaxMembers int
		Lifetime   time.Duration
	}{names, r.MaxMembers, r.Lifetime})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(data)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create deployment publisher enrollment", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, r.DeploymentScope, r.Now)
	if err != nil {
		return result, err
	}
	r.ActorID = access.actorID
	if err = access.servicesAllowed(names); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	deployment, err := q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Selector: r.Selector})
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentNotFound)
	}
	if !access.deploymentAllowed(deployment.ID) {
		return result, ErrDeploymentNotFound
	}
	row, err := q.FindDeploymentPublisherEnrollmentRequest(ctx, controlstatedb.FindDeploymentPublisherEnrollmentRequestParams{DeploymentID: deployment.ID, PrincipalID: access.principalID, IdempotencyKey: r.IdempotencyKey})
	if err == nil {
		if !bytes.Equal(row.RequestDigest, digest[:]) {
			return result, ErrServiceConflict
		}
		var consumed int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.deployment_publisher_members WHERE enrollment_id=$1`, row.ID).Scan(&consumed); err != nil {
			return result, err
		}
		if row.RevokedAt.Valid || !row.ExpiresAt.Time.After(clock.current()) || consumed >= int(row.MaxMembers) {
			return result, ErrPublisherEnrollment
		}
		services, err := d.currentPublisherEnrollmentServices(ctx, q, row, deployment)
		if err != nil {
			return result, err
		}
		secret, _, err := d.openSecret(row.StorageKeyID, deploymentPublisherEnrollmentContext(row.ID), row.SecretCiphertext)
		if err != nil {
			return result, err
		}
		defer clear(secret)
		actual := sha256.Sum256(secret)
		if !bytes.Equal(actual[:], row.SecretDigest) {
			return result, ErrPublisherEnrollment
		}
		result = DeploymentPublisherEnrollment{ID: row.ID, Services: services, Key: string(secret), DeploymentID: deployment.ID, ExpiresAt: row.ExpiresAt.Time.UTC(), MaxMembers: int(row.MaxMembers)}
	} else {
		if !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		configuration, err := d.openDeploymentConfiguration(deployment)
		if err != nil {
			return result, err
		}
		bindings, err := q.ListDeploymentPublisherServices(ctx, deployment.ID)
		if err != nil {
			return result, err
		}
		byName := map[string]controlstatedb.ControlAppliedProjectService{}
		for _, binding := range bindings {
			byName[binding.Service] = binding
		}
		scopes := make([]controlstatedb.ControlDeploymentPublisherEnrollmentService, 0, len(names))
		for _, name := range names {
			binding, bound := byName[name]
			service, saved := configuration.Services[name]
			if !bound || !saved || !binding.ServiceID.Valid && !binding.PublicURLID.Valid {
				return result, ErrProjectConfigurationInvalid
			}
			scopes = append(scopes, controlstatedb.ControlDeploymentPublisherEnrollmentService{Service: name, Protocol: service.Protocol, ServiceID: binding.ServiceID, PublicURLID: binding.PublicURLID})
		}
		until := r.Now.Add(r.Lifetime)
		if access.grantID != "" && access.expiresAt.Before(until) {
			until = access.expiresAt
		}
		if err = d.lockDeploymentMutation(ctx, tx, access); err != nil {
			return result, err
		}
		result, err = d.issueDeploymentPublisherEnrollment(ctx, tx, deployment.ID, r.ActorID, access.principalID, r.MaxMembers, until, r.IdempotencyKey, digest[:], scopes, clock.current())
		if err != nil {
			return result, err
		}
	}
	if !result.ExpiresAt.After(clock.current()) {
		return DeploymentPublisherEnrollment{}, ErrPublisherEnrollment
	}
	if err = d.commitDeploymentAccess(ctx, tx, access); err != nil {
		return DeploymentPublisherEnrollment{}, err
	}
	return result, nil
}

// one enrollment approves only the captured service bindings.
func (d *Database) issueDeploymentPublisherEnrollment(ctx context.Context, tx pgx.Tx, deployment, actor, principal string, maxMembers int, until time.Time, key string, requestDigest []byte, scopes []controlstatedb.ControlDeploymentPublisherEnrollmentService, now time.Time) (result DeploymentPublisherEnrollment, err error) {
	// postgres stores microseconds; the original reply and recovery must agree.
	until = until.UTC().Truncate(time.Microsecond)
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		return result, err
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return result, err
	}
	secret := id + "." + base64.RawURLEncoding.EncodeToString(random[:])
	digest := sha256.Sum256([]byte(secret))
	ciphertext, err := d.sealSecret(deploymentPublisherEnrollmentContext(id), []byte(secret))
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.deployment_publisher_enrollments(id,deployment_id,secret_digest,max_members,created_by_identity_id,expires_at,idempotency_key,request_digest,secret_ciphertext,storage_key_id,create_principal_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, deployment, digest[:], maxMembers, actor, until, key, requestDigest, ciphertext, d.storageKey.CurrentID(), principal)
	if err != nil {
		return result, err
	}
	result = DeploymentPublisherEnrollment{ID: id, Services: map[string]string{}, Key: secret, DeploymentID: deployment, ExpiresAt: until, MaxMembers: maxMembers}
	for _, scope := range scopes {
		if _, err = tx.Exec(ctx, `INSERT INTO control.deployment_publisher_enrollment_services(enrollment_id,service,protocol,service_id,public_url_id) VALUES($1,$2,$3,$4,$5)`, id, scope.Service, scope.Protocol, scope.ServiceID, scope.PublicURLID); err != nil {
			return result, err
		}
		result.Services[scope.Service] = scope.Protocol
	}
	auditPerson, auditPublisher := actor, ""
	if principal != "" && principal != actor {
		auditPerson, auditPublisher = "", principal
	}
	if err = recordDeploymentPublisherUpdate(ctx, tx, deployment, auditPerson, auditPublisher, "enrollment/"+id, now); err != nil {
		return result, err
	}
	return result, nil
}

func (d *Database) currentPublisherEnrollmentServices(ctx context.Context, q *controlstatedb.Queries, enrollment controlstatedb.ControlDeploymentPublisherEnrollment, deployment controlstatedb.ControlDeployment) (map[string]string, error) {
	scopes, err := q.ListDeploymentPublisherEnrollmentServices(ctx, enrollment.ID)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 || len(scopes) > 128 {
		return nil, ErrPublisherEnrollment
	}
	configuration, err := d.openDeploymentConfiguration(deployment)
	if err != nil {
		return nil, err
	}
	bindings, err := q.ListDeploymentPublisherServices(ctx, deployment.ID)
	if err != nil {
		return nil, err
	}
	byName := map[string]controlstatedb.ControlAppliedProjectService{}
	for _, binding := range bindings {
		byName[binding.Service] = binding
	}
	result := map[string]string{}
	for _, scope := range scopes {
		binding := byName[scope.Service]
		if scope.RevokedAt.Valid || binding.ServiceID != scope.ServiceID || binding.PublicURLID != scope.PublicURLID || configuration.Services[scope.Service].Protocol != scope.Protocol {
			return nil, ErrPublisherEnrollment
		}
		result[scope.Service] = scope.Protocol
	}
	return result, nil
}

func (d *Database) GetDeploymentPublisher(ctx context.Context, scope DeploymentScope, selector, publisher string) (result DeploymentPublisher, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get deployment publisher", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, scope, time.Now())
	if err != nil {
		return result, err
	}
	deployment, err := controlstatedb.New(tx).LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, Selector: selector})
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentNotFound)
	}
	if !access.deploymentAllowed(deployment.ID) {
		return result, ErrDeploymentNotFound
	}
	if err = access.publisherAllowed(ctx, controlstatedb.New(tx), publisher); err != nil {
		return result, err
	}
	result, err = deploymentPublisherStatus(ctx, controlstatedb.New(tx), deployment.ID, publisher, time.Now())
	if err != nil {
		return result, err
	}
	return result, d.commitDeploymentAccess(ctx, tx, access)
}

func (d *Database) ListDeploymentPublishers(ctx context.Context, scope DeploymentScope, selector, after string, limit int) (result []DeploymentPublisher, retErr error) {
	if limit < 1 || limit > 100 || after != "" && !opaqueid.Valid(after, opaqueid.PublisherIdentityPrefix) {
		return nil, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list deployment publishers", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, scope, time.Now())
	if err != nil {
		return nil, err
	}
	q := controlstatedb.New(tx)
	deployment, err := q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, Selector: selector})
	if err != nil {
		return nil, publisherLookupError(err, ErrDeploymentNotFound)
	}
	if !access.deploymentAllowed(deployment.ID) {
		return nil, ErrDeploymentNotFound
	}
	ids, err := q.ListDeploymentPublisherIDs(ctx, controlstatedb.ListDeploymentPublisherIDsParams{DeploymentID: deployment.ID, AfterID: after, PageLimit: int32(limit), ManagementGrant: access.grantID})
	if err != nil {
		return nil, err
	}
	result = []DeploymentPublisher{}
	now := time.Now()
	for _, id := range ids {
		publisher, err := deploymentPublisherStatus(ctx, q, deployment.ID, id, now)
		if err != nil {
			return nil, err
		}
		result = append(result, publisher)
	}
	return result, d.commitDeploymentAccess(ctx, tx, access)
}

func deploymentPublisherStatus(ctx context.Context, q *controlstatedb.Queries, deployment, publisher string, now time.Time) (result DeploymentPublisher, err error) {
	row, err := q.GetDeploymentPublisherStatus(ctx, controlstatedb.GetDeploymentPublisherStatusParams{DeploymentID: deployment, PublisherID: publisher})
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisherNotFound)
	}
	member := row.ControlDeploymentPublisherMember
	result.DeploymentPublisherStatus = DeploymentPublisherStatus{
		DeploymentPublisherIdentity: DeploymentPublisherIdentity{TeamID: row.TeamID, ProjectKey: row.ProjectKey, DeploymentID: deployment, DeploymentName: row.DeploymentName, PublisherIdentityID: publisher, KeyID: member.KeyID},
		ObservedRevision:            member.ObservedRevision, CurrentRevision: row.CurrentRevision, SnapshotAt: now,
	}
	if row.RevokedAt.Valid {
		result.RevokedAt = &row.RevokedAt.Time
	}
	if member.LeaseExpiresAt.Valid {
		result.LeaseExpiresAt = &member.LeaseExpiresAt.Time
	}
	if member.AcknowledgedAt.Valid {
		result.AcknowledgedAt = &member.AcknowledgedAt.Time
	}
	result.Runtime, err = publisherRuntimeStatus(ctx, q, publisher, now)
	if err != nil {
		return result, err
	}
	result.Healthy = !row.RevokedAt.Valid && member.Healthy && member.AcknowledgedAt.Valid && member.LeaseExpiresAt.Time.After(now) && member.ObservedRevision == row.CurrentRevision && (result.Runtime == nil || result.Runtime.Active)
	result.Services = map[string]string{}
	scopes, err := q.ListDeploymentPublisherEnrollmentServices(ctx, member.EnrollmentID)
	if err != nil {
		return result, err
	}
	for _, scope := range scopes {
		result.Services[scope.Service] = scope.Protocol
	}
	return result, nil
}

func (d *Database) RevokeDeploymentPublisher(ctx context.Context, scope DeploymentScope, selector, publisher string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke deployment publisher", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, scope, now)
	if err != nil {
		return err
	}
	scope.ActorID = access.actorID
	q := controlstatedb.New(tx)
	deployment, err := q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, Selector: selector})
	if err != nil {
		return publisherLookupError(err, ErrDeploymentNotFound)
	}
	if !access.deploymentAllowed(deployment.ID) {
		return ErrDeploymentNotFound
	}
	if err = access.publisherAllowed(ctx, q, publisher); err != nil {
		return err
	}
	if _, err = q.GetDeploymentPublisherStatus(ctx, controlstatedb.GetDeploymentPublisherStatusParams{DeploymentID: deployment.ID, PublisherID: publisher}); err != nil {
		return publisherLookupError(err, ErrDeploymentPublisherNotFound)
	}
	if err = access.setAuditActor(ctx, tx); err != nil {
		return err
	}
	if err = lockPublisherPublications(ctx, tx, scope.TeamID, publisher, ""); err != nil {
		return err
	}
	if err = d.lockDeploymentMutation(ctx, tx, access); err != nil {
		return err
	}
	auditPerson, _ := access.auditActor()
	if err = revokePublisherIdentity(ctx, tx, q, scope.TeamID, publisher, auditPerson, now); err != nil {
		return err
	}
	return d.commitDeploymentAccess(ctx, tx, access)
}
