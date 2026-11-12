package state

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var (
	ErrWorkloadDenied   = errors.New("visitor identity or current saved permission does not authorize this operation")
	ErrWorkloadConflict = errors.New("visitor session is already bound to another key or scope")
	ErrWorkloadExpired  = fmt.Errorf("%w: visitor session lease, source proof, or fixed deadline has expired", ErrWorkloadDenied)
)

type VisitorSubject = tunnelv1.VisitorSubject

const WorkloadLease = 90 * time.Second
const WorkloadRenewAfter = 30 * time.Second

// workload sessions are the visitor transport's leased principals. environment
// permissions, not project declarations or logical group selectors, own scope.
type WorkloadSession struct {
	RenewalSequence    int64                    `json:"renewal_sequence"`
	ID                 string                   `json:"id"`
	Credential         string                   `json:"credential"`
	TeamID             string                   `json:"team_id"`
	ProjectKey         string                   `json:"project_key"`
	Workload           string                   `json:"workload"`
	Provider           string                   `json:"provider"`
	Subject            VisitorSubject           `json:"subject"`
	LeaseExpiresAt     time.Time                `json:"lease_expires_at"`
	IdentityExpiresAt  time.Time                `json:"identity_expires_at"`
	ExpiresAt          *time.Time               `json:"expires_at,omitempty"`
	RenewAfter         time.Time                `json:"renew_after"`
	ServiceIDs         []string                 `json:"service_ids"`
	Binding            string                   `json:"binding"`
	AssertionExpiresAt *time.Time               `json:"assertion_expires_at,omitempty"`
	GitHub             *WorkloadGitHubExecution `json:"github,omitempty"`
}

type WorkloadGitHubExecution struct {
	RepositoryID      string `json:"repository_id"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
	CheckRunID        string `json:"check_run_id"`
}

func workloadSubject(id string) VisitorSubject {
	return VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: id}
}

func workloadCredentialContext(id string) string { return "workload-credential/" + id }

func workloadAudit(ctx context.Context, tx pgx.Tx, id, event, service string, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO control.workload_audit(workload_session_id,event,service_id,occurred_at) VALUES($1,$2,$3,$4)`, id, event, nullableText(service), now)
	return err
}

func (d *Database) workloadSession(ctx context.Context, tx pgx.Tx, id string, now time.Time) (r WorkloadSession, err error) {
	q := controlstatedb.New(tx)
	row, err := q.GetWorkloadSession(ctx, id)
	if err != nil {
		return r, publisherLookupError(err, ErrWorkloadDenied)
	}
	if err = verifyMachineSession(ctx, tx, id, now); err != nil {
		return r, err
	}
	r = WorkloadSession{ID: row.ID, TeamID: row.TeamID, ProjectKey: row.ProjectKey, Workload: row.WorkloadName, Provider: row.Provider, LeaseExpiresAt: row.LeaseExpiresAt.Time, RenewAfter: minTime(row.RenewedAt.Time.Add(WorkloadRenewAfter), row.IdentityExpiresAt.Time), RenewalSequence: row.RenewalSequence, Binding: row.Binding, IdentityExpiresAt: row.IdentityExpiresAt.Time}
	if row.ExpiresAt.Valid {
		r.ExpiresAt = new(row.ExpiresAt.Time)
		r.RenewAfter = minTime(r.RenewAfter, *r.ExpiresAt)
	}
	if row.Provider == "github" {
		var claims oidc.WorkloadExecution
		if err = json.Unmarshal(row.Claims, &claims); err != nil {
			return r, err
		}
		if claims.GitHub == nil {
			return r, ErrWorkloadDenied
		}
		g := claims.GitHub
		r.GitHub = &WorkloadGitHubExecution{RepositoryID: g.RepositoryID, RepositoryOwnerID: g.RepositoryOwnerID, RunID: row.RunID.String, RunAttempt: row.RunAttempt.String, CheckRunID: row.CheckRunID.String}
	}
	if row.RevokedAt.Valid {
		return r, ErrWorkloadDenied
	}
	if now.Before(row.CreatedAt.Time) || now.Before(row.RenewedAt.Time) || !r.LeaseExpiresAt.After(now) || r.ExpiresAt != nil && !r.ExpiresAt.After(now) || !r.IdentityExpiresAt.After(now) {
		return r, ErrWorkloadExpired
	}
	secret, _, err := d.storageKey.Open(row.StorageKeyID, workloadCredentialContext(id), row.CredentialCiphertext)
	if err != nil {
		return r, err
	}
	defer clear(secret)
	r.Credential, r.Subject = string(secret), workloadSubject(id)
	observability.WorkloadExecution(ctx, id, row.RunID.String, row.RunAttempt.String, row.CheckRunID.String)
	r.ServiceIDs = []string{}
	services, err := q.ListWorkloadSessionServices(ctx, id)
	if err != nil {
		return r, err
	}
	for _, service := range services {
		r.ServiceIDs = append(r.ServiceIDs, service.ServiceID)
	}
	slices.Sort(r.ServiceIDs)
	return r, nil
}

type WorkloadRenewal struct {
	Sequence  int64
	Signature []byte
}

func (d *Database) RenewEnvironmentVisitorSession(ctx context.Context, id, credential string, proof WorkloadRenewal, now time.Time) (r WorkloadSession, retErr error) {
	if proof.Sequence <= 0 || len(proof.Signature) != ed25519.SignatureSize {
		return r, ErrWorkloadDenied
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "renew environment visitor", &retErr)()
	current, err := lockWorkloadCredential(ctx, tx, credential, clock)
	if err != nil {
		return r, err
	}
	if current.ID != id || !ed25519.Verify(current.PublicKey, workloadproof.Renew(id, proof.Sequence), proof.Signature) {
		return r, ErrWorkloadDenied
	}
	var sequence int64
	if err = tx.QueryRow(ctx, `SELECT renewal_sequence FROM control.workload_sessions WHERE id=$1`, id).Scan(&sequence); err != nil {
		return r, err
	}
	if proof.Sequence != sequence {
		if sequence == math.MaxInt64 || proof.Sequence != sequence+1 {
			return r, ErrWorkloadDenied
		}
		checked := clock.current()
		// current authority is checked after locks, but waiting spends the
		// entry-time lease budget. a retry never moves an accepted proof's clock.
		_, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET renewal_sequence=$3,
		lease_expires_at=CASE WHEN renewed_at<=$2::timestamptz-interval '30 seconds' THEN LEAST($2::timestamptz+interval '90 seconds',expires_at,identity_expires_at) ELSE lease_expires_at END,
		renewed_at=CASE WHEN renewed_at<=$2::timestamptz-interval '30 seconds' THEN $2 ELSE renewed_at END WHERE id=$1`, id, clock.entered, proof.Sequence)
		if err == nil {
			err = workloadAudit(ctx, tx, id, "renew", "", checked)
		}
	}
	if err != nil {
		return r, err
	}
	r, err = d.workloadSession(ctx, tx, id, clock.current())
	if err != nil {
		return r, err
	}
	return r, tx.Commit(ctx)
}

// the original session credential can revoke after source expiry. it cannot
// obtain a new permission, restore a session, or revoke another session.
func (d *Database) RevokeEnvironmentVisitorSession(ctx context.Context, id, credential string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke environment visitor", &retErr)()
	digest := sha256.Sum256([]byte(credential))
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.workload_sessions WHERE id=$1 AND credential_digest=$2`, id, digest[:]).Scan(&team); err != nil {
		return publisherLookupError(err, ErrWorkloadDenied)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
		return err
	}
	var authenticated string
	if err = tx.QueryRow(ctx, `SELECT id FROM control.workload_sessions WHERE id=$1 AND credential_digest=$2 FOR UPDATE`, id, digest[:]).Scan(&authenticated); err != nil {
		return publisherLookupError(err, ErrWorkloadDenied)
	}
	tag, err := tx.Exec(ctx, `UPDATE control.workload_sessions SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, id, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 0 {
		if err = workloadAudit(ctx, tx, id, "revoke", "", now); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type WorkloadServiceAuthorization struct {
	Subject        VisitorSubject `json:"subject"`
	ServiceID      string         `json:"service_id"`
	ValidUntil     time.Time      `json:"valid_until"`
	PolicyRevision int64          `json:"policy_revision"`
}

// admission checks the current permission as well as the immutable issued
// service snapshot. environment applies cannot add rights to that snapshot.
func VisitorSubjectAccess(ctx context.Context, tx pgx.Tx, service string, subject VisitorSubject, now time.Time) (time.Time, int64, error) {
	if subject.Validate() != nil {
		return time.Time{}, 0, ErrServiceAccess
	}
	if subject.Kind == tunnelv1.VisitorHumanDevice {
		var found bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.visitor_devices WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL)`, subject.DeviceID, subject.IdentityID).Scan(&found); err != nil {
			return time.Time{}, 0, err
		}
		if !found {
			return time.Time{}, 0, ErrServiceAccess
		}
		return privateVisitorAccess(ctx, tx, service, subject.IdentityID, now)
	}
	if err := verifyMachineSession(ctx, tx, subject.WorkloadSessionID, now); err != nil {
		return time.Time{}, 0, ErrServiceAccess
	}
	var until time.Time
	var revision int64
	err := tx.QueryRow(ctx, `SELECT LEAST(session.lease_expires_at,session.expires_at,session.identity_expires_at,source.permission_deadline,permission.expires_at,$3::timestamptz+interval '90 seconds'),environment.mutation_revision
	FROM control.workload_sessions session
	JOIN control.workload_session_machines source ON source.session_id=session.id
	JOIN control.machine_workload_permissions permission ON permission.id=source.permission_id
	JOIN control.environments environment ON environment.id=source.environment_id
	JOIN control.workload_session_services rights ON rights.workload_session_id=session.id AND rights.service_id=$2 AND rights.service=ANY(permission.services)
	JOIN control.applied_project_services binding ON binding.service_id=rights.service_id AND binding.group_id=environment.group_id
	JOIN control.services service ON service.id=rights.service_id AND service.team_id=session.team_id AND service.enabled AND service.deleted_at IS NULL AND service.protocol=source.expected_protocols->>rights.service
	JOIN control.teams team ON team.id=session.team_id AND team.deleted_at IS NULL
	WHERE session.id=$1 AND session.revoked_at IS NULL AND session.lease_expires_at>$3 AND session.identity_expires_at>$3 AND (session.expires_at IS NULL OR session.expires_at>$3)`, subject.WorkloadSessionID, service, now).Scan(&until, &revision)
	return until, revision, publisherLookupError(err, ErrServiceAccess)
}

func (d *Database) CheckWorkloadService(ctx context.Context, credential, service string, now time.Time) (r WorkloadServiceAuthorization, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "check environment visitor service", &retErr)()
	source, err := lockWorkloadCredential(ctx, tx, credential, clock)
	if err != nil {
		return r, err
	}
	r.Subject, r.ServiceID = workloadSubject(source.ID), service
	r.ValidUntil, r.PolicyRevision, err = VisitorSubjectAccess(ctx, tx, service, r.Subject, clock.current())
	if err != nil {
		return r, err
	}
	return r, tx.Commit(ctx)
}

func (r WorkloadSession) ExecutionReference() string {
	if r.GitHub == nil {
		return ""
	}
	return r.GitHub.RunID + "/" + r.GitHub.RunAttempt + "/" + r.GitHub.CheckRunID
}
