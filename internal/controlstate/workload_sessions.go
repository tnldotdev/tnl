package controlstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/workloadproof"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type VisitorSubject = tunnelv1.VisitorSubject

const WorkloadLease = 90 * time.Second
const WorkloadRenewAfter = 30 * time.Second

type WorkloadSession struct {
	ID             string         `json:"id"`
	Credential     string         `json:"credential"`
	TeamID         string         `json:"team_id"`
	ProjectKey     string         `json:"project_key"`
	CI             string         `json:"ci"`
	Subject        VisitorSubject `json:"subject"`
	LeaseExpiresAt time.Time      `json:"lease_expires_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	RenewAfter     time.Time      `json:"renew_after"`
	ServiceIDs     []string       `json:"service_ids"`
	RunID          string         `json:"run_id"`
	RunAttempt     string         `json:"run_attempt"`
	CheckRunID     string         `json:"check_run_id"`
}

type ExchangeGitHubWorkloadRequest struct {
	TeamID, ProjectKey, CI string
	Execution              oidcauth.GitHubExecution
	PublicKey              ed25519.PublicKey
	Signature              []byte
	Services               []string
}

func workloadSubject(id string) VisitorSubject {
	return VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: id}
}
func workloadCredentialContext(id string) string { return "workload-credential/" + id }

// exchange is called only after GitHub signature/issuer/audience verification.
// jobs cannot establish repository metadata or alter applied policy here.
func (d *Database) ExchangeGitHubWorkload(ctx context.Context, r ExchangeGitHubWorkloadRequest, now time.Time) (result WorkloadSession, retErr error) {
	c := r.Execution
	if c.Validate(now) != nil || len(r.PublicKey) != 32 || len(r.Signature) != 64 || !ed25519.Verify(r.PublicKey, workloadproof.Digest(r.TeamID, r.ProjectKey, r.CI, c.AssertionDigest, r.Services), r.Signature) {
		return result, ErrWorkloadDenied
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "exchange workload", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return result, publisherLookupError(err, ErrWorkloadDenied)
	}
	project, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, publisherLookupError(err, ErrWorkloadDenied)
	}
	configuration, err := d.openAppliedProject(project)
	if err != nil {
		return result, err
	}
	p, found := configuration.CI[r.CI]
	if !found || !p.GitHub.matches(c) {
		return result, ErrWorkloadDenied
	}
	services := slices.Clone(r.Services)
	if services == nil {
		services = slices.Clone(p.Services)
	}
	if len(services) == 0 || len(services) > 32 {
		return result, ErrWorkloadDenied
	}
	slices.Sort(services)
	for i, s := range services {
		if !slices.Contains(p.Services, s) || i > 0 && services[i-1] == s {
			return result, ErrWorkloadDenied
		}
	}
	requested := slices.Clone(r.Services)
	slices.Sort(requested)
	request, _ := json.Marshal([]any{r.CI, requested})
	requestDigest := sha256.Sum256(request)
	var id string
	var public, previous []byte
	err = tx.QueryRow(ctx, `SELECT id,public_key,request_digest FROM control.workload_sessions WHERE team_id=$1 AND project_key=$2 AND repository_id=$3 AND run_id=$4 AND run_attempt=$5 AND check_run_id=$6 FOR UPDATE`, r.TeamID, r.ProjectKey, c.RepositoryID, c.RunID, c.RunAttempt, c.CheckRunID).Scan(&id, &public, &previous)
	if err == nil {
		if !bytes.Equal(public, r.PublicKey) || !bytes.Equal(previous, requestDigest[:]) {
			return result, ErrWorkloadConflict
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		id, err = opaqueid.New("wls_")
		if err != nil {
			return result, err
		}
		secret, _, err := privateSecret()
		if err != nil {
			return result, err
		}
		credential := "wlc_" + secret
		// the namespace prefix is included in the digest and never accepted by
		// the human control-session parser.
		digestValue := sha256.Sum256([]byte(credential))
		sealed, err := d.storageKey.Seal(workloadCredentialContext(id), []byte(credential))
		if err != nil {
			return result, err
		}
		claims, _ := json.Marshal(c)
		deadline := now.Add(time.Duration(p.MaxDurationSeconds) * time.Second)
		lease := minTime(now.Add(WorkloadLease), deadline)
		_, err = tx.Exec(ctx, `INSERT INTO control.workload_sessions(id,team_id,project_key,ci_name,repository_id,run_id,run_attempt,check_run_id,public_key,request_digest,claims,credential_digest,credential_ciphertext,storage_key_id,created_at,renewed_at,lease_expires_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,convert_from($11::bytea,'UTF8')::jsonb,$12,$13,$14,$15,$15,$16,$17)`, id, r.TeamID, r.ProjectKey, r.CI, c.RepositoryID, c.RunID, c.RunAttempt, c.CheckRunID, []byte(r.PublicKey), requestDigest[:], claims, digestValue[:], sealed, d.storageKey.CurrentID(), now, lease, deadline)
		if err != nil {
			return result, err
		}
		for _, s := range services {
			tag, err := tx.Exec(ctx, `INSERT INTO control.workload_session_services(workload_session_id,private_service_id,service) SELECT $1,applied.private_service_id,applied.service FROM control.applied_project_services applied JOIN control.private_services service ON service.id=applied.private_service_id WHERE applied.team_id=$2 AND applied.project_key=$3 AND applied.service=$4 AND service.enabled AND service.deleted_at IS NULL`, id, r.TeamID, r.ProjectKey, s)
			if err != nil {
				return result, err
			}
			if tag.RowsAffected() != 1 {
				return result, ErrWorkloadDenied
			}
		}
		if err = workloadAudit(ctx, tx, id, "start", "", now); err != nil {
			return result, err
		}
	} else {
		return result, err
	}
	// one signed jti may only resume its exact committed session/assertion.
	jti := sha256.Sum256([]byte(oidcauth.GitHubIssuer + "\x00" + c.JTI))
	var saved string
	var assertion []byte
	err = tx.QueryRow(ctx, `INSERT INTO control.workload_assertions(jti_digest,assertion_digest,workload_session_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(jti_digest) DO UPDATE SET jti_digest=EXCLUDED.jti_digest RETURNING workload_session_id,assertion_digest`, jti[:], c.AssertionDigest[:], id, time.Unix(c.ExpiresAt, 0)).Scan(&saved, &assertion)
	if err != nil {
		return result, err
	}
	if saved != id || !bytes.Equal(assertion, c.AssertionDigest[:]) {
		return result, ErrWorkloadConflict
	}
	result, err = d.workloadSession(ctx, tx, id, now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func workloadAudit(ctx context.Context, tx pgx.Tx, id, event, service string, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO control.workload_audit(workload_session_id,event,private_service_id,occurred_at) VALUES($1,$2,$3,$4)`, id, event, nullableText(service), now)
	return err
}

func (d *Database) workloadSession(ctx context.Context, tx pgx.Tx, id string, now time.Time) (r WorkloadSession, err error) {
	q := controlstatedb.New(tx)
	row, err := q.GetWorkloadSession(ctx, id)
	if err != nil {
		return r, publisherLookupError(err, ErrWorkloadDenied)
	}
	r = WorkloadSession{ID: row.ID, TeamID: row.TeamID, ProjectKey: row.ProjectKey, CI: row.CiName, RunID: row.RunID, RunAttempt: row.RunAttempt, CheckRunID: row.CheckRunID, LeaseExpiresAt: row.LeaseExpiresAt.Time, ExpiresAt: row.ExpiresAt.Time, RenewAfter: minTime(row.RenewedAt.Time.Add(WorkloadRenewAfter), row.ExpiresAt.Time)}
	if row.RevokedAt.Valid || !r.LeaseExpiresAt.After(now) || !r.ExpiresAt.After(now) {
		return r, ErrWorkloadDenied
	}
	secret, _, err := d.storageKey.Open(row.StorageKeyID, workloadCredentialContext(id), row.CredentialCiphertext)
	if err != nil {
		return r, err
	}
	defer clear(secret)
	r.Credential = string(secret)
	r.Subject = workloadSubject(id)
	observability.WorkloadExecution(ctx, id, r.RunID, r.RunAttempt, r.CheckRunID)
	r.ServiceIDs = []string{}
	services, err := q.ListWorkloadSessionServices(ctx, id)
	if err != nil {
		return r, err
	}
	for _, service := range services {
		r.ServiceIDs = append(r.ServiceIDs, service.PrivateServiceID)
	}
	slices.Sort(r.ServiceIDs)
	return r, nil
}

// authenticate never creates a ControlPrincipal. the team lock serializes
// authorization with apply, including policy removal and service replacement.
func lockWorkloadCredential(ctx context.Context, tx pgx.Tx, credential string, now time.Time) (id string, err error) {
	if len(credential) < 5 || len(credential) > 256 || credential[:4] != "wlc_" {
		return "", ErrWorkloadDenied
	}
	digest := sha256.Sum256([]byte(credential))
	var team string
	err = tx.QueryRow(ctx, `SELECT id,team_id FROM control.workload_sessions WHERE credential_digest=$1`, digest[:]).Scan(&id, &team)
	if err != nil {
		return "", publisherLookupError(err, ErrWorkloadDenied)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
		return "", publisherLookupError(err, ErrWorkloadDenied)
	}
	var run, attempt, check string
	err = tx.QueryRow(ctx, `SELECT id,run_id,run_attempt,check_run_id FROM control.workload_sessions WHERE id=$1 AND revoked_at IS NULL AND lease_expires_at>$2 AND expires_at>$2 FOR UPDATE`, id, now).Scan(&id, &run, &attempt, &check)
	if err == nil {
		observability.WorkloadExecution(ctx, id, run, attempt, check)
	}
	return id, publisherLookupError(err, ErrWorkloadDenied)
}

func (d *Database) RenewWorkloadSession(ctx context.Context, id, credential string, now time.Time) (r WorkloadSession, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "renew workload", &retErr)()
	current, err := lockWorkloadCredential(ctx, tx, credential, now)
	if err != nil {
		return r, err
	}
	if current != id {
		return r, ErrWorkloadDenied
	}
	_, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET renewed_at=$2,lease_expires_at=LEAST($2::timestamptz+interval '90 seconds',expires_at) WHERE id=$1 AND renewed_at<=$2::timestamptz-interval '30 seconds'`, id, now)
	if err != nil {
		return r, err
	}
	if err = workloadAudit(ctx, tx, id, "renew", "", now); err != nil {
		return r, err
	}
	r, err = d.workloadSession(ctx, tx, id, now)
	if err != nil {
		return r, err
	}
	return r, tx.Commit(ctx)
}

func (d *Database) RevokeWorkloadSession(ctx context.Context, id, credential string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke workload", &retErr)()
	current, err := lockWorkloadCredential(ctx, tx, credential, now)
	if err != nil {
		return err
	}
	if current != id {
		return ErrWorkloadDenied
	}
	if _, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET revoked_at=$2 WHERE id=$1`, id, now); err != nil {
		return err
	}
	if err = workloadAudit(ctx, tx, id, "revoke", "", now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type WorkloadServiceAuthorization struct {
	Subject        VisitorSubject `json:"subject"`
	ServiceID      string         `json:"service_id"`
	ValidUntil     time.Time      `json:"valid_until"`
	PolicyRevision int64          `json:"policy_revision"`
}

// VisitorSubjectAccess is shared by human and workload data-plane adapters.
// call while holding the service/team admission lock; it never grants access
// from human membership to a workload or expands the issued service snapshot.
func VisitorSubjectAccess(ctx context.Context, tx pgx.Tx, service string, subject VisitorSubject, now time.Time) (time.Time, int64, error) {
	if subject.Validate() != nil {
		return time.Time{}, 0, ErrPrivateServiceAccess
	}
	if subject.Kind == tunnelv1.VisitorHumanDevice {
		var found bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.visitor_devices WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL)`, subject.DeviceID, subject.IdentityID).Scan(&found); err != nil {
			return time.Time{}, 0, err
		}
		if !found {
			return time.Time{}, 0, ErrPrivateServiceAccess
		}
		return privateVisitorAccess(ctx, tx, service, subject.IdentityID, now)
	}
	var until time.Time
	var revision int64
	var run, attempt, check string
	err := tx.QueryRow(ctx, `SELECT LEAST(w.lease_expires_at,w.expires_at,$3::timestamptz+interval '90 seconds'),p.revision,w.run_id,w.run_attempt,w.check_run_id FROM control.workload_sessions w JOIN control.workload_session_services rights ON rights.workload_session_id=w.id AND rights.private_service_id=$2 JOIN control.private_services s ON s.id=rights.private_service_id AND s.team_id=w.team_id AND s.enabled AND s.deleted_at IS NULL JOIN control.teams t ON t.id=w.team_id AND t.deleted_at IS NULL JOIN control.applied_projects p ON p.team_id=w.team_id AND p.project_key=w.project_key WHERE w.id=$1 AND w.revoked_at IS NULL AND w.lease_expires_at>$3 AND w.expires_at>$3`, subject.WorkloadSessionID, service, now).Scan(&until, &revision, &run, &attempt, &check)
	if err == nil {
		observability.WorkloadExecution(ctx, subject.WorkloadSessionID, run, attempt, check)
	}
	return until, revision, publisherLookupError(err, ErrPrivateServiceAccess)
}

func (d *Database) CheckWorkloadService(ctx context.Context, credential, service string, now time.Time) (r WorkloadServiceAuthorization, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "check workload service", &retErr)()
	id, err := lockWorkloadCredential(ctx, tx, credential, now)
	if err != nil {
		return r, err
	}
	r.Subject = workloadSubject(id)
	r.ServiceID = service
	r.ValidUntil, r.PolicyRevision, err = VisitorSubjectAccess(ctx, tx, service, r.Subject, now)
	if err != nil {
		return r, err
	}
	return r, tx.Commit(ctx)
}

// a trace-safe execution reference contains no JWT, credential or public key.
func (r WorkloadSession) ExecutionReference() string {
	return r.RunID + "/" + r.RunAttempt + "/" + r.CheckRunID
}

func workloadRequestScope(id, key string) string {
	digest := sha256.Sum256([]byte(key))
	return "workload-ingress/" + id + "/" + hex.EncodeToString(digest[:])
}
