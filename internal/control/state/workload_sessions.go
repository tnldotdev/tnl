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
	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type VisitorSubject = tunnelv1.VisitorSubject

const WorkloadLease = 90 * time.Second
const WorkloadRenewAfter = 30 * time.Second

type WorkloadSession struct {
	ID                 string                   `json:"id"`
	Credential         string                   `json:"credential"`
	TeamID             string                   `json:"team_id"`
	ProjectKey         string                   `json:"project_key"`
	Workload           string                   `json:"workload"`
	Provider           string                   `json:"provider"`
	Subject            VisitorSubject           `json:"subject"`
	LeaseExpiresAt     time.Time                `json:"lease_expires_at"`
	ExpiresAt          time.Time                `json:"expires_at"`
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

type ExchangeWorkloadRequest struct {
	TeamID, ProjectKey, Workload, SourceFingerprint, Nonce string
	Execution                                              oidcauth.WorkloadExecution
	PublicKey                                              ed25519.PublicKey
	Signature                                              []byte
	Services                                               []string
}

func workloadSubject(id string) VisitorSubject {
	return VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: id}
}
func workloadCredentialContext(id string) string { return "workload-credential/" + id }

// exchange is called only after provider signature/issuer/audience verification.
// jobs cannot establish repository metadata or alter applied policy here.
func (d *Database) ExchangeWorkload(ctx context.Context, r ExchangeWorkloadRequest, now time.Time) (result WorkloadSession, retErr error) {
	c := r.Execution
	if c.Validate(now) != nil || !workloadproof.ValidNonce(r.Nonce) || !fingerprintPattern.MatchString(r.SourceFingerprint) || len(r.PublicKey) != 32 || len(r.Signature) != 64 || !ed25519.Verify(r.PublicKey, workloadproof.Exchange(r.TeamID, r.ProjectKey, r.Workload, r.SourceFingerprint, r.Nonce, c.AssertionDigest, r.Services), r.Signature) {
		return result, ErrWorkloadDenied
	}
	team, err := d.workloadTeam(ctx, r.TeamID)
	if err != nil {
		return result, err
	}
	r.TeamID = team
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
	p, found := configuration.Workloads[r.Workload]
	if !found || project.SourceFingerprint != r.SourceFingerprint || !p.matches(c) {
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
	request, _ := json.Marshal([]any{r.Workload, r.SourceFingerprint, requested, c.IdentityDigest()})
	requestDigest := sha256.Sum256(request)
	var id string
	var public, previous []byte
	var repository, run, attempt, check string
	if c.GitHub != nil {
		g := c.GitHub
		repository, run, attempt, check = g.RepositoryID, g.RunID, g.RunAttempt, g.CheckRunID
	}
	err = tx.QueryRow(ctx, `SELECT id,public_key,request_digest FROM control.workload_sessions WHERE team_id=$1 AND project_key=$2 AND (session_nonce=$3 OR (provider='github' AND repository_id=$4 AND run_id=$5 AND run_attempt=$6 AND check_run_id=$7)) FOR UPDATE`, r.TeamID, r.ProjectKey, r.Nonce, repository, run, attempt, check).Scan(&id, &public, &previous)
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
		_, err = tx.Exec(ctx, `INSERT INTO control.workload_sessions(id,team_id,project_key,workload_name,repository_id,run_id,run_attempt,check_run_id,public_key,request_digest,claims,credential_digest,credential_ciphertext,storage_key_id,created_at,renewed_at,lease_expires_at,expires_at,provider,session_nonce,binding) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,convert_from($11::bytea,'UTF8')::jsonb,$12,$13,$14,$15,$15,$16,$17,$18,$19,$20)`, id, r.TeamID, r.ProjectKey, r.Workload, nullableText(repository), nullableText(run), nullableText(attempt), nullableText(check), []byte(r.PublicKey), requestDigest[:], claims, digestValue[:], sealed, d.storageKey.CurrentID(), now, lease, deadline, c.Provider, r.Nonce, workloadBinding(r.TeamID, r.ProjectKey, r.Workload, r.SourceFingerprint, c))
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
	if c.GitHub != nil {
		var reused bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.workload_sessions WHERE team_id=$1 AND project_key=$2 AND session_nonce=$3 AND id<>$4)`, r.TeamID, r.ProjectKey, r.Nonce, id).Scan(&reused); err != nil {
			return result, err
		}
		if reused {
			return result, ErrWorkloadConflict
		}
		if err = consumeWorkloadAssertion(ctx, tx, id, c); err != nil {
			return result, err
		}
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
	r = WorkloadSession{ID: row.ID, TeamID: row.TeamID, ProjectKey: row.ProjectKey, Workload: row.WorkloadName, Provider: row.Provider, LeaseExpiresAt: row.LeaseExpiresAt.Time, ExpiresAt: row.ExpiresAt.Time, RenewAfter: minTime(row.RenewedAt.Time.Add(WorkloadRenewAfter), row.ExpiresAt.Time)}
	r.Binding = row.Binding
	if row.Provider == "github" {
		var claims oidcauth.WorkloadExecution
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
	if !r.LeaseExpiresAt.After(now) || !r.ExpiresAt.After(now) {
		return r, ErrWorkloadExpired
	}
	secret, _, err := d.storageKey.Open(row.StorageKeyID, workloadCredentialContext(id), row.CredentialCiphertext)
	if err != nil {
		return r, err
	}
	defer clear(secret)
	r.Credential = string(secret)
	r.Subject = workloadSubject(id)
	observability.WorkloadExecution(ctx, id, row.RunID.String, row.RunAttempt.String, row.CheckRunID.String)
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
	err = tx.QueryRow(ctx, `SELECT id,COALESCE(run_id,''),COALESCE(run_attempt,''),COALESCE(check_run_id,'') FROM control.workload_sessions WHERE id=$1 AND revoked_at IS NULL AND lease_expires_at>$2 AND expires_at>$2 FOR UPDATE`, id, now).Scan(&id, &run, &attempt, &check)
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
	digest := sha256.Sum256([]byte(credential))
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.workload_sessions WHERE id=$1 AND credential_digest=$2`, id, digest[:]).Scan(&team); err != nil {
		return publisherLookupError(err, ErrWorkloadDenied)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
		return err
	}
	// retention may have removed the proof while this request waited for the
	// team lock. authenticate again under a row lock before confirming deletion.
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
	err := tx.QueryRow(ctx, `SELECT LEAST(w.lease_expires_at,w.expires_at,$3::timestamptz+interval '90 seconds'),p.revision,COALESCE(w.run_id,''),COALESCE(w.run_attempt,''),COALESCE(w.check_run_id,'') FROM control.workload_sessions w JOIN control.workload_session_services rights ON rights.workload_session_id=w.id AND rights.private_service_id=$2 JOIN control.private_services s ON s.id=rights.private_service_id AND s.team_id=w.team_id AND s.enabled AND s.deleted_at IS NULL JOIN control.teams t ON t.id=w.team_id AND t.deleted_at IS NULL JOIN control.applied_projects p ON p.team_id=w.team_id AND p.project_key=w.project_key WHERE w.id=$1 AND w.revoked_at IS NULL AND w.lease_expires_at>$3 AND w.expires_at>$3`, subject.WorkloadSessionID, service, now).Scan(&until, &revision, &run, &attempt, &check)
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
	if r.GitHub == nil {
		return ""
	}
	return r.GitHub.RunID + "/" + r.GitHub.RunAttempt + "/" + r.GitHub.CheckRunID
}

func workloadRequestScope(id, key string) string {
	digest := sha256.Sum256([]byte(key))
	return "workload-ingress/" + id + "/" + hex.EncodeToString(digest[:])
}
