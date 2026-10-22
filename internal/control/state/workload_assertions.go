package controlstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func workloadBinding(team, project, name, source string, c oidcauth.WorkloadExecution) string {
	b, _ := json.Marshal([]string{"tnl-workload-owner/v1", team, project, name, source, c.IdentityDigest()})
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// IdentifyWorkload rechecks saved policy after provider verification. this is a
// cache-selection hint, never a visitor credential or permission to reuse a key.
func (d *Database) IdentifyWorkload(ctx context.Context, team, project, name, source string, c oidcauth.WorkloadExecution, now time.Time) (string, error) {
	team, err := d.workloadTeam(ctx, team)
	if err != nil {
		return "", err
	}
	p, err := d.WorkloadPolicy(ctx, team, project, name, source)
	if err != nil {
		return "", err
	}
	if c.Validate(now) != nil || !p.matches(c) {
		return "", ErrWorkloadDenied
	}
	return workloadBinding(team, project, name, source, c), nil
}

// WorkloadAssertionPolicy authenticates the exact session before verifying a
// rotating assertion. attachment separately fences revocation and expired leases.
func (d *Database) WorkloadAssertionPolicy(ctx context.Context, id, credential string) (ProjectWorkload, error) {
	digest := sha256.Sum256([]byte(credential))
	var team, project, name, source string
	err := d.pool.QueryRow(ctx, `SELECT w.team_id,w.project_key,w.workload_name,p.source_fingerprint FROM control.workload_sessions w JOIN control.applied_projects p USING(team_id,project_key) WHERE w.id=$1 AND w.credential_digest=$2`, id, digest[:]).Scan(&team, &project, &name, &source)
	if err != nil {
		return ProjectWorkload{}, publisherLookupError(err, ErrWorkloadDenied)
	}
	return d.WorkloadPolicy(ctx, team, project, name, source)
}

func (d *Database) AttachWorkloadAssertion(ctx context.Context, id, credential string, c oidcauth.WorkloadExecution, signature []byte, now time.Time) (result WorkloadSession, retErr error) {
	if c.Validate(now) != nil {
		return result, ErrWorkloadDenied
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "attach workload assertion", &retErr)()
	row, err := controlstatedb.New(tx).GetWorkloadSession(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrWorkloadDenied)
	}
	digest := sha256.Sum256([]byte(credential))
	if !bytes.Equal(row.CredentialDigest, digest[:]) {
		return result, ErrWorkloadDenied
	}
	if _, err := controlstatedb.New(tx).LockLocalTeamForMutation(ctx, row.TeamID); err != nil {
		return result, err
	}
	row, err = controlstatedb.New(tx).GetWorkloadSession(ctx, id)
	if err != nil {
		return result, err
	}
	var previous oidcauth.WorkloadExecution
	if err = json.Unmarshal(row.Claims, &previous); err != nil {
		return result, err
	}
	if previous.IdentityDigest() != c.IdentityDigest() || !ed25519.Verify(row.PublicKey, workloadproof.Attach(id, c.AssertionDigest), signature) {
		return result, ErrWorkloadDenied
	}
	project, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: row.TeamID, ProjectKey: row.ProjectKey})
	if err != nil {
		return result, err
	}
	configuration, err := d.openAppliedProject(project)
	if err != nil {
		return result, err
	}
	p, found := configuration.Workloads[row.WorkloadName]
	if !found || !p.matches(c) || row.Binding != workloadBinding(row.TeamID, row.ProjectKey, row.WorkloadName, project.SourceFingerprint, c) || row.RevokedAt.Valid {
		return result, ErrWorkloadDenied
	}
	if !row.LeaseExpiresAt.Time.After(now) || !row.ExpiresAt.Time.After(now) {
		return result, ErrWorkloadExpired
	}
	if err = consumeWorkloadAssertion(ctx, tx, id, c); err != nil {
		return result, err
	}
	result, err = d.workloadSession(ctx, tx, id, now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func consumeWorkloadAssertion(ctx context.Context, tx pgx.Tx, id string, c oidcauth.WorkloadExecution) error {
	if c.GitHub == nil {
		return nil
	}
	jti := sha256.Sum256([]byte(oidcauth.GitHubIssuer + "\x00" + c.GitHub.JTI))
	var saved string
	var assertion []byte
	err := tx.QueryRow(ctx, `INSERT INTO control.workload_assertions(jti_digest,assertion_digest,workload_session_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(jti_digest) DO UPDATE SET jti_digest=EXCLUDED.jti_digest RETURNING workload_session_id,assertion_digest`, jti[:], c.AssertionDigest[:], id, time.Unix(c.ExpiresAt, 0)).Scan(&saved, &assertion)
	if err != nil {
		return err
	}
	if saved != id || !bytes.Equal(assertion, c.AssertionDigest[:]) {
		return ErrWorkloadConflict
	}
	return nil
}
