package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/oidcauth"
)

var (
	ErrWorkloadDenied   = errors.New("workload is not authorized by the saved ci policy")
	ErrWorkloadConflict = errors.New("workload execution is already bound to another key or scope")
	ErrWorkloadBinding  = errors.New("ci repository binding requires verified GitHub repository metadata")
	appliedNumericID    = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

type ProjectCI struct {
	GitHub             ProjectCIGitHub `json:"github"`
	Services           []string        `json:"services"`
	MaxDurationSeconds int             `json:"max_duration_seconds"`
}
type ProjectCIGitHub struct {
	Repository        string   `json:"repository"`
	RepositoryID      string   `json:"repository_id"`
	RepositoryOwnerID string   `json:"repository_owner_id"`
	WorkflowRef       string   `json:"workflow_ref"`
	Ref               string   `json:"ref"`
	Events            []string `json:"events"`
	Environment       string   `json:"environment,omitempty"`
	JobWorkflowRef    string   `json:"job_workflow_ref,omitempty"`
}

func (p ProjectCIGitHub) matches(c oidcauth.GitHubExecution) bool {
	return p.Repository == c.Repository && p.RepositoryID == c.RepositoryID && p.RepositoryOwnerID == c.RepositoryOwnerID && p.WorkflowRef == c.WorkflowRef && p.Ref == c.Ref && slices.Contains(p.Events, c.Event) && (p.Environment == "" || p.Environment == c.Environment) && (p.JobWorkflowRef == "" || p.JobWorkflowRef == c.JobWorkflowRef)
}

func normalizeProjectCI(c *ProjectConfiguration) error {
	if len(c.CI) > 32 {
		return ErrProjectConfigurationInvalid
	}
	for name, p := range c.CI {
		g := p.GitHub
		prefix := g.Repository + "/"
		workflow, suffix, ok := strings.Cut(strings.TrimPrefix(g.WorkflowRef, prefix), "@")
		if !strings.HasPrefix(g.WorkflowRef, prefix) || !ok || suffix != g.Ref || !appliedNumericID.MatchString(g.RepositoryID) || !appliedNumericID.MatchString(g.RepositoryOwnerID) {
			return ErrWorkloadBinding
		}
		services := map[string]config.Service{}
		for key, s := range c.Services {
			if s.Publisher != "local" {
				services[key] = config.Service{}
			}
		}
		policy := config.CI{GitHub: config.CIGitHub{Repository: &g.Repository, Workflow: workflow, Ref: g.Ref, Events: g.Events}, Services: p.Services}
		if g.Environment != "" {
			policy.GitHub.Environment = &g.Environment
		}
		if g.JobWorkflowRef != "" {
			policy.GitHub.ReusableWorkflow = &g.JobWorkflowRef
		}
		if p.MaxDurationSeconds == 0 {
			p.MaxDurationSeconds = 3600
		}
		if p.MaxDurationSeconds < 1 || p.MaxDurationSeconds > 6*60*60 || len(g.WorkflowRef) > 1024 || len(g.Ref) > 512 || len(g.Environment) > 256 || len(g.JobWorkflowRef) > 1024 {
			return ErrProjectConfigurationInvalid
		}
		if err := config.ValidateCI(config.TNL{Services: services, CI: map[string]config.CI{name: policy}}); err != nil {
			return errors.Join(ErrProjectConfigurationInvalid, err)
		}
		slices.Sort(p.Services)
		slices.Sort(p.GitHub.Events)
		c.CI[name] = p
	}
	return nil
}

// apply and exchange take the same team mutation lock. narrowing deletes rights,
// never adds rights to an already issued execution session.
func reconcileWorkloadPolicies(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, c ProjectConfiguration) error {
	rows, err := tx.Query(ctx, `SELECT id,ci_name,claims FROM control.workload_sessions WHERE team_id=$1 AND project_key=$2 AND revoked_at IS NULL FOR UPDATE`, r.TeamID, r.ProjectKey)
	if err != nil {
		return err
	}
	type saved struct {
		id, name string
		claims   []byte
	}
	var sessions []saved
	for rows.Next() {
		var s saved
		if err = rows.Scan(&s.id, &s.name, &s.claims); err != nil {
			rows.Close()
			return err
		}
		sessions = append(sessions, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, s := range sessions {
		p, found := c.CI[s.name]
		var claims oidcauth.GitHubExecution
		if err = json.Unmarshal(s.claims, &claims); err != nil {
			return err
		}
		if !found || !p.GitHub.matches(claims) {
			if _, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET revoked_at=$2 WHERE id=$1`, s.id, r.Now); err != nil {
				return err
			}
			continue
		}
		if _, err = tx.Exec(ctx, `DELETE FROM control.workload_session_services right_ WHERE right_.workload_session_id=$1 AND NOT EXISTS(SELECT 1 FROM control.applied_project_services applied WHERE applied.team_id=$2 AND applied.project_key=$3 AND applied.service=ANY($4::text[]) AND applied.private_service_id=right_.private_service_id)`, s.id, r.TeamID, r.ProjectKey, p.Services); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET expires_at=LEAST(expires_at,created_at+($2::bigint*interval '1 second')),lease_expires_at=LEAST(lease_expires_at,created_at+($2::bigint*interval '1 second')) WHERE id=$1`, s.id, p.MaxDurationSeconds); err != nil {
			return err
		}
	}
	return nil
}
