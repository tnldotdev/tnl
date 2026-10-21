package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/oidcauth"
)

var (
	ErrWorkloadDenied   = errors.New("workload is not authorized by the saved workload policy")
	ErrWorkloadConflict = errors.New("workload execution is already bound to another key or scope")
	ErrWorkloadBinding  = errors.New("workload binding requires verified provider metadata")
	ErrWorkloadExpired  = fmt.Errorf("%w: workload session lease or fixed window has expired", ErrWorkloadDenied)
	appliedNumericID    = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

type ProjectWorkload struct {
	Provider           string                 `json:"provider"`
	Trust              oidcauth.WorkloadTrust `json:"trust"`
	GitHub             *ProjectWorkloadGitHub `json:"github,omitempty"`
	Services           []string               `json:"services"`
	MaxDurationSeconds int                    `json:"max_duration_seconds"`
}
type ProjectWorkloadGitHub struct {
	Repository        string   `json:"repository"`
	RepositoryID      string   `json:"repository_id"`
	RepositoryOwnerID string   `json:"repository_owner_id"`
	WorkflowRef       string   `json:"workflow_ref"`
	Ref               string   `json:"ref"`
	Events            []string `json:"events"`
	Environment       string   `json:"environment,omitempty"`
	JobWorkflowRef    string   `json:"job_workflow_ref,omitempty"`
}

func (p ProjectWorkloadGitHub) matches(c oidcauth.GitHubExecution) bool {
	return p.Repository == c.Repository && p.RepositoryID == c.RepositoryID && p.RepositoryOwnerID == c.RepositoryOwnerID && p.WorkflowRef == c.WorkflowRef && p.Ref == c.Ref && slices.Contains(p.Events, c.Event) && (p.Environment == "" || p.Environment == c.Environment) && (p.JobWorkflowRef == "" || p.JobWorkflowRef == c.JobWorkflowRef)
}

func normalizeProjectWorkloads(c *ProjectConfiguration) error {
	if len(c.Workloads) > 32 {
		return ErrProjectConfigurationInvalid
	}
	for name, p := range c.Workloads {
		if p.Provider != "github" {
			if p.GitHub != nil {
				return ErrProjectConfigurationInvalid
			}
			if err := p.validateTrust(); err != nil {
				return err
			}
			if p.MaxDurationSeconds == 0 {
				p.MaxDurationSeconds = 3600
			}
			if !privateServiceName.MatchString(name) || p.MaxDurationSeconds < 1 || p.MaxDurationSeconds > 21600 || len(p.Services) == 0 || len(p.Services) > 32 {
				return ErrProjectConfigurationInvalid
			}
			seen := map[string]bool{}
			for _, key := range p.Services {
				s, ok := c.Services[key]
				if !ok || s.Publisher == "local" || seen[key] {
					return ErrProjectConfigurationInvalid
				}
				seen[key] = true
			}
			slices.Sort(p.Services)
			c.Workloads[name] = p
			continue
		}
		g := p.GitHub
		if g == nil {
			return ErrWorkloadBinding
		}
		prefix := g.Repository + "/"
		workflow, suffix, ok := strings.Cut(strings.TrimPrefix(g.WorkflowRef, prefix), "@")
		if !strings.HasPrefix(g.WorkflowRef, prefix) || !ok || suffix != g.Ref || !appliedNumericID.MatchString(g.RepositoryID) || !appliedNumericID.MatchString(g.RepositoryOwnerID) {
			return ErrWorkloadBinding
		}
		services := map[string]config.Service{}
		for key, s := range c.Services {
			if s.Publisher != "local" {
				services[key] = config.Service{Publisher: new(s.Publisher)}
			}
		}
		policy := config.Workload{Provider: "github", GitHub: &config.WorkloadGitHub{Repository: &g.Repository, Workflow: workflow, Ref: g.Ref, Events: g.Events}, Services: p.Services}
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
		if err := config.ValidateWorkloads(config.TNL{Services: services, Workloads: map[string]config.Workload{name: policy}}); err != nil {
			return errors.Join(ErrProjectConfigurationInvalid, err)
		}
		slices.Sort(p.Services)
		slices.Sort(p.GitHub.Events)
		p.Trust = oidcauth.WorkloadTrust{Provider: "github", Issuer: oidcauth.GitHubIssuer, JWKSURL: oidcauth.GitHubIssuer + "/.well-known/jwks", Claims: map[string]string{}}
		c.Workloads[name] = p
	}
	return nil
}

// apply and exchange take the same team mutation lock. narrowing deletes rights,
// never adds rights to an already issued execution session.
func reconcileWorkloadPolicies(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, c ProjectConfiguration) error {
	rows, err := tx.Query(ctx, `SELECT id,workload_name,claims FROM control.workload_sessions WHERE team_id=$1 AND project_key=$2 AND revoked_at IS NULL FOR UPDATE`, r.TeamID, r.ProjectKey)
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
		p, found := c.Workloads[s.name]
		var claims oidcauth.WorkloadExecution
		if err = json.Unmarshal(s.claims, &claims); err != nil {
			return err
		}
		if !found || !p.matches(claims) {
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

func (p ProjectWorkload) matches(c oidcauth.WorkloadExecution) bool {
	if p.Provider != c.Provider {
		return false
	}
	if p.Provider == "github" {
		return p.GitHub != nil && c.GitHub != nil && p.GitHub.matches(*c.GitHub)
	}
	return c.Matches(p.Trust)
}

func (p ProjectWorkload) validateTrust() error {
	t := p.Trust
	if t.Provider != p.Provider || !config.WorkloadHTTPS(t.Issuer) || !config.WorkloadHTTPS(t.JWKSURL) || !config.ExactWorkloadValue(t.Audience) || len(t.Claims) == 0 || len(t.Claims) > 32 {
		return ErrProjectConfigurationInvalid
	}
	for k, v := range t.Claims {
		if !config.ExactWorkloadValue(k) || !config.ExactWorkloadValue(v) {
			return ErrProjectConfigurationInvalid
		}
	}
	require := func(keys ...string) bool {
		for _, k := range keys {
			if t.Claims[k] == "" {
				return false
			}
		}
		return true
	}
	switch p.Provider {
	case "vercel":
		if !naming.ValidAuthorityLabel(t.Claims["owner"]) {
			return ErrProjectConfigurationInvalid
		}
		for k := range t.Claims {
			if !slices.Contains([]string{"owner", "owner_id", "project_id", "environment", "sub"}, k) {
				return ErrProjectConfigurationInvalid
			}
		}
		if !require("owner", "owner_id", "project_id", "environment") || !strings.HasPrefix(t.Claims["owner_id"], "team_") || !strings.HasPrefix(t.Claims["project_id"], "prj_") || t.Issuer != "https://oidc.vercel.com" && t.Issuer != "https://oidc.vercel.com/"+t.Claims["owner"] || t.JWKSURL != t.Issuer+"/.well-known/jwks" || t.Audience != "https://vercel.com/"+t.Claims["owner"] {
			return ErrProjectConfigurationInvalid
		}
	case "fly":
		if !naming.ValidAuthorityLabel(t.Claims["org_name"]) || !naming.ValidAuthorityLabel(t.Claims["app_name"]) {
			return ErrProjectConfigurationInvalid
		}
		for k := range t.Claims {
			if !slices.Contains([]string{"org_name", "org_id", "app_name", "app_id", "machine_id", "sub"}, k) {
				return ErrProjectConfigurationInvalid
			}
		}
		if !require("org_name", "org_id", "app_name", "app_id") || t.Issuer != "https://oidc.fly.io/"+t.Claims["org_name"] || t.JWKSURL != t.Issuer+"/.well-known/jwks" || t.Audience != "https://fly.io/"+t.Claims["org_name"] {
			return ErrProjectConfigurationInvalid
		}
	case "oidc":
		for k := range t.Claims {
			if slices.Contains([]string{"iss", "aud", "iat", "nbf", "exp"}, k) {
				return ErrProjectConfigurationInvalid
			}
		}
	default:
		return ErrProjectConfigurationInvalid
	}
	return nil
}

// policy lookup returns only the selected trust policy; JWT input cannot choose endpoints.
func (d *Database) WorkloadPolicy(ctx context.Context, team, project, name, source string) (ProjectWorkload, error) {
	team, err := d.workloadTeam(ctx, team)
	if err != nil {
		return ProjectWorkload{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return ProjectWorkload{}, err
	}
	defer tx.Rollback(ctx)
	row, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return ProjectWorkload{}, publisherLookupError(err, ErrWorkloadDenied)
	}
	if row.SourceFingerprint != source {
		return ProjectWorkload{}, ErrWorkloadDenied
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return ProjectWorkload{}, err
	}
	p, ok := c.Workloads[name]
	if !ok {
		return p, ErrWorkloadDenied
	}
	return p, nil
}

func (d *Database) workloadTeam(ctx context.Context, selector string) (string, error) {
	var id string
	err := d.pool.QueryRow(ctx, `SELECT id FROM control.teams WHERE (id=$1 OR display_name=$1) AND deleted_at IS NULL`, selector).Scan(&id)
	return id, publisherLookupError(err, ErrWorkloadDenied)
}
