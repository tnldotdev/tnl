package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

// workload declares provider identity constraints and exact service rights.
type Workload struct {
	Provider    string            `json:"provider" yaml:"provider" jsonschema:"required,enum=github,enum=vercel,enum=fly,enum=oidc"`
	GitHub      *WorkloadGitHub   `json:"github,omitempty" yaml:"github,omitempty"`
	TeamID      string            `json:"team_id,omitempty" yaml:"team_id,omitempty"`
	ProjectID   string            `json:"project_id,omitempty" yaml:"project_id,omitempty"`
	Environment string            `json:"environment,omitempty" yaml:"environment,omitempty"`
	TeamSlug    string            `json:"team_slug,omitempty" yaml:"team_slug,omitempty"`
	IssuerMode  string            `json:"issuer_mode,omitempty" yaml:"issuer_mode,omitempty" jsonschema:"enum=team,enum=global"`
	Org         string            `json:"org,omitempty" yaml:"org,omitempty"`
	OrgID       string            `json:"org_id,omitempty" yaml:"org_id,omitempty"`
	App         string            `json:"app,omitempty" yaml:"app,omitempty"`
	AppID       string            `json:"app_id,omitempty" yaml:"app_id,omitempty"`
	MachineID   string            `json:"machine_id,omitempty" yaml:"machine_id,omitempty"`
	Issuer      string            `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	JWKSURL     string            `json:"jwks_url,omitempty" yaml:"jwks_url,omitempty"`
	Audience    string            `json:"audience,omitempty" yaml:"audience,omitempty"`
	Claims      map[string]string `json:"claims,omitempty" yaml:"claims,omitempty"`
	TokenFile   string            `json:"token_file,omitempty" yaml:"token_file,omitempty"`
	Services    []string          `json:"services" yaml:"services" jsonschema:"required,minItems=1,maxItems=32,uniqueItems=true"`
	MaxDuration *Duration         `json:"max_duration,omitempty" yaml:"max_duration,omitempty" jsonschema_description:"Fixed session window; defaults to 1h and must be positive and at most 6h."`
}

type WorkloadGitHub struct {
	Repository       *string  `json:"repository,omitempty" yaml:"repository,omitempty"`
	Workflow         string   `json:"workflow" yaml:"workflow"`
	Environment      *string  `json:"environment,omitempty" yaml:"environment,omitempty"`
	Ref              string   `json:"ref" yaml:"ref"`
	Events           []string `json:"events" yaml:"events"`
	ReusableWorkflow *string  `json:"reusable_workflow,omitempty" yaml:"reusable_workflow,omitempty"`
}

const DefaultWorkloadMaxDuration = time.Hour
const MaxWorkloadMaxDuration = 6 * time.Hour

func (p Workload) DurationLimit() time.Duration {
	if p.MaxDuration == nil {
		return DefaultWorkloadMaxDuration
	}
	return p.MaxDuration.Value()
}

var githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var WorkloadEvents = []string{"push", "pull_request", "pull_request_target", "workflow_dispatch", "workflow_call", "schedule", "release", "merge_group", "repository_dispatch", "workflow_run"}

func ExactWorkloadValue(s string) bool {
	return s != "" && len(s) <= 1024 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "*?[]\x00\r\n\t")
}
func WorkloadHTTPS(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
}

func ValidateWorkloads(c TNL) error {
	if len(c.Workloads) > 32 {
		return errors.New("workloads may contain at most 32 policies")
	}
	for name, p := range c.Workloads {
		if !naming.ValidServiceName(name) {
			return errors.New("workload name must be a lowercase DNS label")
		}
		bad := func() error { return fmt.Errorf("workloads.%s must declare exact constraints for its provider", name) }
		g := p.GitHub
		switch p.Provider {
		case "github":
			if g == nil {
				return bad()
			}
			if g.Repository != nil && !githubRepository.MatchString(*g.Repository) {
				return bad()
			}
			if !strings.HasPrefix(g.Workflow, ".github/workflows/") || validateProjectRelativeFile(g.Workflow) != nil || !ExactWorkloadValue(g.Workflow) || !(strings.HasSuffix(g.Workflow, ".yml") || strings.HasSuffix(g.Workflow, ".yaml")) || strings.Contains(strings.TrimPrefix(g.Workflow, ".github/workflows/"), "/") {
				return bad()
			}
			if !(strings.HasPrefix(g.Ref, "refs/heads/") || strings.HasPrefix(g.Ref, "refs/tags/")) || !ExactWorkloadValue(g.Ref) || strings.ContainsAny(g.Ref, "\\ ") || strings.HasSuffix(g.Ref, "/") || strings.Contains(g.Ref, "..") {
				return bad()
			}
			if g.Environment != nil && !ExactWorkloadValue(*g.Environment) {
				return bad()
			}
			if g.ReusableWorkflow != nil {
				w, r, ok := strings.Cut(*g.ReusableWorkflow, "@")
				parts := strings.Split(w, "/")
				if !ok || r == "" || len(parts) != 5 || !githubRepository.MatchString(strings.Join(parts[:min(2, len(parts))], "/")) || parts[2] != ".github" || parts[3] != "workflows" || !ExactWorkloadValue(*g.ReusableWorkflow) || strings.ContainsAny(*g.ReusableWorkflow, " \\") || !(strings.HasSuffix(w, ".yml") || strings.HasSuffix(w, ".yaml")) || validateProjectRelativeFile(w) != nil {
					return bad()
				}
			}
			if len(g.Events) == 0 || len(g.Events) > len(WorkloadEvents) {
				return bad()
			}
			seen := map[string]bool{}
			for _, e := range g.Events {
				if !slices.Contains(WorkloadEvents, e) || seen[e] {
					return bad()
				}
				seen[e] = true
			}
		case "vercel":
			if !strings.HasPrefix(p.TeamID, "team_") || !ExactWorkloadValue(p.TeamID) || !strings.HasPrefix(p.ProjectID, "prj_") || !ExactWorkloadValue(p.ProjectID) || !ExactWorkloadValue(p.Environment) {
				return bad()
			}
			if p.TeamSlug != "" && !naming.ValidAuthorityLabel(p.TeamSlug) || p.IssuerMode != "" && p.IssuerMode != "team" && p.IssuerMode != "global" {
				return bad()
			}
		case "fly":
			if !naming.ValidAuthorityLabel(p.Org) || !naming.ValidAuthorityLabel(p.App) || !ExactWorkloadValue(p.OrgID) || !ExactWorkloadValue(p.AppID) || p.MachineID != "" && !ExactWorkloadValue(p.MachineID) {
				return bad()
			}
		case "oidc":
			if !WorkloadHTTPS(p.Issuer) || !WorkloadHTTPS(p.JWKSURL) || !ExactWorkloadValue(p.Audience) || len(p.Claims) == 0 || len(p.Claims) > 32 {
				return bad()
			}
			for k, v := range p.Claims {
				if !ExactWorkloadValue(k) || !ExactWorkloadValue(v) || slices.Contains([]string{"iss", "aud", "iat", "exp", "nbf"}, k) {
					return bad()
				}
			}
		default:
			return bad()
		}
		// reject mixed provider policies rather than silently ignoring constraints.
		if p.Provider != "github" && g != nil {
			return bad()
		}
		if p.Provider != "vercel" && (p.TeamID != "" || p.ProjectID != "" || p.TeamSlug != "" || p.IssuerMode != "" || p.Environment != "") {
			return bad()
		}
		if p.Provider != "fly" && (p.Org != "" || p.OrgID != "" || p.App != "" || p.AppID != "" || p.MachineID != "") {
			return bad()
		}
		if p.Provider != "oidc" && (p.Issuer != "" || p.JWKSURL != "" || p.Audience != "" || len(p.Claims) > 0 || p.TokenFile != "") {
			return bad()
		}
		if len(p.Services) == 0 || len(p.Services) > 32 {
			return bad()
		}
		seen := map[string]bool{}
		for _, s := range p.Services {
			if _, ok := c.Services[s]; !ok || seen[s] {
				return bad()
			}
			seen[s] = true
		}
		if d := p.DurationLimit(); d < time.Second || d > MaxWorkloadMaxDuration || d%time.Second != 0 {
			return bad()
		}
	}
	return nil
}
