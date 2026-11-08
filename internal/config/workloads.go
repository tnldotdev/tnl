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
	GitHub      *WorkloadGitHub `json:"github,omitempty" yaml:"github,omitempty"`
	Vercel      *WorkloadVercel `json:"vercel,omitempty" yaml:"vercel,omitempty"`
	Fly         *WorkloadFly    `json:"fly,omitempty" yaml:"fly,omitempty"`
	OIDC        *WorkloadOIDC   `json:"oidc,omitempty" yaml:"oidc,omitempty"`
	Token       *WorkloadToken  `json:"token,omitempty" yaml:"token,omitempty"`
	Services    []string        `json:"services" yaml:"services" jsonschema:"required,minItems=1,maxItems=32,uniqueItems=true" jsonschema_description:"exact configured service keys assigned to named publisher groups; local services cannot be workload targets."`
	MaxDuration *Duration       `json:"max_duration,omitempty" yaml:"max_duration,omitempty" jsonschema_description:"Fixed session window; defaults to 1h and must be positive and at most 6h."`
}

type WorkloadGitHub struct {
	Repository       *string  `json:"repository,omitempty" yaml:"repository,omitempty"`
	Workflow         string   `json:"workflow" yaml:"workflow"`
	Environment      *string  `json:"environment,omitempty" yaml:"environment,omitempty"`
	Branch           *string  `json:"branch,omitempty" yaml:"branch,omitempty" jsonschema_description:"Exact branch; defaults to the repository default branch resolved during apply. Mutually exclusive with tag."`
	Tag              *string  `json:"tag,omitempty" yaml:"tag,omitempty" jsonschema_description:"Exact tag; mutually exclusive with branch."`
	Events           []string `json:"events,omitempty" yaml:"events,omitempty" jsonschema_description:"Allowed workflow events; defaults to push."`
	ReusableWorkflow *string  `json:"reusable_workflow,omitempty" yaml:"reusable_workflow,omitempty"`
}

type WorkloadVercel struct {
	Project     string `json:"project,omitempty" yaml:"project,omitempty" jsonschema_description:"Project name; defaults to the linked Vercel project."`
	Team        string `json:"team,omitempty" yaml:"team,omitempty" jsonschema_description:"Team slug; defaults to the linked project's owner."`
	Environment string `json:"environment" yaml:"environment" jsonschema:"required,enum=production,enum=preview,enum=development"`
}

type WorkloadFly struct {
	App       string `json:"app,omitempty" yaml:"app,omitempty" jsonschema_description:"Application name; defaults to fly.toml."`
	Org       string `json:"org,omitempty" yaml:"org,omitempty" jsonschema_description:"Organization slug; defaults to the application's owner."`
	MachineID string `json:"machine_id,omitempty" yaml:"machine_id,omitempty"`
}

type WorkloadOIDC struct {
	Issuer   string            `json:"issuer" yaml:"issuer" jsonschema:"required"`
	JWKSURL  string            `json:"jwks_url,omitempty" yaml:"jwks_url,omitempty" jsonschema_description:"Signing-key endpoint; defaults to issuer discovery during apply."`
	Audience string            `json:"audience,omitempty" yaml:"audience,omitempty" jsonschema_description:"Intended token recipient; defaults to the control URL."`
	Claims   map[string]string `json:"claims" yaml:"claims" jsonschema:"required,minProperties=1,maxProperties=32"`
}

type WorkloadToken struct {
	File *string `json:"file,omitempty" yaml:"file,omitempty"`
	Env  *string `json:"env,omitempty" yaml:"env,omitempty"`
}

// provider is derived from exactly one block, never from a second discriminator.
func (p Workload) Provider() string {
	provider, count := "", 0
	for _, candidate := range []struct {
		name string
		set  bool
	}{
		{"github", p.GitHub != nil}, {"vercel", p.Vercel != nil},
		{"fly", p.Fly != nil}, {"oidc", p.OIDC != nil},
	} {
		if candidate.set {
			provider, count = candidate.name, count+1
		}
	}
	if count != 1 {
		return ""
	}
	return provider
}

func (g WorkloadGitHub) ExecutionRef(defaultBranch string) string {
	if g.Tag != nil {
		return "refs/tags/" + *g.Tag
	}
	if g.Branch != nil {
		return "refs/heads/" + *g.Branch
	}
	if defaultBranch == "" {
		return ""
	}
	return "refs/heads/" + defaultBranch
}

func (g WorkloadGitHub) AllowedEvents() []string {
	if g.Events == nil {
		return []string{"push"}
	}
	return slices.Clone(g.Events)
}

func (p Workload) TokenAudience(server string) string {
	if p.OIDC != nil && p.OIDC.Audience != "" {
		return p.OIDC.Audience
	}
	return server
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
var workloadEnvironment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func ValidateWorkloadTokenEnv(name string) error {
	if !workloadEnvironment.MatchString(name) {
		return errors.New("workload token env must be an environment variable name")
	}
	return nil
}

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
		switch p.Provider() {
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
			if g.Branch != nil && g.Tag != nil {
				return bad()
			}
			if g.Branch != nil || g.Tag != nil {
				if ref := g.ExecutionRef(""); !ValidWorkloadRef(ref) {
					return bad()
				}
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
			events := g.AllowedEvents()
			if len(events) == 0 || len(events) > len(WorkloadEvents) {
				return bad()
			}
			seen := map[string]bool{}
			for _, e := range events {
				if !slices.Contains(WorkloadEvents, e) || seen[e] {
					return bad()
				}
				seen[e] = true
			}
		case "vercel":
			v := p.Vercel
			if v.Project != "" && !ValidVercelProjectName(v.Project) || v.Team != "" && !naming.ValidAuthorityLabel(v.Team) || !slices.Contains([]string{"production", "preview", "development"}, v.Environment) {
				return bad()
			}
		case "fly":
			f := p.Fly
			if f.Org != "" && !naming.ValidAuthorityLabel(f.Org) || f.App != "" && !naming.ValidAuthorityLabel(f.App) || f.MachineID != "" && !ExactWorkloadValue(f.MachineID) {
				return bad()
			}
		case "oidc":
			o := p.OIDC
			if !WorkloadHTTPS(o.Issuer) || o.JWKSURL != "" && !WorkloadHTTPS(o.JWKSURL) || o.Audience != "" && !ExactWorkloadValue(o.Audience) || len(o.Claims) == 0 || len(o.Claims) > 32 {
				return bad()
			}
			for k, v := range o.Claims {
				if !ExactWorkloadValue(k) || !ExactWorkloadValue(v) || slices.Contains([]string{"iss", "aud", "iat", "exp", "nbf"}, k) {
					return bad()
				}
			}
		default:
			return bad()
		}
		if t := p.Token; t != nil {
			if (t.File == nil) == (t.Env == nil) {
				return bad()
			}
			if t.File != nil && (*t.File == "" || len(*t.File) > 4096 || strings.ContainsAny(*t.File, "\x00\r\n")) {
				return bad()
			}
			if t.Env != nil && !workloadEnvironment.MatchString(*t.Env) {
				return bad()
			}
		}
		if len(p.Services) == 0 || len(p.Services) > 32 {
			return bad()
		}
		seen := map[string]bool{}
		for _, s := range p.Services {
			service, ok := c.Services[s]
			if !ok || seen[s] {
				return bad()
			}
			if PublisherGroupName(service) == "local" {
				return fmt.Errorf("workloads.%s: service %q must use a named publisher group", name, s)
			}
			seen[s] = true
		}
		if d := p.DurationLimit(); d < time.Second || d > MaxWorkloadMaxDuration || d%time.Second != 0 {
			return bad()
		}
	}
	return nil
}

func ValidWorkloadRef(ref string) bool {
	if len(ref) > 512 || strings.HasSuffix(ref, ".") {
		return false
	}
	prefix := "refs/heads/"
	if strings.HasPrefix(ref, "refs/tags/") {
		prefix = "refs/tags/"
	}
	if !strings.HasPrefix(ref, prefix) {
		return false
	}
	name := strings.TrimPrefix(ref, prefix)
	if !ExactWorkloadValue(name) || strings.ContainsAny(name, "\\ :~^") || strings.Contains(name, "@{") || strings.Contains(name, "..") || strings.Contains(name, "//") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
