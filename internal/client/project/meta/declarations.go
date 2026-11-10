package meta

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
)

const GeneratedDirectoryName = ".tnl/generated"
const DeclarationsName = "project.d.ts"

// Declarations derives types from the source contract, never runtime endpoints.
// typescript factories retain their full return type without running a checker
// against one checkout's evaluated result. static files have exact declared keys.
func Declarations(configuration config.TNL, configPath, outputDir string) ([]byte, error) {
	if configPath == "" {
		return nil, errors.New("project configuration is required for declarations")
	}
	var source string
	if strings.EqualFold(filepath.Ext(configPath), ".ts") {
		relative, err := filepath.Rel(outputDir, strings.TrimSuffix(configPath, filepath.Ext(configPath))+".js")
		if err != nil {
			return nil, err
		}
		relative = filepath.ToSlash(relative)
		if !strings.HasPrefix(relative, ".") {
			relative = "./" + relative
		}
		source = "import(" + typeScriptString(relative) + ").default"
		source = "typeof " + source
	} else {
		// use the normalized static shape and shared key mappings. no target
		// values are emitted: only fields that influence the public type shape.
		shape := map[string]any{}
		services := map[string]any{}
		for name, service := range configuration.Services {
			value := map[string]any{"protocol": config.Protocol(service)}
			if paths := config.ServicePaths(service); len(paths) != 0 {
				mounts := map[string]any{}
				for prefix, mount := range paths {
					mounts[prefix] = map[string]any{"service": mount.Service, "stripPrefix": mount.StripPrefix}
				}
				value["http"] = map[string]any{"paths": mounts}
			}
			services[name] = value
		}
		shape["services"] = services
		publishers := map[string]any{}
		for name := range configuration.PublisherGroups {
			publishers[name] = map[string]any{}
		}
		shape["publisherGroups"] = publishers
		policies := map[string]any{}
		for name, policy := range configuration.Workloads {
			grants := map[string]any{}
			resources := func(selected []config.WorkloadResource) []map[string]string {
				result := make([]map[string]string, 0, len(selected))
				for _, resource := range selected {
					if resource.Service != nil {
						result = append(result, map[string]string{"service": *resource.Service})
					} else if resource.PublicURL != nil {
						result = append(result, map[string]string{"publicURL": *resource.PublicURL})
					}
				}
				return result
			}
			if len(policy.Grants.Visit) != 0 {
				grants["visit"] = resources(policy.Grants.Visit)
			}
			if len(policy.Grants.Publish) != 0 {
				grants["publish"] = resources(policy.Grants.Publish)
			}
			if len(policy.Grants.Allocate) != 0 {
				grants["allocate"] = policy.Grants.Allocate
			}
			value := map[string]any{"grants": grants}
			if policy.Ownership != "" {
				value["ownership"] = policy.Ownership
			}
			if g := policy.GitLab; g != nil {
				block := map[string]any{}
				if g.Project != "" {
					block["project"] = g.Project
				}
				if g.Server != "" {
					block["server"] = g.Server
				}
				if g.Branch != nil {
					block["branch"] = *g.Branch
				}
				if g.Tag != nil {
					block["tag"] = *g.Tag
				}
				if g.PipelineSource != "" {
					block["pipelineSource"] = g.PipelineSource
				}
				if g.Environment != "" {
					block["environment"] = g.Environment
				}
				if g.Audience != "" {
					block["audience"] = g.Audience
				}
				value["gitlab"] = block
			}
			if k := policy.Kubernetes; k != nil {
				block := map[string]any{"serviceAccount": k.ServiceAccount}
				if k.Context != "" {
					block["context"] = k.Context
				}
				if k.Namespace != "" {
					block["namespace"] = k.Namespace
				}
				if k.Audience != "" {
					block["audience"] = k.Audience
				}
				value["kubernetes"] = block
			}
			if g := policy.Google; g != nil {
				block := map[string]any{"serviceAccount": g.ServiceAccount}
				if g.Audience != "" {
					block["audience"] = g.Audience
				}
				value["google"] = block
			}
			if policy.GitHub != nil {
				github := map[string]any{"workflow": policy.GitHub.Workflow}
				if policy.GitHub.Branch != nil {
					github["branch"] = *policy.GitHub.Branch
				}
				if policy.GitHub.Tag != nil {
					github["tag"] = *policy.GitHub.Tag
				}
				if policy.GitHub.Events != nil {
					github["events"] = policy.GitHub.Events
				}
				if policy.GitHub.Repository != nil {
					github["repository"] = *policy.GitHub.Repository
				}
				if policy.GitHub.Environment != nil {
					github["environment"] = *policy.GitHub.Environment
				}
				if policy.GitHub.ReusableWorkflow != nil {
					github["reusableWorkflow"] = *policy.GitHub.ReusableWorkflow
				}
				value["github"] = github
			}
			if v := policy.Vercel; v != nil {
				block := map[string]any{"environment": v.Environment}
				if v.Project != "" {
					block["project"] = v.Project
				}
				if v.Team != "" {
					block["team"] = v.Team
				}
				value["vercel"] = block
			}
			if f := policy.Fly; f != nil {
				block := map[string]any{}
				if f.App != "" {
					block["app"] = f.App
				}
				if f.Org != "" {
					block["org"] = f.Org
				}
				if f.MachineID != "" {
					block["machineId"] = f.MachineID
				}
				value["fly"] = block
			}
			if o := policy.OIDC; o != nil {
				block := map[string]any{"issuer": o.Issuer, "claims": o.Claims}
				if o.Audience != "" {
					block["audience"] = o.Audience
				}
				if o.JWKSURL != "" {
					block["jwksUrl"] = o.JWKSURL
				}
				value["oidc"] = block
			}
			if t := policy.Token; t != nil {
				block := map[string]any{}
				if t.File != nil {
					block["file"] = *t.File
				}
				if t.Env != nil {
					block["env"] = *t.Env
				}
				value["token"] = block
			}
			if policy.MaxDuration != nil {
				value["maxDuration"] = policy.MaxDuration.Value().String()
			}
			policies[name] = value
		}
		shape["workloads"] = policies
		aliases := map[string]any{}
		for name, alias := range configuration.Aliases {
			aliases[name] = map[string]any{"service": alias.Service}
		}
		shape["aliases"] = aliases
		webhooks := map[string]any{}
		for name, webhook := range configuration.Webhooks {
			methods := webhook.Methods
			if len(methods) == 0 {
				methods = []string{"POST"}
			}
			webhooks[name] = map[string]any{"service": webhook.Service, "path": webhook.Path, "methods": methods}
		}
		shape["webhooks"] = webhooks
		if configuration.OAuth {
			shape["oauth"] = true
		}
		data, err := json.MarshalIndent(shape, "  ", "  ")
		if err != nil {
			return nil, err
		}
		source = string(data)
	}
	return []byte("// generated by tnl generate; commit this file.\nimport type { TnlResolvedConfig, TnlStableServiceNames } from \"@tnldotdev/tnl\";\n\ntype ProjectConfig = " + source + ";\ntype RequireStableNames<Check extends true> = Check;\ntype DeclaredServiceNames = RequireStableNames<TnlStableServiceNames<TnlResolvedConfig<ProjectConfig>>>;\n\ndeclare module \"@tnldotdev/tnl\" {\n  interface TnlProjectConfig {\n    config: ProjectConfig;\n  }\n}\n"), nil
}

func typeScriptString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
