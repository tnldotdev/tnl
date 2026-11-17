package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func connectionDeployment(options ContextOptions) (projectConfiguration, connectorruntime.Context, error) {
	r := options.Deployment
	credential, err := auth.ParseDeploymentCredential(r.Token)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	if credential.SelectProject(r.Project) != nil || options.Manifest != "" || options.Workload != "" ||
		r.Name == "local" || !(naming.ValidServiceName(r.Name) || opaqueid.Valid(r.Name, "dpl_")) || options.TeamID != "" && options.TeamID != credential.Approval.TeamId {
		return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
	}
	if credential.Approval.Permissions.Connect == nil {
		return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrUnauthorized
	}
	protocols := *credential.Approval.Permissions.Connect
	names := slices.Clone(r.Services)
	if len(names) == 0 {
		for name := range protocols {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	configuration := config.TNL{Deployment: r.Name, Services: config.Services{}}
	for i, name := range names {
		protocol, ok := protocols[name]
		if !ok || !naming.ValidServiceName(name) || !protocol.Valid() || i > 0 && names[i-1] == name {
			return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrUnauthorized
		}
		configuration.Services[name] = config.Service{Protocol: new(string(protocol))}
	}
	directory, err := filepath.Abs(options.Directory)
	if err == nil {
		directory, err = filepath.EvalSymlinks(directory)
	}
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	captured, err := credential.CaptureSigner()
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	encoded, err := json.Marshal([]any{credential.ControlURL, credential.Approval, captured.PublicKey(), names, r.Name})
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	digest := sha256.Sum256(encoded)
	id := hex.EncodeToString(digest[:])
	scope := connectorruntime.Context{Schema: 1, Directory: directory, ConfigDigest: id, Server: credential.ControlURL, Audience: credential.ControlURL, TeamID: credential.Approval.TeamId, ProjectKey: credential.Approval.ProjectKey, ProjectLabel: credential.Approval.ProjectKey, SourceID: id, WorktreeKey: "deployment", Deployment: r.Name, Services: names}
	scope.TeamName = credential.Team
	project := projectConfiguration{Project: clientproject.Project{Root: directory, Config: configuration, Deployment: r.Name}}
	return project, scope, scope.Validate()
}
