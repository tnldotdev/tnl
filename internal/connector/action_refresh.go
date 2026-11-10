package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/tnldotdev/tnl/internal/client/identity/workload"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
)

// validateGitHubActionsRefresh binds an explicit action-owned runtime source to
// the same selected policy and audience as the initial assertion. the source is
// not a manifest field, an SDK environment or permission to replace a session.
func validateGitHubActionsRefresh(options OwnerStartOptions, project projectConfiguration, request connectorruntime.StartRequest) error {
	source := request.GitHubActionsRefresh
	if source == nil {
		return nil
	}
	scope := request.Context
	if scope.Workload == "" || request.Assertion == "" || request.Refresh != nil || options.ParentPID != 0 || options.SDKRegistry != "" || source.Audience != scope.Audience || workload.ValidateGitHubActionsSource(source.Getenv) != nil {
		return connectorruntime.ErrInvalid
	}
	if options.Manifest != "" {
		manifest, err := workloadmanifest.Read(options.Manifest)
		if err != nil {
			return err
		}
		data, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		policy, ok := manifest.Workloads[scope.Workload]
		if !ok || hex.EncodeToString(digest[:]) != scope.ConfigDigest || policy.Provider != "github" || policy.Acquisition.Method != "github-actions" || policy.Acquisition.Audience != scope.Audience {
			return connectorruntime.ErrInvalid
		}
	} else {
		policy, ok := project.Config.Workloads[scope.Workload]
		if !ok || policy.Provider() != "github" || policy.Token != nil {
			return connectorruntime.ErrInvalid
		}
	}
	return nil
}
