package connector

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector/kubeconfig"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this hidden exec entry point writes only the Kubernetes wire credential on
// stdout. the selected kubeconfig pins this installation's absolute executable.
func WriteKubeCredential(ctx context.Context, path string, output io.Writer) error {
	profile, err := kubeconfig.ReadProfile(path)
	if err != nil {
		return err
	}
	credential, err := kubeconfig.Credential(ctx, profile, nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(credential)
}

func prepareKubernetesConnection(ctx context.Context, session *Session, flags StartOptions, service controlv1.Service, profile *Profile, listen string) error {
	key, err := ConfiguredService(flags.project.Project, flags.Name)
	if err != nil {
		return err
	}
	sourceID, projectLabel, serviceLabel := service.Id, "services", service.Name
	if key != "" {
		if config.PublisherGroupName(flags.project.Config.Services[key]) == "local" {
			sourceID = flags.project.LocalPublicationIdentity().Fingerprint
		} else {
			source, err := flags.project.SourceIdentity(ctx)
			if err != nil {
				return err
			}
			sourceID = source.Fingerprint
		}
		projectLabel, serviceLabel = flags.project.Worktree.Label.Project, key
	}
	if flags.KubeUser == "" && flags.KubeTokenFile == "" && (flags.KubeUserConfig != "" || service.KubernetesAuth == nil) {
		return publisherCLIError("kubernetes requires --kube-token-file or both --kube-user-config and --kube-user")
	}
	source, err := kubeconfig.ResolveSource(kubeconfig.Source{ConfigFile: flags.KubeUserConfig, ExistingUser: flags.KubeUser, TokenFile: flags.KubeTokenFile}, service.KubernetesAuth)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := os.Getenv("KUBECONFIG")
	if flags.Kubeconfig != "" {
		path = flags.Kubeconfig
	}
	plan, err := kubeconfig.PlanLocal(home, path)
	if err != nil {
		return err
	}
	helper, err := os.Executable()
	if err != nil {
		return err
	}
	helper, err = filepath.EvalSymlinks(helper)
	if err != nil {
		return err
	}
	owner := kubeconfig.Owner{ControlURL: session.authenticated.ServerEndpoint, TeamID: service.TeamId, SourceID: sourceID, ServiceID: service.Id}
	server := profile.URL
	if listen != "" {
		server = "https://" + listen
	}
	prepared, err := kubeconfig.PrepareConnection(ctx, plan, kubeconfig.Options{Owner: owner, ProjectLabel: projectLabel, Service: serviceLabel, Namespace: flags.Namespace, Server: server, TLSServerName: profile.Hostname, Helper: helper}, kubeconfig.Profile{Owner: owner, StateDir: session.database.Root(), IdentityID: session.identity.Identity.Id, Source: source})
	if err != nil {
		return err
	}
	profile.Kubeconfig, profile.Namespace = &prepared, prepared.Namespace
	profile.Command = []string{"kubectl", "--kubeconfig", prepared.File, "--context", prepared.Context, "get", "namespaces"}
	return nil
}
