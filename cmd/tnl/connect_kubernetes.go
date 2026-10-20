package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/kubeconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type kubeCredentialCommand struct {
	Profile string `name:"profile" required:"" type:"path"`
}

// this hidden exec entry point writes only the Kubernetes wire credential on
// stdout. the selected kubeconfig pins this installation's absolute executable.
func runKubeCredential(ctx context.Context, flags kubeCredentialCommand, output io.Writer) error {
	profile, err := kubeconfig.ReadProfile(flags.Profile)
	if err != nil {
		return err
	}
	var issue kubeconfig.IssueCertificate
	if profile.Public && profile.Certificate == nil {
		issue = func(ctx context.Context) (kubeconfig.CertificateFiles, error) {
			session, err := openTeamSession(ctx, remoteFlags{ServerURL: profile.Owner.ControlURL, StateDir: profile.StateDir}, "tnl connect", io.Discard)
			if err != nil {
				return kubeconfig.CertificateFiles{}, err
			}
			defer session.Close()
			if profile.IdentityID == "" || profile.IdentityID != session.identity.Identity.Id {
				return kubeconfig.CertificateFiles{}, kubeconfig.ErrCredential
			}
			material, err := ensureConnectCertificate(ctx, session, profile.Owner.ServiceID)
			return kubeconfig.CertificateFiles{CertificateFile: material.CertificateFile, KeyFile: material.KeyFile}, err
		}
	}
	credential, err := kubeconfig.Credential(ctx, profile, issue)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(credential)
}

func prepareKubernetesConnection(ctx context.Context, session *teamSession, flags connectStartCommand, service controlv1.PrivateService, profile *nativeConnectionProfile, listen string) error {
	key, err := configuredConnectService(flags.project, flags.Name)
	if err != nil {
		return err
	}
	sourceID, projectLabel, serviceLabel := service.Id, "services", service.Name
	if key != "" {
		source, err := flags.project.SourceIdentity(ctx)
		if err != nil {
			return err
		}
		sourceID = source.Fingerprint
		projectLabel, serviceLabel = flags.project.Worktree.Label.Project, key
	}
	source := kubeconfig.Source{ConfigFile: flags.KubeUserConfig, ExistingUser: flags.KubeUser, TokenFile: flags.KubeTokenFile}
	if source.ConfigFile != "" {
		source.ConfigFile, err = filepath.Abs(source.ConfigFile)
		if err != nil {
			return err
		}
	}
	if source.TokenFile != "" {
		source.TokenFile, err = filepath.Abs(source.TokenFile)
		if err != nil {
			return err
		}
	}
	if source.ConfigFile == "" && source.ExistingUser == "" && source.TokenFile == "" && service.KubernetesAuth != nil {
		hint := service.KubernetesAuth
		if hint.Provider != controlv1.KubernetesEKS {
			return kubeconfig.ErrCredential
		}
		source.EKS = &kubeconfig.EKS{Cluster: hint.Cluster, Region: hint.Region}
	}
	if source.EKS == nil && source.ExistingUser == "" && source.TokenFile == "" {
		return publisherCLIError("kubernetes requires --kube-token-file or both --kube-user-config and --kube-user")
	}
	if err := source.Validate(); err != nil {
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
	prepared, err := kubeconfig.PrepareConnection(ctx, plan, kubeconfig.Options{Owner: owner, ProjectLabel: projectLabel, Service: serviceLabel, Namespace: flags.Namespace, Server: server, TLSServerName: profile.Hostname, Helper: helper}, kubeconfig.Profile{Owner: owner, StateDir: session.database.Root(), IdentityID: session.identity.Identity.Id, Public: profile.Public, Source: source})
	if err != nil {
		return err
	}
	profile.Kubeconfig, profile.Namespace = &prepared, prepared.Namespace
	profile.Command = []string{"kubectl", "--kubeconfig", prepared.File, "--context", prepared.Context, "get", "namespaces"}
	return nil
}
