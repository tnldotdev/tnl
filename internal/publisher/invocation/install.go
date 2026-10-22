package invocation

import (
	"context"

	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	localproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	publisherprovision "github.com/tnldotdev/tnl/internal/publisher/setup"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type InstallationOptions struct {
	PublicOptions
	Installation  publisherjob.ServiceOptions
	ServiceName   string
	ReadinessPath string
	ServerCAFile  string
}

func InstallHTTP(ctx context.Context, flags InstallationOptions, presentation publisherprovision.Presentation) error {
	address, err := target.NormalizePublicAddress(flags.Target, controlv1.Http)
	if err != nil {
		return err
	}
	options, err := localproxy.TargetOptionsForCA(flags.TargetCAFile, flags.ProjectRoot)
	if err != nil {
		return err
	}
	options.ServerName = flags.TargetTLSName
	if err := localproxy.PreflightWithOptions(ctx, address, options); err != nil {
		return err
	}
	server, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer database.Close()
	authenticated, err := flags.Authenticate(ctx, database, server, flags.AccessToken)
	if err != nil {
		return err
	}
	team := flags.SelectedTeam
	if team == "" {
		team = flags.Team
	}
	services, err := preparePublisherServices(ctx, database, server, flags.PublicURL, flags.Name, flags.Domain, team, false, authenticated)
	if err != nil {
		return err
	}
	policy, err := resolveVisitorAccess(ctx, authenticated.Control, flags.Access, flags.Anonymous, flags.IP)
	if err != nil {
		return err
	}
	cfg := services.config(address, policy.prefixes, flags.Limits)
	if policy.explicit {
		cfg.AccessMode = policy.access
	}
	route, err := reserveConfiguredURL(ctx, services, cfg)
	if err != nil {
		return err
	}
	name := flags.ServiceName
	if name == "" {
		name = flags.Name
	}
	job := publisherjob.Job{Name: name, Target: address, TargetTLSName: flags.TargetTLSName, Limits: flags.Limits, ReadinessPath: flags.ReadinessPath}
	return publisherprovision.InstallPublication(ctx, publisherprovision.Publication{Database: database, Server: server, Route: route, Control: authenticated.Control, Options: flags.Installation, Job: job, TargetCAFile: flags.TargetCAFile, ServerCAFile: flags.ServerCAFile, ProjectRoot: flags.ProjectRoot}, presentation)
}
