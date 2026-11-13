package invocation

import (
	"context"

	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/setup"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type InstallationOptions struct {
	PublicOptions
	Installation  installedjobs.ServiceOptions
	ServiceName   string
	ReadinessPath string
	ServerCAFile  string
}

func InstallHTTP(ctx context.Context, flags InstallationOptions, presentation setup.Presentation) error {
	address, err := target.NormalizePublicAddress(flags.Target, controlv1.Http)
	if err != nil {
		return err
	}
	options, err := publicTargetOptions(ctx, flags.PublicOptions, address)
	if err != nil {
		return err
	}
	if err := publisherproxy.PreflightWithOptions(ctx, address, options); err != nil {
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
	publicURL, err := reserveConfiguredURL(ctx, services, cfg)
	if err != nil {
		return err
	}
	name := flags.ServiceName
	if name == "" {
		name = flags.Name
	}
	job := installedjobs.Job{TelemetryDisabled: flags.TelemetryDisabled, Name: name, Target: address, TargetTLSName: flags.TargetTLSName, Limits: flags.Limits, ReadinessPath: flags.ReadinessPath}
	trust, err := configuredTargetTrust(ctx, flags.Project, flags.Service, address)
	if err != nil {
		return err
	}
	if trust != nil {
		job.TargetCAPEM, job.TargetTLSName = trust.PEM, trust.Hostname
	}
	job.PreferredRegions = flags.PreferredRegions
	return setup.InstallPublication(ctx, setup.Publication{Database: database, Server: server, Route: publicURL, Control: authenticated.Control, Options: flags.Installation, Job: job, TargetCAFile: flags.TargetCAFile, ServerCAFile: flags.ServerCAFile, ProjectRoot: flags.ProjectRoot}, presentation)
}
