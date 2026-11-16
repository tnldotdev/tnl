package invocation

import (
	"context"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func configuredTargetTrust(ctx context.Context, project clientproject.Project, service, address string) (*targettrust.Snapshot, error) {
	if service == "" {
		return nil, nil
	}
	declaration, err := project.CaptureTargetTrust(ctx, service, address)
	if err != nil || declaration == nil {
		return nil, err
	}
	return declaration.Snapshot()
}

func configuredTargetOptions(ctx context.Context, project clientproject.Project, service, address string) (publisherproxy.TargetOptions, error) {
	trust, err := configuredTargetTrust(ctx, project, service, address)
	if err != nil || trust == nil {
		return publisherproxy.TargetOptions{}, err
	}
	tls, err := trust.Verifier()
	if err != nil {
		return publisherproxy.TargetOptions{}, err
	}
	return publisherproxy.TargetOptions{RootCAs: tls.RootCAs, ServerName: tls.ServerName}, nil
}

func publicTargetOptions(ctx context.Context, flags PublicOptions, address string) (publisherproxy.TargetOptions, error) {
	if flags.Service != "" {
		return configuredTargetOptions(ctx, flags.Project, flags.Service, address)
	}
	options, err := publisherproxy.TargetOptionsForCA(flags.TargetCAFile, flags.ProjectRoot)
	options.ServerName = flags.TargetTLSName
	return options, err
}
