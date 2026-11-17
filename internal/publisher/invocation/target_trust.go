package invocation

import (
	"context"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

func configuredTargetOptions(ctx context.Context, project clientproject.Project, service, address string) (publisherproxy.TargetOptions, error) {
	trust, err := project.CaptureServiceTrust(ctx, service, address)
	if err != nil || trust == nil {
		return publisherproxy.TargetOptions{}, err
	}
	tls, err := trust.Verifier()
	if err != nil {
		return publisherproxy.TargetOptions{}, err
	}
	return publisherproxy.TargetOptions{RootCAs: tls.RootCAs, ServerName: tls.ServerName}, nil
}
