package resolve

import (
	"context"
	"errors"
	"net"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentLookup interface {
	GetDeployment(ctx context.Context, team, project, selector string) (controlv1.Deployment, error)
}

// ApplyComparisonBase replaces targets in the last applied declaration with the
// selected deployment's saved targets. deployment management can edit them
// without changing the declaration or its project revision.
func ApplyComparisonBase(ctx context.Context, lookup deploymentLookup, team, project, selection string, saved controlv1.AppliedProjectConfiguration) (controlv1.AppliedProjectConfiguration, error) {
	if selection == "local" || saved.Deployments == nil {
		return saved, nil
	}
	for _, entry := range *saved.Deployments {
		if entry.Name != selection {
			continue
		}
		live, err := lookup.GetDeployment(ctx, team, project, entry.Id)
		if err != nil {
			return saved, err
		}
		if live.Id != entry.Id || live.TeamId != team || live.ProjectKey != project || live.Name != selection {
			return saved, invalidApplyTarget("control returned another deployment")
		}
		bindings, err := mergeApplyTargets(ctx, saved.Configuration.Services, live)
		if err != nil {
			return saved, err
		}
		saved.Configuration.Services = bindings
		break
	}
	return saved, nil
}

func mergeApplyTargets(ctx context.Context, saved map[string]controlv1.ProjectServiceConfiguration, live controlv1.Deployment) (map[string]controlv1.ProjectServiceConfiguration, error) {
	bindings := make(map[string]controlv1.ProjectServiceConfiguration, len(live.Targets))
	for name, target := range live.Targets {
		service, ok := live.Services[name]
		if !ok {
			return nil, invalidApplyTarget("control returned invalid deployment target facts")
		}
		binding, declared := saved[name]
		if !declared {
			binding.Name, binding.Protocol = new(name), new(service.Protocol)
		}
		binding.Target, binding.TargetDiscovery, binding.TargetTls = "", target.Discovery, nil
		if target.App != nil && *target.App {
			binding.Target = "app"
		} else if target.Address != nil {
			binding.Target = *target.Address
		}
		if tls := target.Tls; tls != nil {
			var hostname, ca string
			if tls.Hostname != nil {
				hostname = *tls.Hostname
			}
			if tls.Ca != nil {
				ca = *tls.Ca
			}
			address := binding.Target
			if address == "app" && hostname != "" {
				address = net.JoinHostPort(hostname, "443")
			}
			snapshot, err := targettrust.CapturePortable(ctx, string(service.Protocol), address, ca, hostname)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, invalidApplyTarget("control returned invalid deployment target trust")
			}
			trust, err := snapshot.Declaration()
			if err != nil {
				return nil, invalidApplyTarget("control returned invalid deployment target trust")
			}
			binding.TargetTls = &controlv1.ProjectTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest, HostnameFromTarget: trust.HostnameFromTarget}
			if len(trust.CAPEM) != 0 {
				binding.TargetTls.CaPem = new(string(trust.CAPEM))
			}
		}
		bindings[name] = binding
	}
	return bindings, nil
}

func invalidApplyTarget(message string) error {
	return failure.Wrap("read deployment targets", failure.ServerResponseInvalid, errors.New(message))
}
