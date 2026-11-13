package state

import (
	"context"
	"strings"

	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

type DeploymentTarget struct {
	Address string               `json:"address"`
	TLS     *DeploymentTargetTLS `json:"tls,omitempty"`
}

type DeploymentTargetTLS struct {
	CA       string `json:"ca,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// reads preserve publisher-side discovery for deployments declared by apply;
// runtime writes still accept only the narrower explicit-address input above.
type DeploymentTargetStatus struct {
	App       bool                    `json:"app,omitempty"`
	Address   string                  `json:"address,omitempty"`
	TLS       *DeploymentTargetTLS    `json:"tls,omitempty"`
	Discovery *ProjectTargetDiscovery `json:"discovery,omitempty"`
}

// runtime input is an address and portable trust, never a file, bundle URL,
// discovery instruction, declaration, visitor policy, or caller-supplied digest.
func normalizeDeploymentTarget(ctx context.Context, name, protocol, group string, input DeploymentTarget) (ProjectServiceConfiguration, error) {
	s := ProjectServiceConfiguration{Name: name, Protocol: protocol, PublisherGroup: group}
	if len(input.Address) > 8192 {
		return s, ErrProjectConfigurationInvalid
	}
	address, err := normalizeAppliedPrivateAddress(input.Address, protocol)
	if err != nil {
		return s, err
	}
	s.Target = address
	tls := input.TLS
	if protocol == "http" && strings.HasPrefix(input.Address, "https://") && tls == nil {
		tls = &DeploymentTargetTLS{}
	}
	if protocol == "http" && strings.HasPrefix(input.Address, "http://") && tls != nil {
		return s, ErrProjectConfigurationInvalid
	}
	if tls != nil {
		snapshot, err := targettrust.CapturePortable(ctx, protocol, address, tls.CA, tls.Hostname)
		if err != nil {
			return s, ErrProjectConfigurationInvalid
		}
		declaration, err := snapshot.Declaration()
		if err != nil {
			return s, ErrProjectConfigurationInvalid
		}
		s.TargetTLS = &ProjectTargetTLS{Hostname: declaration.Hostname, CAPEM: string(declaration.CAPEM), Digest: declaration.Digest}
	}
	if err = normalizeAppliedProjectService(&s); err != nil {
		return s, err
	}
	return s, nil
}

func deploymentTarget(s ProjectServiceConfiguration) DeploymentTargetStatus {
	result := DeploymentTargetStatus{Address: s.Target, Discovery: s.TargetDiscovery}
	if s.Target == "app" {
		result.Address, result.App = "", true
	}
	if s.TargetTLS != nil {
		ca := s.TargetTLS.CAPEM
		if ca == "" {
			ca = "system"
		}
		result.TLS = &DeploymentTargetTLS{Hostname: s.TargetTLS.Hostname, CA: ca}
	}
	return result
}
