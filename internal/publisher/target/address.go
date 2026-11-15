package target

import (
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func NormalizePrivateAddress(address string, protocol controlv1.ServiceProtocol) (string, error) {
	if protocol == "http" {
		return config.NormalizeHTTPServiceTarget(config.Service{}, address)
	}
	canonical, err := tcptarget.Normalize(address)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return canonical, nil
}
