package target

import (
	"errors"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func NormalizePrivateAddress(address string, protocol controlv1.PrivateServiceProtocol) (string, error) {
	if protocol == "http" {
		return config.NormalizeHTTPServiceTarget(config.Service{}, address)
	}
	canonical, err := tcptarget.Normalize(address)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return canonical, nil
}

func NormalizePublicAddress(address string, protocol controlv1.PublicURLServiceProtocol) (string, error) {
	if protocol == controlv1.Http {
		return targetsyntax.NormalizeTarget(address)
	}
	canonical, err := tcptarget.Normalize(address)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return canonical, nil
}

func EnrolledAddress(route controlv1.PublicURL, selected string) (string, error) {
	if route.ServiceProtocol != controlv1.Http {
		if route.Target != "" {
			return "", failure.Wrap("read enrolled URL target", failure.ServerResponseInvalid, errors.New("control returned a private TCP target"))
		}
		return NormalizePublicAddress(selected, route.ServiceProtocol)
	}
	if selected == "" {
		selected = route.Target
	}
	address, err := NormalizePublicAddress(selected, controlv1.Http)
	if err != nil {
		return "", err
	}
	if route.Target != "" && route.Target != address {
		return "", failure.Wrap("select enrolled target", failure.PublisherGrantMismatch, errors.New("HTTP target differs from saved URL"))
	}
	return address, nil
}
