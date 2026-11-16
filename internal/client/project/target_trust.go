package project

import (
	"context"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

// CaptureTargetTrust captures portable CA material and a verified hostname.
// the declaration never depends on a local file or a runtime bundle fetch.
func (p Project) CaptureTargetTrust(ctx context.Context, name, discovered string) (*targettrust.Declaration, error) {
	service := p.Config.Services[name]
	if service.Target != nil && service.Target.TLS != nil && !(config.TargetType(service) == "app" && discovered == "") {
		publication, err := p.ResolvePublish(name, discovered)
		if err != nil {
			return nil, err
		}
		discovered = string(*publication.Target)
	}
	trust, err := p.captureTrust(ctx, name, discovered)
	if err != nil {
		return nil, err
	}
	if trust == nil {
		return nil, nil
	}
	return trust.Declaration()
}
