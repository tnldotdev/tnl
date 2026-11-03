package project

import (
	"context"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

// CaptureTargetTrust reads the declared CA source at apply time. source paths
// and bundle URLs never enter the resulting declaration or remote worker.
func (p Project) CaptureTargetTrust(ctx context.Context, cache *targettrust.Cache, name, discovered string) (*targettrust.Declaration, error) {
	service := p.Config.Services[name]
	if service.Target != nil && service.Target.TLS != nil && !(config.TargetType(service) == "app" && discovered == "") {
		publication, err := p.ResolvePublish(name, discovered)
		if err != nil {
			return nil, err
		}
		discovered = string(*publication.Target)
	}
	trust, err := p.captureTrust(ctx, cache, name, discovered)
	if err != nil {
		return nil, err
	}
	if trust == nil {
		return nil, nil
	}
	return trust.Declaration()
}
