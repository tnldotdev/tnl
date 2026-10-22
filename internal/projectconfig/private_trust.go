package projectconfig

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/privatetrust"
)

// CaptureServiceTrust captures trust for a private service's resolved target.
// the caller compares it with control's approved metadata before mutations.
func (p Project) CaptureServiceTrust(ctx context.Context, cache *privatetrust.Cache, name, target string) (*privatetrust.Snapshot, error) {
	service, found := p.Config.Services[name]
	if !found || config.IsPublicService(service) {
		return nil, fmt.Errorf("service %q is not a configured private service", name)
	}
	return p.captureTrust(ctx, cache, name, target)
}

func (p Project) captureTrust(ctx context.Context, cache *privatetrust.Cache, name, target string) (*privatetrust.Snapshot, error) {
	if err := config.ValidateTNL(p.Config); err != nil {
		return nil, err
	}
	service, found := p.Config.Services[name]
	if !found {
		return nil, fmt.Errorf("service %q is not configured", name)
	}
	if service.Target == nil || service.Target.TLS == nil {
		if !config.IsPublicService(service) && strings.HasPrefix(target, "https://") {
			return nil, fmt.Errorf("service %q HTTPS listener requires target.tls", name)
		}
		return nil, nil
	}
	setting := config.TrustSource{CA: "system", Hostname: service.Target.TLS.ServerName}
	if service.Target.TLS.CAFile != nil {
		setting.CA = *service.Target.TLS.CAFile
	}
	if cache == nil {
		cache = privatetrust.NewCache(nil)
	}
	if config.TargetType(service) == "app" && target == "" {
		if setting.Hostname == nil {
			return nil, fmt.Errorf("service %q target.tls.server_name is required before its app listener is known", name)
		}
		snapshot, err := cache.Capture(ctx, p.Root, net.JoinHostPort(*setting.Hostname, "443"), setting)
		return &snapshot, err
	}
	if config.Protocol(service) == "http" || config.Protocol(service) == "kubernetes" {
		origin, err := localproxy.ParseCanonicalTarget(target)
		if err != nil || origin.Scheme != "https" {
			return nil, fmt.Errorf("service %q target TLS requires a resolved HTTPS origin", name)
		}
		target = origin.Host
	}
	snapshot, err := cache.Capture(ctx, p.Root, target, setting)
	if err != nil {
		return nil, fmt.Errorf("capture service %q TLS trust: %w", name, err)
	}
	return &snapshot, nil
}
