package project

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

// CaptureServiceTrust captures trust for a service's resolved target.
// the caller compares it with control's approved metadata before mutations.
func (p Project) CaptureServiceTrust(ctx context.Context, name, target string) (*targettrust.Snapshot, error) {
	service, found := p.Config.Services[name]
	if !found || config.IsPublicService(service) {
		return nil, fmt.Errorf("service %q is not a configured service", name)
	}
	return p.captureTrust(ctx, name, target)
}

func (p Project) captureTrust(ctx context.Context, name, target string) (*targettrust.Snapshot, error) {
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
	tls := service.Target.TLS
	ca, hostname := "system", ""
	if tls.CA != nil {
		ca = *tls.CA
	}
	if tls.Hostname != nil {
		hostname = *tls.Hostname
	}
	if config.TargetType(service) == "app" && target == "" {
		if hostname == "" {
			return nil, fmt.Errorf("service %q target.tls.hostname is required before its app listener is known", name)
		}
		snapshot, err := targettrust.CapturePortable(ctx, config.Protocol(service), net.JoinHostPort(hostname, "443"), ca, hostname)
		return &snapshot, err
	}
	if config.Protocol(service) == "http" || config.Protocol(service) == "kubernetes" {
		origin, err := targetsyntax.ParseCanonicalTarget(target)
		if err != nil || origin.Scheme != "https" {
			return nil, fmt.Errorf("service %q target TLS requires a resolved HTTPS origin", name)
		}
		target = origin.Host
	}
	snapshot, err := targettrust.CapturePortable(ctx, config.Protocol(service), target, ca, hostname)
	if err != nil {
		return nil, fmt.Errorf("capture service %q TLS trust: %w", name, err)
	}
	return &snapshot, nil
}
