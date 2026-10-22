package target

import (
	"errors"
	"path/filepath"
	"strings"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

// TargetPlan contains captured target configuration only. foreground,
// app and group publishers do not manufacture partially installed jobs.
type TargetPlan struct {
	Protocol       config.ProtocolName
	Target         string
	Trust          *targettrust.Snapshot
	Project        *clientproject.Project
	ProjectService string
}

// ErrScope is shared with installed jobs so callers retain the same failure
// identity when target validation moves below the supervisor.
var ErrScope = failure.Wrap("select installed job", failure.InvalidTunnelFlags, errors.New("installed publishers require an explicit server and an exact public URL or service grant; connectors require a saved user identity"))

func (p *TargetPlan) Normalize() error {
	if !p.Protocol.Valid() {
		return ErrScope
	}
	if p.Project != nil {
		definition, found := p.Project.Config.Services[p.ProjectService]
		if !found || !filepath.IsAbs(p.Project.Root) || config.IsPublicService(definition) || config.Protocol(definition) != string(p.Protocol) || config.TargetType(definition) == "app" {
			return ErrScope
		}
	} else if p.ProjectService != "" {
		return ErrScope
	}
	if p.Trust != nil {
		if _, err := p.Trust.Verifier(); err != nil {
			return errors.Join(ErrScope, err)
		}
	}
	var target string
	var err error
	if p.Protocol == config.ProtocolHTTP || p.Protocol == config.ProtocolKubernetes {
		if p.Protocol == config.ProtocolKubernetes && (!strings.HasPrefix(p.Target, "https://") || p.Trust == nil) {
			return ErrScope
		}
		if strings.HasPrefix(p.Target, "https://") && p.Trust == nil || strings.HasPrefix(p.Target, "http://") && p.Trust != nil {
			return ErrScope
		}
		target, err = config.NormalizeHTTPServiceTarget(config.Service{}, p.Target)
		if err == nil && p.Trust != nil && !strings.Contains(p.Target, "://") {
			target = "https://" + strings.TrimPrefix(target, "http://")
		}
	} else {
		target, err = tcptarget.Normalize(p.Target)
	}
	if err != nil {
		return ErrScope
	}
	p.Target = target
	return nil
}
