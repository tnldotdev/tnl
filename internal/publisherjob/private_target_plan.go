package publisherjob

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/tcptarget"
)

// PrivateTargetPlan contains captured target configuration only. foreground,
// app and group publishers do not manufacture partially installed jobs.
type PrivateTargetPlan struct {
	Protocol       config.ProtocolName
	Target         string
	Trust          *privatetrust.Snapshot
	Project        *projectconfig.Project
	ProjectService string
}

func (j Job) PrivateTargetPlan() PrivateTargetPlan {
	return PrivateTargetPlan{Protocol: j.Protocol, Target: j.Target, Trust: j.Trust, Project: j.Project, ProjectService: j.ProjectService}
}

func (p *PrivateTargetPlan) normalize() error {
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
