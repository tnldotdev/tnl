package state

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

var (
	ErrProjectConfigurationInvalid = errors.New("local service declaration is invalid")
	ErrProjectConfigurationStale   = errors.New("local service declaration changed")
	ErrProjectSourceConflict       = errors.New("project label belongs to another source")
	fingerprintPattern             = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// local declarations are bounded facts for one worktree-owned service, not a
// saved project-wide remote desired-state or authorization document.
type LocalServiceDeclaration struct {
	Name            string                   `json:"name,omitempty"`
	Protocol        string                   `json:"protocol,omitempty"`
	Target          string                   `json:"target"`
	TargetDiscovery *ProjectTargetDiscovery  `json:"target_discovery,omitempty"`
	TargetTLS       *ProjectTargetTLS        `json:"target_tls,omitempty"`
	PublicURL       *ProjectServicePublicURL `json:"public_url,omitempty"`
	Access          *ProjectServiceAccess    `json:"access,omitempty"`
	HTTP            *config.HTTPService      `json:"http,omitempty"`
}

type ProjectTargetTLS struct {
	Hostname string `json:"hostname"`
	CAPEM    string `json:"ca_pem,omitempty"`
	Digest   string `json:"digest"`
}

type ProjectServicePublicURL struct {
	RequirePostQuantum *bool                `json:"require_post_quantum,omitempty"`
	DomainID           string               `json:"domain_id,omitempty"`
	Hostname           string               `json:"hostname,omitempty"`
	Access             *ProjectPublicAccess `json:"access,omitempty"`
	Limits             *ProjectPublicLimits `json:"limits,omitempty"`
	Ephemeral          bool                 `json:"ephemeral,omitempty"`
}

type ProjectPublicAccess struct {
	Mode string   `json:"mode,omitempty"`
	IP   []string `json:"ip,omitempty"`
}

type ProjectPublicLimits struct {
	HTTP    *ProjectHTTPApplicationLimits `json:"http,omitempty"`
	Traffic *trafficlimits.Selection      `json:"traffic,omitempty"`
}

type ProjectHTTPApplicationLimits struct {
	Total       *int                    `json:"total,omitempty"`
	Concurrency *int                    `json:"concurrency,omitempty"`
	Rate        *ProjectApplicationRate `json:"rate,omitempty"`
}

type ProjectApplicationRate struct {
	Count int    `json:"count"`
	Per   string `json:"per"`
	Burst *int   `json:"burst,omitempty"`
}

type ProjectServiceAccess struct {
	Team bool `json:"team"`
}

type ProjectWebhook struct {
	Service   string   `json:"service"`
	Path      string   `json:"path"`
	Provider  string   `json:"provider"`
	Delivery  string   `json:"delivery,omitempty"`
	Methods   []string `json:"methods,omitempty"`
	SourceIPs []string `json:"source_ips,omitempty"`
}

type serviceResourceMutation struct {
	TeamID, ProjectKey, SourceFingerprint, ActorID string
	DNSAutomation                                  bool
	Now                                            time.Time
}

func normalizeLocalService(name string, input LocalServiceDeclaration) (LocalServiceDeclaration, error) {
	data, err := json.Marshal(input)
	if err != nil || len(data) > 512<<10 || !serviceName.MatchString(name) {
		return LocalServiceDeclaration{}, ErrProjectConfigurationInvalid
	}
	var service LocalServiceDeclaration
	if err = json.Unmarshal(data, &service); err != nil {
		return service, err
	}
	if service.Name == "" {
		service.Name = name
	}
	if service.Protocol == "" {
		service.Protocol = "http"
	}
	if service.HTTP != nil {
		for _, mount := range service.HTTP.Paths {
			if mount.Service == name {
				return service, ErrProjectConfigurationInvalid
			}
		}
	}
	if !serviceName.MatchString(service.Name) || (ServiceMetadata{Protocol: service.Protocol}).Validate() != nil || service.Access != nil && !service.Access.Team || service.Target == "" && service.TargetDiscovery == nil || len(service.Target) > 8192 || strings.ContainsAny(service.Target, "\x00\r\n") {
		return service, ErrProjectConfigurationInvalid
	}
	if p := service.PublicURL; p != nil && p.Access != nil && p.Access.IP != nil && len(p.Access.IP) == 0 {
		return service, ErrProjectConfigurationInvalid
	}
	if err = normalizeLocalServiceValues(&service); err != nil {
		return service, err
	}
	return service, nil
}
