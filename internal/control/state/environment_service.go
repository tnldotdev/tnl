package state

import (
	"encoding/json"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

// environment publication facts are derived only from the pinned definition and
// approved destination. they are not a project desired-state document.
type EnvironmentServicePublication struct {
	Protocol        string                  `json:"protocol"`
	Target          string                  `json:"target"`
	TargetTLS       *ProjectTargetTLS       `json:"target_tls,omitempty"`
	TargetDiscovery *ProjectTargetDiscovery `json:"target_discovery,omitempty"`
	HTTP            *EnvironmentServiceHTTP `json:"http,omitempty"`
}

type EnvironmentServiceHTTP struct {
	Access *config.Access     `json:"access,omitempty"`
	Limits *config.WorkLimits `json:"limits,omitempty"`
}

func normalizeEnvironmentService(input EnvironmentServicePublication) (EnvironmentServicePublication, error) {
	// preserve an explicitly empty IP list as invalid before omitempty can erase
	// its presence while cloning caller-owned settings.
	if input.HTTP != nil && input.HTTP.Access != nil && input.HTTP.Access.Validate() != nil {
		return EnvironmentServicePublication{}, ErrEnvironmentInvalid
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > 512<<10 {
		return EnvironmentServicePublication{}, ErrEnvironmentInvalid
	}
	var s EnvironmentServicePublication
	if err = json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	if (ServiceMetadata{Protocol: s.Protocol}).Validate() != nil {
		return s, ErrEnvironmentInvalid
	}
	if s.HTTP != nil {
		if s.Protocol != "http" {
			return s, ErrEnvironmentInvalid
		}
		if a := s.HTTP.Access; a != nil {
			if a.Validate() != nil || a.VisitorMode() != "restricted" {
				return s, ErrEnvironmentInvalid
			}
			a.Mode = a.VisitorMode()
			a.IP, err = authorization.CanonicalizeIPPrefixes(a.IP)
			if err != nil {
				return s, ErrEnvironmentInvalid
			}
		}
		if s.HTTP.Limits != nil {
			if _, e := config.ResolveWorkLimits(&config.Limits{HTTP: s.HTTP.Limits}, "http"); e != nil {
				return s, ErrEnvironmentInvalid
			}
		}
	}
	if s.TargetDiscovery != nil {
		if s.Target != "" || s.TargetTLS != nil {
			return s, ErrEnvironmentInvalid
		}
		s.TargetDiscovery, err = s.TargetDiscovery.Normalize(s.Protocol)
		return s, err
	}
	if s.Target == "" || len(s.Target) > 8192 || strings.ContainsAny(s.Target, "\x00\r\n") {
		return s, ErrEnvironmentInvalid
	}
	if s.Protocol == "kubernetes" && s.TargetTLS == nil {
		return s, ErrEnvironmentInvalid
	}
	if s.Protocol == "http" && (s.TargetTLS == nil && strings.HasPrefix(s.Target, "https://") || s.TargetTLS != nil && strings.HasPrefix(s.Target, "http://")) {
		return s, ErrEnvironmentInvalid
	}
	s.Target, err = normalizeAppliedPrivateAddress(s.Target, s.Protocol)
	if err != nil {
		return s, ErrEnvironmentInvalid
	}
	if t := s.TargetTLS; t != nil {
		if (targettrust.Declaration{Hostname: t.Hostname, CAPEM: []byte(t.CAPEM), Digest: t.Digest}).Validate() != nil {
			return s, ErrEnvironmentInvalid
		}
	}
	return s, nil
}
