package controlstate

import "github.com/tnldotdev/tnl/internal/config"

// ProjectTargetDiscovery is handed unchanged to the assigned publisher. no
// resolved address, provider credential, application credential or local CA path
// is supplied by apply. protocol verification and target trust belong to discovery.
type ProjectTargetDiscovery struct {
	Type     string  `json:"type"`
	Region   string  `json:"region"`
	Cluster  *string `json:"cluster,omitempty"`
	Instance *string `json:"instance,omitempty"`
	Endpoint *string `json:"endpoint,omitempty"`
}

func (t *ProjectTargetDiscovery) Validate(protocol string) error {
	if t == nil {
		return ErrProjectConfigurationInvalid
	}
	target := config.ServiceTarget{Type: t.Type, Region: &t.Region, Cluster: t.Cluster, Instance: t.Instance, Endpoint: t.Endpoint}
	if t.Type != "eks" && t.Type != "rds" {
		return ErrProjectConfigurationInvalid
	}
	if err := config.ValidateCloudTarget(protocol, target); err != nil {
		return ErrProjectConfigurationInvalid
	}
	if t.Type == "rds" && t.Endpoint == nil {
		t.Endpoint = new("writer")
	}
	return nil
}
