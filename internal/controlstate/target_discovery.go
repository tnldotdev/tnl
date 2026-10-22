package controlstate

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

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

// only this allowlisted projection crosses the visitor boundary. RDS metadata,
// target addresses, trust bundles and publisher credentials never leave control.
func (d *Database) visitorKubernetesAuth(ctx context.Context, q *controlstatedb.Queries, service string) (*controlv1.KubernetesAuth, error) {
	row, err := q.VisitorServiceConfiguration(ctx, text(service))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c, err := d.openAppliedProject(controlstatedb.ControlAppliedProject{TeamID: row.TeamID, ProjectKey: row.ProjectKey, ConfigurationCiphertext: row.ConfigurationCiphertext, StorageKeyID: row.StorageKeyID})
	if err != nil {
		return nil, err
	}
	s, ok := c.Services[row.Service]
	if !ok {
		return nil, ErrPrivateServiceAccess
	}
	target := s.TargetDiscovery
	if s.Protocol != "kubernetes" || target == nil || target.Type != "eks" {
		return nil, nil
	}
	if target.Validate(s.Protocol) != nil || target.Cluster == nil {
		return nil, ErrPrivateServiceAccess
	}
	return &controlv1.KubernetesAuth{Provider: controlv1.KubernetesEKS, Cluster: *target.Cluster, Region: target.Region}, nil
}
