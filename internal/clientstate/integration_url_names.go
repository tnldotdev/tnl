package clientstate

import (
	"context"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// IntegrationURLHostname preserves each registered origin across label changes.
func (d *Database) IntegrationURLHostname(ctx context.Context, server, projectKey, namespace, purpose, proposed string) (string, error) {
	if projectKey == "" || namespace == "" || !naming.ValidServiceName(purpose) {
		return "", errors.New("integration URL project, namespace, and purpose are required")
	}
	store, err := d.Server(ctx, server)
	if err != nil {
		return "", err
	}
	if !validIntegrationURLHostname(proposed, namespace) {
		return "", errors.New("invalid integration URL hostname")
	}
	if err := d.queries.SaveIntegrationURLHostname(ctx, clientstatedb.SaveIntegrationURLHostnameParams{
		ServerOrigin: store.controlEndpoint, ProjectKey: projectKey, Namespace: namespace, Purpose: purpose, Hostname: proposed,
	}); err != nil {
		return "", fmt.Errorf("save integration URL hostname: %w", err)
	}
	hostname, err := d.queries.GetIntegrationURLHostname(ctx, clientstatedb.GetIntegrationURLHostnameParams{
		ServerOrigin: store.controlEndpoint, ProjectKey: projectKey, Namespace: namespace, Purpose: purpose,
	})
	if err != nil {
		return "", fmt.Errorf("read integration URL hostname: %w", err)
	}
	if !validIntegrationURLHostname(hostname, namespace) {
		return "", errors.New("saved integration URL hostname is invalid")
	}
	return hostname, nil
}

func validIntegrationURLHostname(hostname, namespace string) bool {
	canonical, err := naming.CanonicalizeHostname(hostname)
	depth, ok := naming.ChildDepth(hostname, namespace)
	return err == nil && canonical == hostname && ok && depth == 1
}
