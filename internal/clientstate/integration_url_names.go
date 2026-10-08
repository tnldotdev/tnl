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
		return "", errors.New("clientstate: callback project, namespace, and purpose are required")
	}
	store, err := d.Server(ctx, server)
	if err != nil {
		return "", err
	}
	if !validIntegrationURLHostname(proposed, namespace) {
		return "", errors.New("clientstate: invalid callback hostname")
	}
	if err := d.queries.SaveCallbackHostname(ctx, clientstatedb.SaveCallbackHostnameParams{
		ServerOrigin: store.controlEndpoint, ProjectKey: projectKey, Namespace: namespace, Purpose: purpose, Hostname: proposed,
	}); err != nil {
		return "", fmt.Errorf("clientstate: save callback hostname: %w", err)
	}
	hostname, err := d.queries.GetCallbackHostname(ctx, clientstatedb.GetCallbackHostnameParams{
		ServerOrigin: store.controlEndpoint, ProjectKey: projectKey, Namespace: namespace, Purpose: purpose,
	})
	if err != nil {
		return "", fmt.Errorf("clientstate: read callback hostname: %w", err)
	}
	if !validIntegrationURLHostname(hostname, namespace) {
		return "", errors.New("clientstate: saved callback hostname is invalid")
	}
	return hostname, nil
}

func validIntegrationURLHostname(hostname, namespace string) bool {
	canonical, err := naming.CanonicalizeHostname(hostname)
	depth, ok := naming.ChildDepth(hostname, namespace)
	return err == nil && canonical == hostname && ok && depth == 1
}
