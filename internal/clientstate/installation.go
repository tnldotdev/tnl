package clientstate

import (
	"context"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const installationIDPrefix = "installation_"

// InstallationID returns the stable pseudonymous identifier for this client database.
func (d *Database) InstallationID(ctx context.Context) (string, error) {
	id, err := d.queries.GetInstallationID(ctx)
	if err != nil {
		return "", fmt.Errorf("clientstate: read installation ID: %w", err)
	}
	if id != "" {
		if !validInstallationID(id) {
			return "", errors.New("clientstate: installation ID is invalid")
		}
		return id, nil
	}
	generated, err := opaqueid.New(installationIDPrefix)
	if err != nil {
		return "", fmt.Errorf("clientstate: generate installation ID: %w", err)
	}
	if err := d.queries.SetInstallationID(ctx, generated); err != nil {
		return "", fmt.Errorf("clientstate: save installation ID: %w", err)
	}
	id, err = d.queries.GetInstallationID(ctx)
	if err != nil {
		return "", fmt.Errorf("clientstate: reread installation ID: %w", err)
	}
	if !validInstallationID(id) {
		return "", errors.New("clientstate: installation ID is invalid")
	}
	return id, nil
}

func validInstallationID(id string) bool {
	return opaqueid.Valid(id, installationIDPrefix)
}
