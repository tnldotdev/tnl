package daemon

import (
	"context"
	"errors"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

// ApplyIngressPool changes durable allocation policy without starting listeners
// or workers. serving control processes only initialize or verify this policy.
func ApplyIngressPool(ctx context.Context, cfg daemonconfig.Config) error {
	if !cfg.Role.RunsControl() {
		return errors.New("ingress-pool apply requires control or standalone configuration")
	}
	ports, err := cfg.ServicePortInventory()
	if err != nil {
		return err
	}
	database, err := controlstate.Open(ctx, cfg.DatabaseURL, cfg.StorageKey, cfg.StorageKeyPrevious, cfg.ManagedURLMode)
	if err != nil {
		return err
	}
	defer database.Close()
	return database.ConfigureIngressServicePorts(ctx, controlstate.PrimaryIngressPoolID, ports.Ranges())
}
