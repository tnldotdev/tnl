package state

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// protocol pins are control-owned approvals, not a caller-selected target field.
// the encrypted envelope never substitutes a newer definition for a missing pin.
type environmentTargetBinding struct {
	Target          string                  `json:"target"`
	TargetTLS       *ProjectTargetTLS       `json:"target_tls,omitempty"`
	TargetDiscovery *ProjectTargetDiscovery `json:"target_discovery,omitempty"`
	HTTP            *EnvironmentServiceHTTP `json:"http,omitempty"`
	protocol        string
}

type environmentBindings map[string]environmentTargetBinding

type storedEnvironmentTargets struct {
	Bindings  environmentBindings `json:"bindings"`
	Protocols map[string]string   `json:"protocols"`
}

func bindEnvironmentService(protocol string, binding environmentTargetBinding) (EnvironmentServicePublication, error) {
	if binding.protocol == "" || binding.protocol != protocol {
		return EnvironmentServicePublication{}, ErrEnvironmentInvalid
	}
	return normalizeEnvironmentService(EnvironmentServicePublication{Protocol: protocol, Target: binding.Target, TargetTLS: binding.TargetTLS, TargetDiscovery: binding.TargetDiscovery, HTTP: binding.HTTP})
}

func environmentTargetsContext(group string) string { return "environment-targets/" + group }

func (d *Database) openEnvironmentTargets(row controlstatedb.ControlPublisherGroupBinding) (environmentBindings, error) {
	data, _, err := d.storageKey.Open(row.StorageKeyID, environmentTargetsContext(row.GroupID), row.BindingsCiphertext)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var stored storedEnvironmentTargets
	if err = json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	if stored.Bindings == nil || stored.Protocols == nil || len(stored.Bindings) != len(stored.Protocols) || len(stored.Bindings) > 128 {
		return nil, ErrEnvironmentInvalid
	}
	for name, binding := range stored.Bindings {
		protocol, ok := stored.Protocols[name]
		if !ok || !serviceName.MatchString(name) {
			return nil, ErrEnvironmentInvalid
		}
		binding.protocol = protocol
		if _, err = bindEnvironmentService(protocol, binding); err != nil {
			return nil, err
		}
		stored.Bindings[name] = binding
	}
	return stored.Bindings, nil
}

func (d *Database) saveEnvironmentTargets(ctx context.Context, tx pgx.Tx, group string, bindings environmentBindings) error {
	protocols := make(map[string]string, len(bindings))
	for name, binding := range bindings {
		if _, err := bindEnvironmentService(binding.protocol, binding); err != nil {
			return err
		}
		protocols[name] = binding.protocol
	}
	data, err := json.Marshal(storedEnvironmentTargets{Bindings: bindings, Protocols: protocols})
	if err != nil {
		return err
	}
	defer clear(data)
	sealed, err := d.storageKey.Seal(environmentTargetsContext(group), data)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_bindings(group_id,bindings_ciphertext,storage_key_id) VALUES($1,$2,$3) ON CONFLICT(group_id) DO UPDATE SET bindings_ciphertext=EXCLUDED.bindings_ciphertext,storage_key_id=EXCLUDED.storage_key_id`, group, sealed, d.storageKey.CurrentID())
	return err
}
