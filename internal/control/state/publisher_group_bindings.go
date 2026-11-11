package state

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// bindings contain only target authority. visitor policy stays in the template.
type PublisherGroupTargetBinding struct {
	Target          string                  `json:"target"`
	TargetTLS       *ProjectTargetTLS       `json:"target_tls,omitempty"`
	TargetDiscovery *ProjectTargetDiscovery `json:"target_discovery,omitempty"`
	protocol        string
}

type PublisherGroupBindings map[string]PublisherGroupTargetBinding

// the protocol pin is control-owned approval, not a caller-selected target
// setting. the private envelope keeps it out of both request and response shapes.
type storedPublisherGroupBindings struct {
	Bindings  PublisherGroupBindings `json:"bindings"`
	Protocols map[string]string      `json:"protocols"`
}

func publisherGroupBindingProtocols(c ProjectConfiguration, template string) map[string]string {
	protocols := map[string]string{}
	for name, service := range c.Services {
		if service.PublisherGroup == template && service.TargetBinding == "group" {
			protocols[name] = service.Protocol
		}
	}
	return protocols
}

func normalizePublisherGroupBindings(input PublisherGroupBindings, protocols map[string]string) (PublisherGroupBindings, error) {
	data, err := json.Marshal(input)
	if err != nil || len(data) > 512<<10 || len(input) > 128 {
		return nil, ErrProjectConfigurationInvalid
	}
	result := PublisherGroupBindings{}
	if input != nil {
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, err
		}
	}
	for name, binding := range result {
		if !serviceName.MatchString(name) || len(binding.Target) > 8192 || strings.ContainsAny(binding.Target, "\x00\r\n") || binding.Target == "" && binding.TargetDiscovery == nil {
			return nil, ErrProjectConfigurationInvalid
		}
		protocol, ok := protocols[name]
		if !ok {
			return nil, ErrProjectConfigurationInvalid
		}
		binding.protocol = protocol
		s := ProjectServiceConfiguration{PublisherGroup: "bound", Protocol: protocol, Target: binding.Target, TargetTLS: binding.TargetTLS, TargetDiscovery: binding.TargetDiscovery}
		s, err = bindPublisherGroupService(s, binding)
		if err != nil {
			return nil, err
		}
		result[name] = PublisherGroupTargetBinding{Target: s.Target, TargetTLS: s.TargetTLS, TargetDiscovery: s.TargetDiscovery, protocol: protocol}
	}
	return result, nil
}

func bindPublisherGroupService(service ProjectServiceConfiguration, binding PublisherGroupTargetBinding) (ProjectServiceConfiguration, error) {
	if binding.protocol == "" || binding.protocol != service.Protocol {
		return service, ErrProjectConfigurationInvalid
	}
	service.TargetBinding = ""
	service.Target, service.TargetTLS, service.TargetDiscovery = binding.Target, binding.TargetTLS, binding.TargetDiscovery
	if service.Protocol == "kubernetes" && service.TargetDiscovery == nil && service.TargetTLS == nil {
		return service, ErrProjectConfigurationInvalid
	}
	if err := normalizeAppliedProjectService(&service); err != nil {
		return service, err
	}
	return service, nil
}

func validatePublisherGroupBindings(c ProjectConfiguration, template string, bindings PublisherGroupBindings) error {
	for name := range bindings {
		s, ok := c.Services[name]
		if !ok || s.PublisherGroup != template || s.TargetBinding != "group" {
			return ErrProjectConfigurationInvalid
		}
	}
	for name, s := range c.Services {
		if s.PublisherGroup != template || s.TargetBinding != "group" {
			continue
		}
		b, ok := bindings[name]
		if !ok {
			return ErrProjectConfigurationInvalid
		}
		if _, err := bindPublisherGroupService(s, b); err != nil {
			return err
		}
	}
	return nil
}

func publisherGroupBindingsContext(id string) string { return "publisher-group-bindings/" + id }

func (d *Database) openPublisherGroupBindings(row controlstatedb.ControlPublisherGroupBinding) (PublisherGroupBindings, error) {
	data, _, err := d.storageKey.Open(row.StorageKeyID, publisherGroupBindingsContext(row.GroupID), row.BindingsCiphertext)
	if err != nil {
		return nil, err
	}
	var stored storedPublisherGroupBindings
	if err = json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	// never infer a missing pin from the current template. an explicit binding
	// creation or replacement is the only operation that approves a protocol.
	if stored.Bindings == nil || stored.Protocols == nil || len(stored.Bindings) != len(stored.Protocols) {
		return nil, ErrProjectConfigurationInvalid
	}
	for name, binding := range stored.Bindings {
		protocol, ok := stored.Protocols[name]
		if !ok || (ServiceMetadata{Protocol: protocol}).Validate() != nil {
			return nil, ErrProjectConfigurationInvalid
		}
		binding.protocol = protocol
		stored.Bindings[name] = binding
	}
	return stored.Bindings, nil
}

func (d *Database) loadPublisherGroupBindings(ctx context.Context, tx pgx.Tx, groups []controlstatedb.ControlProjectPublisherGroup) (map[string]PublisherGroupBindings, error) {
	result := map[string]PublisherGroupBindings{}
	for _, group := range groups {
		row, err := controlstatedb.New(tx).GetPublisherGroupBindings(ctx, group.ID)
		if err == pgx.ErrNoRows {
			result[group.ID] = PublisherGroupBindings{}
			continue
		}
		if err != nil {
			return nil, err
		}
		bindings, err := d.openPublisherGroupBindings(row)
		if err != nil {
			return nil, err
		}
		result[group.ID] = bindings
	}
	return result, nil
}

func (d *Database) savePublisherGroupBindings(ctx context.Context, tx pgx.Tx, id string, bindings PublisherGroupBindings) error {
	protocols := map[string]string{}
	for name, binding := range bindings {
		if binding.protocol == "" {
			return ErrProjectConfigurationInvalid
		}
		protocols[name] = binding.protocol
	}
	data, err := json.Marshal(storedPublisherGroupBindings{Bindings: bindings, Protocols: protocols})
	if err != nil {
		return err
	}
	sealed, err := d.storageKey.Seal(publisherGroupBindingsContext(id), data)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_bindings(group_id,bindings_ciphertext,storage_key_id) VALUES($1,$2,$3) ON CONFLICT(group_id) DO UPDATE SET bindings_ciphertext=EXCLUDED.bindings_ciphertext,storage_key_id=EXCLUDED.storage_key_id`, id, sealed, d.storageKey.CurrentID())
	return err
}

// apply carries complete replacement binding sets keyed by immutable group ID.
// unchanged instances retain their saved bindings; removing a template service
// prunes its old binding without requiring every customer to be resubmitted.
func (d *Database) reconcilePublisherGroupBindings(ctx context.Context, tx pgx.Tx, c ProjectConfiguration, groups []controlstatedb.ControlProjectPublisherGroup, old map[string]PublisherGroupBindings, updates map[string]PublisherGroupBindings, omit string) (map[string]PublisherGroupBindings, bool, error) {
	next := map[string]PublisherGroupBindings{}
	seen := map[string]bool{}
	changed := false
	for _, group := range groups {
		if group.TemplateName == "" || group.Name == omit {
			continue
		}
		bindings := PublisherGroupBindings{}
		for name, binding := range old[group.ID] {
			s, found := c.Services[name]
			if found && s.PublisherGroup == group.TemplateName && s.TargetBinding == "group" {
				bindings[name] = binding
			}
		}
		if update, ok := updates[group.ID]; ok {
			seen[group.ID] = true
			var err error
			bindings, err = normalizePublisherGroupBindings(update, publisherGroupBindingProtocols(c, group.TemplateName))
			if err != nil {
				return nil, false, err
			}
		}
		if err := validatePublisherGroupBindings(c, group.TemplateName, bindings); err != nil {
			return nil, false, err
		}
		next[group.ID] = bindings
		if !reflect.DeepEqual(old[group.ID], bindings) {
			if err := d.savePublisherGroupBindings(ctx, tx, group.ID, bindings); err != nil {
				return nil, false, err
			}
			changed = true
		}
	}
	if len(seen) != len(updates) {
		return nil, false, ErrProjectConfigurationInvalid
	}
	return next, changed, nil
}

func (d *Database) expandedPublisherConfiguration(ctx context.Context, tx pgx.Tx, c ProjectConfiguration, groups []controlstatedb.ControlProjectPublisherGroup) (ProjectConfiguration, error) {
	bindings, err := d.loadPublisherGroupBindings(ctx, tx, groups)
	if err != nil {
		return c, err
	}
	return publisherTemplateConfiguration(c, groups, "", bindings)
}
