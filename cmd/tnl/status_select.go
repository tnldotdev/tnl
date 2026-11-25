package main

import (
	"slices"
	"strings"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func statusTunnelMatches(t clientstate.TunnelInfo, selector naming.ServiceSelector) bool {
	return selector.Kind == naming.SelectorID && t.ServiceID == selector.ID ||
		statusAddressMatches(selector, string(t.ServiceProtocol), t.PublicURL) ||
		t.PublicURL == "" && selector.MatchesEndpoint(string(t.ServiceProtocol), t.Hostname, 0)
}

func statusAddressMatches(selector naming.ServiceSelector, protocol, address string) bool {
	if selector.Kind != naming.SelectorAddress || address == "" {
		return false
	}
	endpoint, err := naming.ParseServiceSelector(address)
	if err != nil || endpoint.Kind != naming.SelectorAddress {
		return false
	}
	if protocol == "" {
		protocol = endpoint.Protocol
	}
	return selector.MatchesEndpoint(protocol, endpoint.Host, endpoint.Port)
}

func selectStatusService(project *projectStatus, selector naming.ServiceSelector, tunnels clientstate.TunnelSnapshot) (bool, error) {
	if selector.Kind == naming.SelectorOmitted {
		return true, nil
	}
	if selector.Kind == naming.SelectorName {
		name := selector.Name
		_, matched := project.configuration.Config.Services[name]
		matched = matched || slices.ContainsFunc(tunnels.Tunnels, func(t clientstate.TunnelInfo) bool { return t.Service == name }) ||
			slices.ContainsFunc(tunnels.Aliases, func(a clientstate.AliasInfo) bool { return a.Service == name })
		if project.Server != nil {
			found, err := project.Server.selectService(name, tunnels, matched)
			if err != nil {
				return false, err
			}
			matched = matched || found
		}
		if local := project.Local; local != nil {
			local.Snapshot.Services = slices.DeleteFunc(local.Snapshot.Services, func(s publisherapp.Service) bool { return s.Name != name })
			local.Snapshot.Publications = slices.DeleteFunc(local.Snapshot.Publications, func(t clientstate.TunnelInfo) bool { return t.Service != name })
			local.Tunnels.SelectService(name)
			matched = matched || len(local.Snapshot.Services)+len(local.Tunnels.Tunnels)+len(local.Tunnels.Aliases)+len(local.Tunnels.IntegrationURLs) > 0
		}
		return matched, nil
	}

	// an exact endpoint or ID selects records carrying that fact, not every
	// publication that happens to use the same project service name.
	ids := map[string]bool{}
	note := func(id string) {
		if id != "" {
			ids[id] = true
		}
	}
	keptTunnels := map[string]bool{}
	keptNames := map[string]bool{}
	for _, tunnel := range tunnels.Tunnels {
		if statusTunnelMatches(tunnel, selector) {
			keptTunnels[tunnel.ID], keptNames[tunnel.Service] = true, true
			note(tunnel.ServiceID)
		}
	}
	var matched bool
	if local := project.Local; local != nil {
		local.Snapshot.Services = slices.DeleteFunc(local.Snapshot.Services, func(s publisherapp.Service) bool {
			return !keptTunnels[s.TunnelID] && !(selector.Kind == naming.SelectorAddress &&
				s.TunnelID == "" && statusAddressMatches(selector, s.ServiceProtocol, s.PublicURL))
		})
		local.Snapshot.Publications = slices.DeleteFunc(local.Snapshot.Publications, func(t clientstate.TunnelInfo) bool { return !keptTunnels[t.ID] })
		local.Tunnels.Tunnels = slices.DeleteFunc(local.Tunnels.Tunnels, func(t clientstate.TunnelInfo) bool { return !keptTunnels[t.ID] })
		aliases := slices.DeleteFunc(local.Tunnels.Aliases, func(a clientstate.AliasInfo) bool {
			keep := selector.Kind == naming.SelectorID && a.ServiceID == selector.ID ||
				statusAddressMatches(selector, "http", a.PublicURL)
			if keep {
				note(a.ServiceID)
			}
			return !keep
		})
		// no integration URL is the endpoint of the selected service.
		local.Tunnels.Aliases, local.Tunnels.IntegrationURLs = nil, nil
		var tunnelName string
		for name := range keptNames {
			tunnelName = name
		}
		local.Tunnels.SelectService(tunnelName)
		local.Tunnels.Aliases = aliases
		matched = len(local.Snapshot.Services)+len(local.Tunnels.Tunnels)+len(aliases) != 0
	}
	if server := project.Server; server != nil {
		server.selectApplied(func(b controlv1.AppliedProjectService, protocol controlv1.ServiceProtocol) bool {
			id := ""
			if b.ServiceId != nil {
				id = *b.ServiceId
			}
			port := 0
			if b.Port != nil {
				port = *b.Port
			}
			keep := selector.Kind == naming.SelectorID && id == selector.ID ||
				b.Hostname != nil && selector.MatchesEndpoint(string(protocol), *b.Hostname, port)
			if keep {
				note(id)
			}
			return keep
		})
		server.Services = slices.DeleteFunc(server.Services, func(s statusServerService) bool {
			keep := selector.Kind == naming.SelectorID && s.ServiceID == selector.ID ||
				s.Endpoint != nil && selector.MatchesEndpoint(string(s.Protocol), s.Endpoint.Hostname, s.Endpoint.Port)
			if keep {
				note(s.ServiceID)
			}
			return !keep
		})
		matched = matched || len(keptTunnels)+len(server.Services)+len(server.AppliedServices) != 0
	}
	if len(ids) > 1 || len(keptNames) > 1 {
		return false, ambiguousStatusSelector(ids, keptNames)
	}
	return matched, nil
}

func ambiguousStatusSelector(ids, names map[string]bool) error {
	var choices []string
	for id := range ids {
		choices = append(choices, id)
	}
	if len(choices) < 2 {
		for name := range names {
			if name != "" {
				choices = append(choices, name)
			}
		}
	}
	slices.Sort(choices)
	return serviceInputError(failure.InvalidCommand, "More than one service matches. Choose an exact service name or ID: "+strings.Join(choices, ", ")+".")
}

func (server *statusServer) selectApplied(keep func(controlv1.AppliedProjectService, controlv1.ServiceProtocol) bool) {
	// the hash identifies the complete applied configuration. emit only the
	// matching binding records rather than attaching it to a partial config.
	if server.Applied == nil {
		return
	}
	server.declarations = server.Applied.ServiceDeclarations
	for _, binding := range server.Applied.Services {
		if keep(binding, server.declarations[binding.Service]) {
			server.AppliedServices = append(server.AppliedServices, binding)
		}
	}
	server.Applied = nil
}

func (server *statusServer) selectService(name string, local clientstate.TunnelSnapshot, configured bool) (bool, error) {
	names := map[string]string{}
	for _, tunnel := range local.Tunnels {
		if tunnel.Server == server.ControlURL && tunnel.Service != "" && tunnel.ServiceID != "" {
			names[tunnel.ServiceID] = tunnel.Service
		}
	}
	for _, alias := range local.Aliases {
		if alias.Server == server.ControlURL && alias.Service != "" && alias.ServiceID != "" {
			names[alias.ServiceID] = alias.Service
		}
	}
	server.selectApplied(func(binding controlv1.AppliedProjectService, _ controlv1.ServiceProtocol) bool {
		if binding.ServiceId != nil {
			names[*binding.ServiceId] = binding.Service
		}
		return binding.Service == name
	})
	projectName := configured || len(server.AppliedServices) != 0 || slices.ContainsFunc(server.Services, func(s statusServerService) bool {
		return names[s.ServiceID] == name || s.sourceName == name
	})
	fallback := map[string]bool{}
	server.Services = slices.DeleteFunc(server.Services, func(s statusServerService) bool {
		known := names[s.ServiceID]
		if known == "" {
			known = s.sourceName
		}
		if known == name {
			return false
		}
		if !projectName && known == "" && s.Name == name {
			fallback[s.ServiceID] = true
			return false
		}
		return true
	})
	if len(fallback) > 1 {
		return false, ambiguousStatusSelector(fallback, nil)
	}
	return len(server.Services)+len(server.AppliedServices) != 0, nil
}
