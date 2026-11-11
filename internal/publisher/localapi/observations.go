package localapi

import (
	"slices"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func scopeName(grant publisherprotocol.Endpoint) string {
	if grant.Service != nil {
		return *grant.Service
	}
	if grant.InvocationId != nil {
		return *grant.InvocationId
	}
	return ""
}

// filter every observation before encoding without changing owner views.
func scopedSnapshot(snapshot publisherapp.Snapshot, grant publisherprotocol.Endpoint) publisherapp.Snapshot {
	if grant.Scope == "owner" {
		return snapshot
	}
	name := scopeName(grant)
	snapshot.Services = slices.DeleteFunc(slices.Clone(snapshot.Services), func(service publisherapp.Service) bool { return service.Name != name })
	snapshot.Publications = slices.DeleteFunc(slices.Clone(snapshot.Publications), func(publication clientstate.TunnelInfo) bool {
		if grant.Scope == "invocation" {
			return !slices.ContainsFunc(snapshot.Services, func(service publisherapp.Service) bool { return service.TunnelID == publication.ID })
		}
		return publication.Service != name
	})
	return snapshot
}

// unrelated events advance the exclusive cursor but contain no sibling facts.
func scopedEvents(events []publisherapp.Event, grant publisherprotocol.Endpoint, current publisherapp.Snapshot) []publisherapp.Event {
	// retained service events preserve the exact tunnel relationship after close
	// has cleared it from the current snapshot. never infer it from a target or URL.
	for _, event := range events {
		if event.Service != nil && event.Service.Name == scopeName(grant) {
			current.Services = append(current.Services, *event.Service)
		}
		if event.Snapshot != nil {
			for _, service := range event.Snapshot.Services {
				if service.Name == scopeName(grant) {
					current.Services = append(current.Services, service)
				}
			}
		}
	}
	result := make([]publisherapp.Event, len(events))
	for index, event := range events {
		result[index] = scopedEvent(event, grant, current)
	}
	return result
}

func scopedEvent(event publisherapp.Event, grant publisherprotocol.Endpoint, current publisherapp.Snapshot) publisherapp.Event {
	result := publisherapp.Event{Cursor: event.Cursor, Type: "cursor", At: event.At}
	if event.Snapshot != nil {
		snapshot := scopedSnapshot(*event.Snapshot, grant)
		result.Snapshot, result.Type = &snapshot, "snapshot"
	}
	if event.Service != nil && event.Service.Name == scopeName(grant) {
		service := *event.Service
		result.Service, result.Type = &service, event.Type
	}
	if event.Publication != nil && slices.ContainsFunc(current.Services, func(service publisherapp.Service) bool { return service.TunnelID == event.Publication.ID }) {
		publication := *event.Publication
		result.Publication, result.Type = &publication, event.Type
	}
	return result
}
