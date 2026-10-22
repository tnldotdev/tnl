// package clientruntime owns local app registration and publication observations.
// clientstate owns their transactional snapshot, cursor, and bounded history.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

const EventRetention = clientstate.RuntimeEventRetention

var ErrCursorExpired = clientstate.ErrRuntimeCursorExpired
var ErrOwnerConflict = errors.New("another live app owns this service")
var ErrRegistrationStale = errors.New("app registration is stale")

// Service uses Name as its registration key: a configured service name or an
// invocation ID. an invocation key is never a configured tunnel service name.
type Service struct {
	Project           string       `json:"project,omitempty"`
	Name              string       `json:"service"`
	ServiceProtocol   string       `json:"service_protocol,omitempty"`
	Directory         string       `json:"directory"`
	TunnelID          string       `json:"tunnel_id,omitempty"`
	PublicURL         string       `json:"public_url,omitempty"`
	RegistrationID    string       `json:"registration_id,omitempty"`
	Target            string       `json:"target,omitempty"`
	Framework         string       `json:"framework,omitempty"`
	Registered        bool         `json:"registered"`
	Routable          bool         `json:"routable"`
	Ready             bool         `json:"ready"`
	PublishRunNumber  uint64       `json:"publish_run_number,omitempty"`
	ProvisioningStage string       `json:"provisioning_stage,omitempty"`
	Readiness         Readiness    `json:"readiness"`
	Observation       *Observation `json:"observation,omitempty"`
	Failure           string       `json:"failure,omitempty"`
}

type Event struct {
	Cursor      string                  `json:"cursor"`
	Type        string                  `json:"type"`
	At          time.Time               `json:"at"`
	Service     *Service                `json:"service,omitempty"`
	Snapshot    *Snapshot               `json:"snapshot,omitempty"`
	Publication *clientstate.TunnelInfo `json:"publication,omitempty"`
}

type Snapshot struct {
	SchemaVersion int                      `json:"schema_version"`
	Project       string                   `json:"project"`
	Cursor        string                   `json:"cursor"`
	ObservedAt    time.Time                `json:"observed_at"`
	Services      []Service                `json:"services"`
	Publications  []clientstate.TunnelInfo `json:"publications,omitempty"`
	Events        []Event                  `json:"-"`
}

func Identity(project, state string) string {
	digest := sha256.Sum256([]byte(project + "\x00" + state))
	return hex.EncodeToString(digest[:12])
}

func ReadSnapshot(project, state string) (Snapshot, error) {
	database, err := clientstate.Open(context.Background(), state)
	if err != nil {
		return Snapshot{}, err
	}
	defer database.Close()
	return ReadSnapshotFrom(context.Background(), database, project)
}

func ReadSnapshotFrom(ctx context.Context, database *clientstate.Database, project string) (Snapshot, error) {
	snapshot, err := database.ReadRuntimeSnapshot(ctx, project)
	if err != nil {
		return Snapshot{}, err
	}
	return decodeSnapshot(snapshot)
}

func ListSnapshots(state string) ([]Snapshot, error) {
	database, err := clientstate.Open(context.Background(), state)
	if err != nil {
		return nil, err
	}
	defer database.Close()
	return ListSnapshotsFrom(context.Background(), database)
}

func ListSnapshotsFrom(ctx context.Context, database *clientstate.Database) ([]Snapshot, error) {
	native, err := database.ListRuntimeSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Snapshot, 0, len(native))
	for _, entry := range native {
		snapshot, err := decodeSnapshot(entry)
		if err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, nil
}

// CommitSnapshot commits app services and one event using the native project
// journal. the returned cursor/history replace the caller's view only on success.
// publications written concurrently remain part of the same native snapshot.
func CommitSnapshot(ctx context.Context, database *clientstate.Database, snapshot *Snapshot, kind string, service *Service) error {
	if snapshot == nil {
		return errors.New("clientruntime: snapshot is required")
	}
	services := make([]json.RawMessage, 0, len(snapshot.Services))
	for _, value := range snapshot.Services {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		services = append(services, encoded)
	}
	event := Event{Service: service}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	native, err := database.CommitRuntimeUpdate(ctx, snapshot.Project, clientstate.RuntimeUpdate{
		Services: services, ExpectedCursor: snapshot.Cursor, Type: kind, Payload: payload, Snapshot: service == nil,
	})
	if err != nil {
		return err
	}
	persisted, err := decodeSnapshot(native)
	if err != nil {
		return err
	}
	snapshot.SchemaVersion, snapshot.Cursor, snapshot.ObservedAt = persisted.SchemaVersion, persisted.Cursor, persisted.ObservedAt
	snapshot.Publications, snapshot.Events = persisted.Publications, persisted.Events
	return nil
}

func decodeSnapshot(native clientstate.RuntimeSnapshot) (Snapshot, error) {
	result := Snapshot{SchemaVersion: 1, Project: native.Project, Cursor: native.Cursor, ObservedAt: native.ObservedAt,
		Services: make([]Service, 0, len(native.Services)), Publications: native.Publications, Events: make([]Event, 0, len(native.Events))}
	for _, value := range native.Services {
		var service Service
		if err := json.Unmarshal(value, &service); err != nil {
			return Snapshot{}, err
		}
		result.Services = append(result.Services, service)
	}
	for _, value := range native.Events {
		event, err := decodeEvent(value)
		if err != nil {
			return Snapshot{}, err
		}
		result.Events = append(result.Events, event)
	}
	return result, nil
}

func decodeEvent(native clientstate.RuntimeEvent) (Event, error) {
	var event Event
	if err := json.Unmarshal(native.Payload, &event); err != nil {
		return Event{}, err
	}
	event.Cursor, event.Type, event.At = native.Cursor, native.Type, native.At
	if event.Snapshot != nil {
		event.Snapshot.Cursor, event.Snapshot.ObservedAt = native.Cursor, native.At
	}
	return event, nil
}

func EventsAfter(snapshot Snapshot, cursor string) ([]Event, error) {
	native := clientstate.RuntimeSnapshot{Cursor: snapshot.Cursor, Events: make([]clientstate.RuntimeEvent, 0, len(snapshot.Events))}
	for _, event := range snapshot.Events {
		payload, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		native.Events = append(native.Events, clientstate.RuntimeEvent{Cursor: event.Cursor, Type: event.Type, At: event.At, Payload: payload})
	}
	resumed, err := clientstate.RuntimeEventsAfter(native, cursor)
	if err != nil {
		return nil, err
	}
	result := make([]Event, 0, len(resumed))
	for _, entry := range resumed {
		event, err := decodeEvent(entry)
		if err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, nil
}

// EventsAfterFrom resumes directly from native state without loading unrelated
// snapshot payloads. both native resume and snapshot-based resume are exclusive.
func EventsAfterFrom(ctx context.Context, database *clientstate.Database, project, cursor string) ([]Event, error) {
	native, err := database.RuntimeEventsAfter(ctx, project, cursor)
	if err != nil {
		return nil, err
	}
	result := make([]Event, 0, len(native))
	for _, value := range native {
		event, err := decodeEvent(value)
		if err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, nil
}
