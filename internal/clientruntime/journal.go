// package clientruntime owns local app registration, publication observations,
// and a bounded durable event journal. it never starts or stops applications.
package clientruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

const EventRetention = 2048

var ErrCursorExpired = errors.New("local event cursor expired; read a new status snapshot")
var ErrOwnerConflict = errors.New("another live app owns this service")
var ErrRegistrationStale = errors.New("app registration is stale")

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
	Cursor   string    `json:"cursor"`
	Type     string    `json:"type"`
	At       time.Time `json:"at"`
	Service  *Service  `json:"service,omitempty"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	Project       string    `json:"project"`
	Cursor        string    `json:"cursor"`
	ObservedAt    time.Time `json:"observed_at"`
	Services      []Service `json:"services"`
	Events        []Event   `json:"-"`
}

func Identity(project, state string) string {
	digest := sha256.Sum256([]byte(project + "\x00" + state))
	return hex.EncodeToString(digest[:12])
}

func ReadSnapshot(project, state string) (Snapshot, error) {
	db, err := clientstate.Open(context.Background(), state)
	if err != nil {
		return Snapshot{}, err
	}
	defer db.Close()
	return readSnapshot(db, project)
}

func ListSnapshots(state string) ([]Snapshot, error) {
	db, err := clientstate.Open(context.Background(), state)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	journals, err := db.ListRuntimeJournals(context.Background())
	if err != nil {
		return nil, err
	}
	result := make([]Snapshot, 0, len(journals))
	for _, journal := range journals {
		snapshot, err := decodeJournal(journal)
		if err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, nil
}

func readSnapshot(db *clientstate.Database, project string) (Snapshot, error) {
	journal, found, err := db.ReadRuntimeJournal(context.Background(), project)
	if err != nil {
		return Snapshot{}, err
	}
	if !found {
		return Snapshot{SchemaVersion: 1, Project: project, Cursor: "0", Services: []Service{}}, nil
	}
	return decodeJournal(journal)
}

func decodeJournal(journal clientstate.RuntimeJournal) (Snapshot, error) {
	var snapshot Snapshot
	if err := json.Unmarshal(journal.Snapshot, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.SchemaVersion != 1 || snapshot.Project != journal.Project {
		return Snapshot{}, errors.New("invalid local journal identity")
	}
	snapshot.Events = make([]Event, 0, len(journal.Events))
	for _, encoded := range journal.Events {
		var event Event
		if err := json.Unmarshal(encoded, &event); err != nil {
			return Snapshot{}, err
		}
		snapshot.Events = append(snapshot.Events, event)
	}
	return snapshot, nil
}

func WriteSnapshot(snapshot Snapshot, db *clientstate.Database) error {
	if len(snapshot.Events) == 0 {
		return errors.New("local runtime snapshot requires an event")
	}
	cursor, err := ParseCursor(snapshot.Cursor)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	event, err := json.Marshal(snapshot.Events[len(snapshot.Events)-1])
	if err != nil {
		return err
	}
	return db.SaveRuntimeJournal(context.Background(), snapshot.Project, int64(cursor), encoded, event)
}

func EventsAfter(snapshot Snapshot, cursor string) ([]Event, error) {
	sequence, err := ParseCursor(cursor)
	if err != nil {
		return nil, err
	}
	latestSequence, err := ParseCursor(snapshot.Cursor)
	if err != nil {
		return nil, err
	}
	if sequence > latestSequence {
		return nil, ErrCursorExpired
	}
	if len(snapshot.Events) > 0 {
		first, _ := ParseCursor(snapshot.Events[0].Cursor)
		if sequence < first-1 {
			return nil, ErrCursorExpired
		}
	}
	return slices.DeleteFunc(slices.Clone(snapshot.Events), func(event Event) bool { value, _ := ParseCursor(event.Cursor); return value <= sequence }), nil
}

func ParseCursor(cursor string) (uint64, error) {
	value, err := strconv.ParseUint(cursor, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != cursor || strings.TrimSpace(cursor) != cursor {
		return 0, fmt.Errorf("invalid local event cursor")
	}
	return value, nil
}
