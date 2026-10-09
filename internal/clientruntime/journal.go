// package clientruntime owns local app registration, publication observations,
// and a bounded durable event journal. it never starts or stops applications.
package clientruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const EventRetention = 2048

var ErrCursorExpired = errors.New("local event cursor expired; read a new status snapshot")
var ErrOwnerConflict = errors.New("another live app owns this service")
var ErrRegistrationStale = errors.New("app registration is stale")

type Service struct {
	Project          string       `json:"project,omitempty"`
	Name             string       `json:"service"`
	Directory        string       `json:"directory"`
	PublicURL        string       `json:"public_url,omitempty"`
	RegistrationID   string       `json:"registration_id,omitempty"`
	Target           string       `json:"target,omitempty"`
	Framework        string       `json:"framework,omitempty"`
	Registered       bool         `json:"registered"`
	Routable         bool         `json:"routable"`
	Ready            bool         `json:"ready"`
	PublishRunNumber uint64       `json:"publish_run_number,omitempty"`
	Readiness        Readiness    `json:"readiness"`
	Observation      *Observation `json:"observation,omitempty"`
	Failure          string       `json:"failure,omitempty"`
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

type diskJournal struct {
	Snapshot Snapshot `json:"snapshot"`
	Events   []Event  `json:"events"`
}

func Identity(project, state string) string {
	digest := sha256.Sum256([]byte(project + "\x00" + state))
	return hex.EncodeToString(digest[:12])
}

func JournalPath(project, state string) string {
	return filepath.Join(state, "runtime", Identity(project, state)+".json")
}

func ReadSnapshot(project, state string) (Snapshot, error) {
	data, err := os.ReadFile(JournalPath(project, state))
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{SchemaVersion: 1, Project: project, Cursor: "0", Services: []Service{}}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	if len(data) > 16<<20 {
		return Snapshot{}, errors.New("local journal exceeds limit")
	}
	var journal diskJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return Snapshot{}, err
	}
	if journal.Snapshot.SchemaVersion != 1 || journal.Snapshot.Project != project {
		return Snapshot{}, errors.New("invalid local journal")
	}
	journal.Snapshot.Events = journal.Events
	return journal.Snapshot, nil
}

func ListSnapshots(state string) ([]Snapshot, error) {
	entries, err := os.ReadDir(filepath.Join(state, "runtime"))
	if errors.Is(err, os.ErrNotExist) {
		return []Snapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := []Snapshot{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(state, "runtime", entry.Name()))
		if err != nil {
			return nil, err
		}
		if len(data) > 16<<20 {
			return nil, errors.New("local journal exceeds limit")
		}
		var journal diskJournal
		if err := json.Unmarshal(data, &journal); err != nil {
			return nil, err
		}
		if journal.Snapshot.SchemaVersion != 1 || filepath.Base(JournalPath(journal.Snapshot.Project, state)) != entry.Name() {
			return nil, errors.New("invalid local journal identity")
		}
		journal.Snapshot.Events = journal.Events
		result = append(result, journal.Snapshot)
	}
	slices.SortFunc(result, func(a, b Snapshot) int { return strings.Compare(a.Project, b.Project) })
	return result, nil
}

func WriteSnapshot(snapshot Snapshot, state string) error {
	directory := filepath.Dir(JournalPath(snapshot.Project, state))
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(diskJournal{Snapshot: snapshot, Events: snapshot.Events})
	if err != nil {
		return err
	}
	for len(data) > 8<<20 && len(snapshot.Events) > 1 {
		snapshot.Events = snapshot.Events[len(snapshot.Events)/2:]
		data, err = json.Marshal(diskJournal{Snapshot: snapshot, Events: snapshot.Events})
		if err != nil {
			return err
		}
	}
	file, err := os.CreateTemp(directory, ".journal-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), JournalPath(snapshot.Project, state))
}

func EventsAfter(snapshot Snapshot, cursor string) ([]Event, error) {
	sequence, err := ParseCursor(cursor)
	if err != nil {
		return nil, err
	}
	watermark, err := ParseCursor(snapshot.Cursor)
	if err != nil {
		return nil, err
	}
	if sequence > watermark {
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
