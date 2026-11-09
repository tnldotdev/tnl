package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestScopedChecksCannotProbeOrReturnSiblingPublications(t *testing.T) {
	for _, scope := range []string{"app", "invocation"} {
		t.Run(scope, func(t *testing.T) {
			server := httptest.NewUnstartedServer(nil)
			caps, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			name := "web"
			request := publisherprotocol.CapabilityRequest{Scope: "app", Service: &name}
			if scope == "invocation" {
				name = "ivk_0123456789abcdefghijkl"
				request = publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &name}
			}
			endpoint, err := caps.Issue(request)
			if err != nil {
				t.Fatal(err)
			}
			var checked [][]string
			snapshot := publisherapp.Snapshot{SchemaVersion: 1, Services: []publisherapp.Service{{Name: name, TunnelID: "own"}, {Name: "sibling", TunnelID: "other"}}, Publications: []clientstate.TunnelInfo{{ID: "own", Service: name}, {ID: "other", Service: "sibling"}}}
			server.Config.Handler = (&Server{Capabilities: caps, Check: func(_ context.Context, names []string) (publisherapp.Snapshot, error) {
				checked = append(checked, names)
				return snapshot, nil
			}}).Handler()
			server.Start()
			defer server.Close()
			var result publisherapp.Snapshot
			if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/check", publisherprotocol.Check{}, &result); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(checked, [][]string{{name}}) || len(result.Services) != 1 || result.Services[0].Name != name || len(result.Publications) != 1 || result.Publications[0].ID != "own" {
				t.Fatalf("unchecked scope: names=%v result=%+v", checked, result)
			}
			for _, names := range [][]string{{"sibling"}, {name, "sibling"}, {name, name}} {
				if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/check", publisherprotocol.Check{Services: &names}, nil); !errors.Is(err, publisherprotocol.ErrForbidden) {
					t.Fatalf("cross-scope check %v: %v", names, err)
				}
			}
			if len(checked) != 1 || len(snapshot.Services) != 2 || snapshot.Services[1].Name != "sibling" {
				t.Fatal("scope changed owner state or reached another probe")
			}
		})
	}
}

func TestScopedEventsAdvanceCursorWithoutDisclosingSiblingState(t *testing.T) {
	name := "web"
	grant := publisherprotocol.Endpoint{Scope: "app", Service: &name}
	private := publisherapp.Service{Name: "private-sibling", Target: "http://private-sibling:1234"}
	snapshot := publisherapp.Snapshot{Services: []publisherapp.Service{{Name: name}, private}, Publications: []clientstate.TunnelInfo{{Service: "private-sibling"}}}
	for _, event := range []publisherapp.Event{
		{Cursor: "next", Type: "private-sibling", At: time.Now(), Service: &private},
		{Cursor: "next", Type: "snapshot", At: time.Now(), Snapshot: &snapshot},
		{Cursor: "next", Type: "private-sibling", At: time.Now(), Publication: &clientstate.TunnelInfo{Service: "private-sibling"}},
	} {
		result := scopedEvent(event, grant, publisherapp.Snapshot{})
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "private-sibling") || result.Cursor != "next" || !result.At.Equal(event.At) {
			t.Fatalf("leaked event or lost cursor: %s", encoded)
		}
	}
	if len(snapshot.Services) != 2 || snapshot.Services[1].Name != "private-sibling" {
		t.Fatal("filter mutated owner snapshot")
	}
}

func TestScopedJournalKeepsExclusiveCursorAndExpiry(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager, err := publisherapp.New(t.Context(), root, database, []publisherapp.Service{{Name: "web"}, {Name: "sibling"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server := httptest.NewUnstartedServer(nil)
	caps, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	name := "web"
	endpoint, err := caps.Issue(publisherprotocol.CapabilityRequest{Scope: "app", Service: &name})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = (&Server{Capabilities: caps, Manager: manager, Database: database, Project: root}).Handler()
	server.Start()
	defer server.Close()
	cursor := manager.Snapshot().Cursor
	if _, err := manager.Reserve("sibling", "0123456789abcdef0123456789abcdef", 1, "https://sibling.example"); err != nil {
		t.Fatal(err)
	}
	var events []publisherapp.Event
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/events?after="+cursor, nil, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].Cursor == cursor {
		t.Fatal("hidden updates prevented cursor advancement")
	}
	for _, event := range events {
		if event.Service != nil || event.Publication != nil {
			t.Fatalf("sibling payload: %+v", event)
		}
	}
	var next []publisherapp.Event
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/events?after="+events[len(events)-1].Cursor, nil, &next); err != nil || len(next) != 0 {
		t.Fatalf("nonexclusive cursor: %+v %v", next, err)
	}
	var response *publisherprotocol.ResponseError
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/events?after=invalid", nil, nil); !errors.As(err, &response) || response.Code != "runtime.cursor_expired" {
		t.Fatalf("expired cursor: %v", err)
	}
}
