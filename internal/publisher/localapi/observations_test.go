package localapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestInvocationEventsRetainClosedPublicationWithoutSiblingPayload(t *testing.T) {
	name := "ivk_0123456789ABCDEFGHIJKL"
	grant := publisherprotocol.Endpoint{Scope: "invocation", InvocationId: &name}
	own := publisherapp.Service{Name: name, TunnelID: "own-tunnel"}
	sibling := publisherapp.Service{Name: "private-sibling", TunnelID: "other-tunnel", Target: "http://private-sibling:1234"}
	snapshot := publisherapp.Snapshot{Services: []publisherapp.Service{own, sibling}, Publications: []clientstate.TunnelInfo{{ID: "own-tunnel"}, {ID: "other-tunnel", Target: "private-sibling"}}}
	now := time.Now()
	events := []publisherapp.Event{
		{Cursor: "first", Type: "service.registered", At: now, Service: &own},
		{Cursor: "hidden", Type: "private-sibling", At: now, Service: &sibling},
		{Cursor: "snapshot", Type: "snapshot", At: now, Snapshot: &snapshot},
		{Cursor: "own-stopped", Type: "tunnel.stopped", At: now, Publication: &clientstate.TunnelInfo{ID: "own-tunnel"}},
		{Cursor: "other-stopped", Type: "private-sibling", At: now, Publication: &clientstate.TunnelInfo{ID: "other-tunnel", Target: "private-sibling"}},
	}
	// current state no longer contains a tunnel binding after successful close.
	filtered := scopedEvents(events, grant, publisherapp.Snapshot{Services: []publisherapp.Service{{Name: name}}})
	encoded, err := json.Marshal(filtered)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-sibling") || strings.Contains(string(encoded), "other-tunnel") {
		t.Fatalf("sibling payload leaked: %s", encoded)
	}
	if len(filtered) != len(events) || filtered[1].Type != "cursor" || filtered[1].Cursor != "hidden" || !filtered[1].At.Equal(now) || filtered[3].Publication == nil || filtered[3].Publication.ID != "own-tunnel" {
		t.Fatalf("lost exclusive cursor or historical publication: %+v", filtered)
	}
	if len(snapshot.Services) != 2 || snapshot.Services[1].Name != "private-sibling" || len(snapshot.Publications) != 2 {
		t.Fatal("filter mutated the owner snapshot")
	}
}
