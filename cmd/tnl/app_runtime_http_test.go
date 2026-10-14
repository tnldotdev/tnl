package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func TestLocalProjectAPIUsesRegistrationOwnershipAndOneEventCursor(t *testing.T) {
	state := t.TempDir()
	manager, err := clientruntime.New(t.Context(), "/project", state,
		[]clientruntime.Service{{Name: "api"}, {Name: "web"}},
		func(ctx context.Context, _ clientruntime.Service, _ func(uint64, bool) error) error {
			<-ctx.Done()
			return ctx.Err()
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	owner := strings.Repeat("a", 32)
	id, err := manager.Reserve("api", owner, os.Getpid(), "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	a := &appRuntime{manager: manager, prepared: map[string]appPreparation{
		id: {assignment: privateprotocol.Assignment{Service: "api"}, framework: privateprotocol.FrameworkNode},
	}}
	handler := a.localHandler()
	call := func(method, path, body, scope, headerOwner string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if scope != "" {
			r = r.WithContext(context.WithValue(r.Context(), localPublisherScopeKey{}, scope))
		}
		if headerOwner != "" {
			r.Header.Set("X-Registration-Owner", headerOwner)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	before := manager.Snapshot().Cursor
	bound := `{"owner":"` + owner + `","target":"http://127.0.0.1:4321"}`
	if response := call(http.MethodPut, "/v1/registrations/"+id, bound, "web", ""); response.Code != http.StatusConflict {
		t.Fatalf("other app registered api: %d %s", response.Code, response.Body)
	}
	if response := call(http.MethodPut, "/v1/registrations/"+id, bound, "api", ""); response.Code != http.StatusNoContent {
		t.Fatalf("register = %d %s", response.Code, response.Body)
	}
	if response := call(http.MethodPost, "/v1/registrations/"+id+"/renew", "", "api", strings.Repeat("b", 32)); response.Code != http.StatusConflict {
		t.Fatalf("wrong owner renewed = %d %s", response.Code, response.Body)
	}
	status := call(http.MethodGet, "/v1/status", "", "", "")
	var snapshot localpublisherv1.ProjectSnapshot
	if err := json.Unmarshal(status.Body.Bytes(), &snapshot); err != nil || status.Code != http.StatusOK || len(snapshot.Services) != 2 || snapshot.Cursor != manager.Snapshot().Cursor {
		t.Fatalf("status = %d %s, %v", status.Code, status.Body, err)
	}
	pageResponse := call(http.MethodGet, "/v1/events?after="+before, "", "", "")
	var page localpublisherv1.ProjectEventPage
	if err := json.Unmarshal(pageResponse.Body.Bytes(), &page); err != nil || pageResponse.Code != http.StatusOK || len(page.Events) != 1 || page.Events[0].Type != "service.registered" || page.Cursor != snapshot.Cursor {
		t.Fatalf("events = %d %s, %v", pageResponse.Code, pageResponse.Body, err)
	}
	empty := call(http.MethodGet, "/v1/events?after="+page.Cursor, "", "", "")
	if err := json.Unmarshal(empty.Body.Bytes(), &page); err != nil || empty.Code != http.StatusOK || len(page.Events) != 0 || page.Cursor != snapshot.Cursor {
		t.Fatalf("empty events = %d %s, %v", empty.Code, empty.Body, err)
	}
	if response := call(http.MethodGet, "/v1/events?after=999999999", "", "", ""); response.Code != http.StatusGone {
		t.Fatalf("future cursor = %d %s", response.Code, response.Body)
	}
	if response := call(http.MethodPost, "/v1/registrations/"+id+"/renew", "", "api", owner); response.Code != http.StatusNoContent {
		t.Fatalf("renew = %d %s", response.Code, response.Body)
	}
	if response := call(http.MethodDelete, "/v1/registrations/"+id, "", "api", owner); response.Code != http.StatusNoContent {
		t.Fatalf("unregister = %d %s", response.Code, response.Body)
	}
}
