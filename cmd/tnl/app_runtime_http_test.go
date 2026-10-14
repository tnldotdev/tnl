package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func TestLocalProjectAPIUsesRegistrationOwnershipAndOneEventCursor(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
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

func TestLocalOwnerEventsResumeDirectPublicationFromAnotherWriter(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	project := t.TempDir()
	manager, err := clientruntime.New(t.Context(), project, state, []clientruntime.Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	before := manager.Snapshot().Cursor
	db, err := clientstate.Open(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tunnel, err := db.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: project,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	handler := (&appRuntime{manager: manager}).localHandler()
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	status := request("/v1/status")
	var snapshot localpublisherv1.ProjectSnapshot
	if err := json.Unmarshal(status.Body.Bytes(), &snapshot); err != nil || status.Code != http.StatusOK || snapshot.Cursor != "2" {
		t.Fatalf("owner status = %d %s, %v", status.Code, status.Body, err)
	}
	pageResponse := request("/v1/events?after=" + before)
	var page localpublisherv1.ProjectEventPage
	if err := json.Unmarshal(pageResponse.Body.Bytes(), &page); err != nil || pageResponse.Code != http.StatusOK || len(page.Events) != 1 || page.Events[0].Type != "tunnel.starting" || page.Cursor != snapshot.Cursor {
		t.Fatalf("owner resume = %d %s, %v", pageResponse.Code, pageResponse.Body, err)
	}
}

func TestNamedOwnerAPIAndDirectTunnelShareExclusiveCursor(t *testing.T) {
	a, stateDir, started := testAppRuntime(t)
	protocol := "postgres"
	target := config.Target("127.0.0.1:5432")
	a.project.Config.Services["orders"] = config.Service{Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &target}}
	a.project.RelativeServiceDirectories["orders"] = "."
	if err := a.manager.Configure(configuredRuntimeServices(a.project)); err != nil {
		t.Fatal(err)
	}
	before := a.manager.Snapshot().Cursor
	owner := strings.Repeat("a", 32)
	id, err := a.manager.Reserve("orders", owner, os.Getpid(), "orders.example:15432")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RegisterNamed(id, owner, string(target)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("named publication did not start")
	}
	if err := a.manager.Started(id, string(target), "tun_named"); err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RecordPublication(id, string(target), clientruntime.PublicationEvent{
		Type: "provisioning", Hostname: "orders.example", PublishRunNumber: 1,
	}); err != nil {
		t.Fatal(err)
	}
	db, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	direct, err := db.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:3306",
		ServiceProtocol: controlv1.Mysql, Project: a.project.Root,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Finish(context.Background(), nil)
	if _, err := a.manager.Reserve("api", "app-owner", os.Getpid(), "https://api.example"); err != nil {
		t.Fatal(err)
	}
	handler := a.localHandler()
	request := func(method, path, headerOwner string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, nil)
		if headerOwner != "" {
			r.Header.Set("X-Publication-Owner", headerOwner)
		}
		handler.ServeHTTP(w, r)
		return w
	}
	status := request(http.MethodGet, "/v1/status", "")
	var snapshot localpublisherv1.ProjectSnapshot
	if err := json.Unmarshal(status.Body.Bytes(), &snapshot); err != nil || status.Code != http.StatusOK {
		t.Fatalf("status = %d %s: %v", status.Code, status.Body, err)
	}
	var named *localpublisherv1.ServiceStatus
	for i := range snapshot.Services {
		if snapshot.Services[i].Service == "orders" {
			named = &snapshot.Services[i]
		}
	}
	if named == nil || named.PublicationId == nil || *named.PublicationId != id || named.TunnelId == nil || *named.TunnelId != "tun_named" {
		t.Fatalf("named status = %+v", snapshot.Services)
	}
	pageResponse := request(http.MethodGet, "/v1/events?after="+before, "")
	var page localpublisherv1.ProjectEventPage
	if err := json.Unmarshal(pageResponse.Body.Bytes(), &page); err != nil || pageResponse.Code != http.StatusOK {
		t.Fatalf("events = %d %s: %v", pageResponse.Code, pageResponse.Body, err)
	}
	if len(page.Events) != 7 || page.Events[0].Type != "service.prepared" || page.Events[1].Type != "service.registered" ||
		page.Events[2].Type != "service.publication" || page.Events[3].Type != "service.starting" ||
		page.Events[4].Type != "publication.provisioning" || page.Events[4].Publication == nil ||
		page.Events[4].Publication.Hostname == nil || *page.Events[4].Publication.Hostname != "orders.example" ||
		page.Events[5].Type != "tunnel.starting" || page.Events[6].Type != "service.prepared" || page.Cursor != snapshot.Cursor {
		t.Fatalf("mixed project events = %+v", page)
	}
	previous, err := clientruntime.ParseCursor(before)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range page.Events {
		current, err := clientruntime.ParseCursor(event.Cursor)
		if err != nil || current != previous+1 {
			t.Fatalf("cursor after %d = %q: %v", previous, event.Cursor, err)
		}
		previous = current
	}
	watchCtx, stopWatch := context.WithTimeout(t.Context(), time.Second)
	defer stopWatch()
	var output bytes.Buffer
	if err := runAppWatch(watchCtx, a.project, stateDir, watchCommand{After: before, Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != len(page.Events) {
		t.Fatalf("watch resumed %d events, owner returned %d: %s", len(lines), len(page.Events), output.String())
	}
	for i, line := range lines {
		var event clientruntime.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil || event.Cursor != page.Events[i].Cursor || event.Type != page.Events[i].Type {
			t.Fatalf("watch event %d after %s: %s, %v", i, strconv.FormatUint(previous, 10), line, err)
		}
	}
	if response := request(http.MethodPost, "/v1/publications/"+id+"/renew", strings.Repeat("b", 32)); response.Code != http.StatusConflict {
		t.Fatalf("unowned renewal = %d", response.Code)
	}
	if response := request(http.MethodPost, "/v1/publications/"+id+"/renew", owner); response.Code != http.StatusNoContent {
		t.Fatalf("renew = %d", response.Code)
	}
	if response := request(http.MethodDelete, "/v1/publications/"+id, owner); response.Code != http.StatusNoContent {
		t.Fatalf("stop = %d %s", response.Code, response.Body)
	}
	if a.manager.Current("orders", id, string(target), 1) {
		t.Fatal("stopped named lease admits visitors")
	}
	if response := request(http.MethodPost, "/v1/publications/"+id+"/renew", owner); response.Code != http.StatusConflict {
		t.Fatalf("stale renewal = %d", response.Code)
	}
}
