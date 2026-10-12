package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

type cancelOnReadyWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelOnReadyWriter) Write(data []byte) (int, error) {
	n, err := w.Buffer.Write(data)
	if bytes.Contains(data, []byte(`"type":"ready"`)) {
		w.cancel()
	}
	return n, err
}

func TestNamedPublisherCLIStreamsExistingPublishEventsAndReleasesOwner(t *testing.T) {
	id := "reg_0123456789abcdef0123456789abcdef"
	owner := "0123456789abcdef0123456789abcdef"
	tunnelID := "tun_0123456789abcdefghijkl"
	target := "127.0.0.1:5432"
	publicURL := "orders.example:15432"
	currentIP := "192.0.2.10"
	number := int64(1)
	released := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-owner" || r.Header.Get("Origin") != "" {
			t.Errorf("local publisher request lacked owner authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/publications":
			var request localpublisherv1.PublicationRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Owner != owner || request.Service != "orders" || request.Pid < 1 {
				t.Errorf("unexpected named publication request: %+v", request)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.PublicationLease{PublicationId: id, Service: "orders", Cursor: "0", CurrentIp: &currentIP})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/events":
			if r.URL.Query().Get("after") != "0" {
				t.Errorf("unexpected event cursor %q", r.URL.Query().Get("after"))
			}
			status := localpublisherv1.ServiceStatus{Service: "orders", Protocol: localpublisherv1.ServiceStatusProtocolPostgres,
				State: localpublisherv1.Publishing, Target: &target, PublicationId: &id, TunnelId: &tunnelID}
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectEventPage{Cursor: "2", Events: []localpublisherv1.ProjectEvent{
				{Cursor: "1", Type: "service.starting", Service: "orders", Status: &status},
				{Cursor: "2", Type: "publication.ready", Service: "orders", Status: &status,
					Publication: &localpublisherv1.PublicationEvent{Type: "ready", PublicUrl: &publicURL, PublishRunNumber: &number}},
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/publications/"+id:
			if r.Header.Get("X-Publication-Owner") != owner {
				t.Error("stop lost the publication owner")
			}
			released = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected local publisher call: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stdout := &cancelOnReadyWriter{cancel: cancel}
	output, err := newPublishOutput(publishOutputNDJSON, "tnl publish", stdout, &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := namedPublisherClient{endpoint: localPublisherEndpoint{URL: server.URL, Credential: "local-owner"},
		http: &http.Client{Timeout: time.Second}}
	err = followNamedPublication(ctx, publishCommand{Service: "orders"}, client, owner, output)
	if !errors.Is(err, context.Canceled) || !released {
		t.Fatalf("named publication termination = %v, released=%t", err, released)
	}
	if err := output.finish(ctx, err); !errors.Is(err, context.Canceled) {
		t.Fatalf("named publication output finish = %v", err)
	}
	var events []struct {
		Type             string `json:"type"`
		Cursor           int    `json:"cursor"`
		TunnelID         string `json:"tunnel_id"`
		URL              string `json:"url"`
		IP               string `json:"ip"`
		PublishRunNumber uint64 `json:"publish_run_number"`
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var event struct {
			Type             string `json:"type"`
			Cursor           int    `json:"cursor"`
			TunnelID         string `json:"tunnel_id"`
			URL              string `json:"url"`
			IP               string `json:"ip"`
			PublishRunNumber uint64 `json:"publish_run_number"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 4 || events[0].Type != "starting" || events[1].Type != "current_ip" ||
		events[2].Type != "ready" || events[3].Type != "stopped" || events[2].URL != publicURL ||
		events[2].PublishRunNumber != 1 || events[1].IP != currentIP {
		t.Fatalf("named publication events = %+v", events)
	}
	for index, event := range events {
		if event.Cursor != index+1 || event.TunnelID != tunnelID {
			t.Fatalf("named publication event %d = %+v", index, event)
		}
	}
}

func TestNamedPublicationReattachesAfterItsPublisherRestarts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		privateprotocol.Write(w, http.StatusConflict, localpublisherv1.Problem{
			Code: "runtime.registration_stale", Message: "publication belonged to an earlier publisher owner",
		})
	}))
	defer server.Close()
	client := namedPublisherClient{endpoint: localPublisherEndpoint{URL: server.URL, Credential: "owner"}, http: &http.Client{Timeout: time.Second}}
	err := client.request(t.Context(), http.MethodPost, "/v1/publications/old/renew", "0123456789abcdef0123456789abcdef", nil, nil)
	if !errors.Is(err, errNamedPublisherLost) || !namedPublisherConnectionLost(err) {
		t.Fatalf("stale owner publication was not retried: %v", err)
	}
}

func TestNamedPublisherRejectsOptionsThatWouldNotReachItsOwner(t *testing.T) {
	for _, test := range []struct {
		args []string
		want []string
	}{
		{[]string{"publish", "orders"}, nil},
		{[]string{"publish", "orders", "--output", "ndjson", "--open"}, nil},
		{[]string{"publish", "orders", "--protocol", "mysql", "--allow-all-ips"}, []string{"--allow-all-ips", "--protocol"}},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse(test.args)
		if err != nil {
			t.Fatal(err)
		}
		got := namedPublishOverrides(parsed)
		if !slices.Equal(got, test.want) {
			t.Fatalf("named publish args %q: overrides = %q, want %q", test.args, got, test.want)
		}
	}
}
