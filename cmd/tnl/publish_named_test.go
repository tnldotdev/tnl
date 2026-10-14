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

type stopAfterReady struct {
	bytes.Buffer
	stop context.CancelFunc
}

func (w *stopAfterReady) Write(data []byte) (int, error) {
	n, err := w.Buffer.Write(data)
	if bytes.Contains(data, []byte(`"type":"ready"`)) {
		w.stop()
	}
	return n, err
}

func TestNamedCLIStreamsOwnerEventsAndReleasesLease(t *testing.T) {
	id := "reg_0123456789abcdef0123456789abcdef"
	owner := "0123456789abcdef0123456789abcdef"
	target, publicURL := "127.0.0.1:5432", "orders.example:15432"
	tunnelID, ip, number := "tun_0123456789abcdefghijkl", "192.0.2.10", int64(1)
	hostname := "orders.example"
	released := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-owner" || r.Header.Get("Origin") != "" {
			t.Error("missing owner authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/publications":
			var request localpublisherv1.PublicationRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Owner != owner || request.Service != "orders" || request.Pid < 1 {
				t.Errorf("unexpected lease request: %+v", request)
			}
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.PublicationLease{PublicationId: id, Service: "orders", Cursor: "0", CurrentIp: &ip})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectSnapshot{Project: "/project", Cursor: "0", Services: []localpublisherv1.ServiceStatus{}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/events":
			if r.URL.Query().Get("after") != "0" {
				t.Errorf("resume cursor = %q", r.URL.Query().Get("after"))
			}
			starting := localpublisherv1.ServiceStatus{Service: "orders", Protocol: localpublisherv1.ServiceStatusProtocolPostgres,
				State: localpublisherv1.Publishing, Target: &target, PublicationId: &id, TunnelId: &tunnelID}
			ready := starting
			ready.State, ready.PublicUrl, ready.PublishRunNumber = localpublisherv1.Routable, &publicURL, &number
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectEventPage{Cursor: "3", Events: []localpublisherv1.ProjectEvent{
				{Cursor: "1", Type: "service.starting", Service: &starting.Service, Status: &starting},
				{Cursor: "2", Type: "publication.provisioning", Service: &starting.Service, Status: &starting,
					Publication: &localpublisherv1.PublicationEvent{Type: "provisioning", Hostname: &hostname, PublishRunNumber: &number}},
				{Cursor: "3", Type: "service.publication", Service: &ready.Service, Status: &ready},
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/publications/"+id:
			if r.Header.Get("X-Publication-Owner") != owner {
				t.Error("stop lost lease owner")
			}
			released = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stdout := &stopAfterReady{stop: cancel}
	output, err := newPublishOutput(publishOutputNDJSON, "tnl publish", stdout, &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := namedPublisherClient{endpoint: localPublisherEndpoint{URL: server.URL, Credential: "local-owner"}, http: &http.Client{Timeout: time.Second}}
	err = followNamedPublication(ctx, publishCommand{Service: "orders"}, client, owner, output, nil, telemetrySelfHosted)
	if !errors.Is(err, context.Canceled) || !released {
		t.Fatalf("publish termination = %v, released=%t", err, released)
	}
	if err := output.finish(ctx, err); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if output.provision != 1 {
		t.Fatalf("provisioning progress = %d", output.provision)
	}
	var types []string
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var event struct {
			Type     string `json:"type"`
			URL      string `json:"url"`
			TunnelID string `json:"tunnel_id"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		types = append(types, event.Type)
		if event.Type == "ready" && (event.URL != publicURL || event.TunnelID != tunnelID) {
			t.Fatalf("ready = %+v", event)
		}
	}
	if !slices.Equal(types, []string{"starting", "current_ip", "ready", "stopped"}) {
		t.Fatalf("output = %s", stdout.String())
	}
}

func TestNamedCLIRecoversReadyStatusWhenLeaseAlreadyExists(t *testing.T) {
	id, owner, target := "reg_0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef", "127.0.0.1:5432"
	tunnelID, publicURL, number := "tun_0123456789abcdefghijkl", "orders.example:15432", int64(2)
	stopped := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-owner" {
			t.Error("missing owner token")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/publications":
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.PublicationLease{PublicationId: id, Service: "orders", Cursor: "5"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			privateprotocol.Write(w, http.StatusOK, localpublisherv1.ProjectSnapshot{Project: "/project", Cursor: "5", Services: []localpublisherv1.ServiceStatus{{
				Service: "orders", Protocol: localpublisherv1.ServiceStatusProtocolPostgres, State: localpublisherv1.Routable,
				Target: &target, PublicUrl: &publicURL, PublicationId: &id, TunnelId: &tunnelID, PublishRunNumber: &number,
			}}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/publications/"+id:
			if r.Header.Get("X-Publication-Owner") != owner {
				t.Error("missing lease owner")
			}
			stopped = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stdout := &stopAfterReady{stop: cancel}
	output, err := newPublishOutput(publishOutputNDJSON, "tnl publish", stdout, &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := namedPublisherClient{endpoint: localPublisherEndpoint{URL: server.URL, Credential: "local-owner"}, http: &http.Client{Timeout: time.Second}}
	err = followNamedPublication(ctx, publishCommand{Service: "orders"}, client, owner, output, nil, telemetrySelfHosted)
	if !errors.Is(err, context.Canceled) || !stopped || !strings.Contains(stdout.String(), `"type":"ready"`) || !strings.Contains(stdout.String(), `"tunnel_id":"`+tunnelID+`"`) {
		t.Fatalf("reacquired ready lease = %v, stopped=%t, events=%s", err, stopped, stdout.String())
	}
}

func TestNamedCLIRejectsOverridesNotAppliedByOwner(t *testing.T) {
	for _, test := range []struct{ args, want []string }{
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
		if got := namedPublishOverrides(parsed); !slices.Equal(got, test.want) {
			t.Fatalf("%q: flags = %q, want %q", test.args, got, test.want)
		}
	}
}
