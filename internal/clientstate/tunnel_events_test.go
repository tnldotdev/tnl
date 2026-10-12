package clientstate

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestDatabaseTunnelEventsResumeAcrossStateOpens(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	owner, err := Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	project := t.TempDir()
	tunnel, err := owner.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:5432",
		Project: project, Service: "orders", ServiceProtocol: controlv1.Postgres,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	if err := tunnel.SetPublicURL(t.Context(), testPublicURLID, "orders.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "orders.example:15432", 1); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	latest, err := reader.LatestTunnelEventCursor(t.Context(), project)
	if err != nil || latest != 3 {
		t.Fatalf("database cursor = %d, %v", latest, err)
	}
	events, err := reader.TunnelEventsAfter(t.Context(), project, 1)
	if err != nil || len(events) != 2 || events[0].Hostname != "orders.example" ||
		events[1].Sequence != 3 || events[1].State != TunnelStateReady || events[1].PublicPort != 15432 {
		t.Fatalf("resumed database events = %#v, %v", events, err)
	}
	other, err := reader.LatestTunnelEventCursor(t.Context(), t.TempDir())
	if err != nil || other != 0 {
		t.Fatalf("other project cursor = %d, %v", other, err)
	}
	if _, err := reader.TunnelEventsAfter(t.Context(), project, 4); !errors.Is(err, ErrTunnelCursorExpired) {
		t.Fatalf("future database cursor = %v", err)
	}
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	events, err = reader.TunnelEventsAfter(t.Context(), project, latest)
	if err != nil || len(events) != 1 || events[0].State != TunnelStateStopped {
		t.Fatalf("stopped database event = %#v, %v", events, err)
	}
}

func TestPrivateTCPServiceEventsIncludeEverySupportedProtocol(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Redis, controlv1.Ssh} {
		t.Run(string(protocol), func(t *testing.T) {
			database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			project := t.TempDir()
			tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
				Command: TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:6379",
				Project: project, Service: "cache", ServiceProtocol: protocol,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Finish(context.Background(), nil)
			if err := tunnel.SetPublicURL(t.Context(), testPublicURLID, "cache.example"); err != nil {
				t.Fatal(err)
			}
			if err := tunnel.SetReady(t.Context(), "cache.example:16379", 1); err != nil {
				t.Fatal(err)
			}
			events, err := database.TunnelEventsAfter(t.Context(), project, 0)
			if err != nil || len(events) != 3 || events[2].State != TunnelStateReady ||
				events[2].ServiceProtocol != protocol || events[2].PublicPort != 16379 {
				t.Fatalf("%s events = %#v, %v", protocol, events, err)
			}
		})
	}
}

func TestDatabaseTunnelEventsBoundRetentionAndExpireOldCursor(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project := t.TempDir()
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:5432",
		Project: project, Service: "orders", ServiceProtocol: controlv1.Postgres,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	if err := tunnel.SetPublicURL(t.Context(), testPublicURLID, "orders.example"); err != nil {
		t.Fatal(err)
	}
	for number := uint64(1); number <= 2050; number++ {
		if err := tunnel.SetReady(t.Context(), "orders.example:15432", number); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.TunnelEventsAfter(t.Context(), project, 0); !errors.Is(err, ErrTunnelCursorExpired) {
		t.Fatalf("expired database cursor = %v", err)
	}
	latest, err := database.LatestTunnelEventCursor(t.Context(), project)
	if err != nil || latest != 2052 {
		t.Fatalf("latest cursor = %d, %v", latest, err)
	}
	events, err := database.TunnelEventsAfter(t.Context(), project, 4)
	if err != nil || len(events) != 2048 || events[0].Sequence != 5 || events[2047].Sequence != latest {
		t.Fatalf("retained database events = %d, %v", len(events), err)
	}
}
