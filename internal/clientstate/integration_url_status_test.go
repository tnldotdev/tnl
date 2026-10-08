package clientstate

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestIntegrationURLStatusUsesPublisherLeaseAndProjectIdentity(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	observed := now
	database.now = func() time.Time { return observed }
	const server, project = "https://control.example.test", "/projects/shop"
	// the service uses another namespace, but oauth remains on the project's
	// root namespace. the local project identity connects the two.
	group := project + "\x00app.member.example.test"
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: server, Target: "3000", Project: t.TempDir(),
		Service: "api", IntegrationGroup: group,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	const oauthHost = "oauth-shop-ab1234.root.member.example.test"
	if _, err := database.IntegrationURLHostname(t.Context(), server, project, "root.member.example.test", "oauth", oauthHost); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkIntegrationURLReady(t.Context(), server, oauthHost, "publisher"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := database.Snapshot(t.Context())
	if err != nil || len(snapshot.IntegrationURLs) != 1 || snapshot.IntegrationURLs[0].State != "ready" {
		t.Fatalf("ready project oauth = %#v, %v", snapshot.IntegrationURLs, err)
	}
	observed = now.Add(13 * time.Second)
	snapshot, err = database.Snapshot(t.Context())
	if err != nil || len(snapshot.IntegrationURLs) != 1 || snapshot.IntegrationURLs[0].State != "stale" ||
		snapshot.IntegrationURLs[0].Reason != failure.IntegrationURLLeaseExpired || snapshot.IntegrationURLs[0].Action == "" {
		t.Fatalf("expired publisher lease = %#v, %v", snapshot.IntegrationURLs, err)
	}
	if err := database.ClearIntegrationURLReady(t.Context(), server, oauthHost, "publisher"); err != nil {
		t.Fatal(err)
	}
	snapshot, err = database.Snapshot(t.Context())
	if err != nil || len(snapshot.IntegrationURLs) != 1 || snapshot.IntegrationURLs[0].State != "unavailable" ||
		snapshot.IntegrationURLs[0].Reason != failure.IntegrationURLNotReady {
		t.Fatalf("stopped publisher status = %#v, %v", snapshot.IntegrationURLs, err)
	}
}
