package state

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestKnownProjectURLsSurviveTunnelStopAndStayBounded(t *testing.T) {
	db, err := OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example.test"
	tunnel, err := db.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: server, Project: project, Target: "http://127.0.0.1:3000", ServiceProtocol: controlv1.Http})
	if err != nil {
		t.Fatal(err)
	}
	const first = "url_0123456789abcdefghijkl"
	if err := tunnel.SetPublicURL(t.Context(), first, "web.member.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Finish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ids, err := db.KnownProjectPublicURLs(t.Context(), project, server)
	if err != nil || len(ids) != 1 || ids[0] != first {
		t.Fatalf("stopped tunnel lost saved URL: %v, %v", ids, err)
	}
	for _, selection := range []struct{ project, server string }{{t.TempDir(), server}, {project, "https://another.example.test"}} {
		foreign, err := db.KnownProjectPublicURLs(t.Context(), selection.project, selection.server)
		if err != nil || len(foreign) != 0 {
			t.Fatalf("locally known URLs crossed projects or servers: %v, %v", foreign, err)
		}
	}
	// repeated temporary publications cannot make local status grow without bound.
	base := time.Now().UnixNano()
	for i := range 260 {
		if _, err := db.db.ExecContext(t.Context(), `UPDATE local_tunnels SET public_url_id = ?, updated_at = ? WHERE id = ?`, fmt.Sprintf("url_%022d", i), base+int64(i), tunnel.ID()); err != nil {
			t.Fatal(err)
		}
	}
	ids, err = db.KnownProjectPublicURLs(t.Context(), project, server)
	if err != nil || len(ids) != 256 {
		t.Fatalf("unbounded project URL inventory: %d, err=%v", len(ids), err)
	}
	if ids[0] != "url_0000000000000000000259" {
		t.Fatalf("latest project URL is %q", ids[0])
	}
}
