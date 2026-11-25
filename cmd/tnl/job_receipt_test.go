package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/background"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func launchBackgroundPresentation(t *testing.T, root string, kind background.Kind, ready background.Readiness, receipt func(background.Entry) error) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupBackgroundJobs(t, root) })
	var id string
	if err := background.Launch(t.Context(), background.LaunchOptions{
		StateDir: root, Kind: kind, Binary: binary, Payload: payload,
		Args: []string{"-test.run=^TestBackgroundPresentationChild$", "-tnl-background-presentation-fixture"},
	}, func(_ context.Context, entry background.Entry) error {
		id = entry.JobID
		// status cannot advertise readiness or reveal a client profile before
		// the launcher commits the receipt.
		status, err := background.Status(t.Context(), root, id)
		if err != nil || status.State != background.StateStarting || len(status.Profile) != 0 {
			return fmt.Errorf("background handoff already appears ready: %+v (%v)", status, err)
		}
		return receipt(entry)
	}); err != nil {
		t.Fatal(err)
	}
	if !opaqueid.Valid(id, opaqueid.JobPrefix) {
		t.Fatalf("invalid job ID %q", id)
	}
	return id
}

func TestBackgroundListAndStopPresentation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "client")
	supervisorParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	supervisor := filepath.Join(supervisorParent, "supervisor")
	invoke := func(output io.Writer, args ...string) error {
		return run(t.Context(), append(args, "--state-dir", root, "--system-state-dir", supervisor, "--output=human"), output, io.Discard)
	}
	var output bytes.Buffer
	id := launchBackgroundPresentation(t, root, background.KindPublish, background.Readiness{Address: "https://example.test"}, func(entry background.Entry) error {
		if err := invoke(&output, "status", "--bg"); err != nil {
			return err
		}
		if !strings.Contains(output.String(), entry.JobID) || !strings.Contains(output.String(), "starting") {
			return fmt.Errorf("list omitted the pre-handoff state: %s", &output)
		}
		return nil
	})
	output.Reset()
	if err := invoke(&output, "stop", id); err != nil {
		t.Fatal(err)
	}
	if output.String() != "Stopped "+id+".\n" && output.String() != "Requested stop for "+id+".\n" {
		t.Fatal("stop omitted its result", output.String())
	}
	waitBackgroundJobExit(t, t.Context(), root, id)
	output.Reset()
	if err := invoke(&output, "stop", id); err == nil || output.Len() != 0 {
		t.Fatal("duplicate stop was reported as a new successful stop")
	}
}

func TestBackgroundConnectionReceiptPreservesEveryProtocol(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolTCP, config.ProtocolKubernetes} {
		t.Run(string(protocol), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "client")
			// the connector owns the profile; the background owner only carries it.
			profile := connector.Profile{Schema: 1, Protocol: protocol, Hostname: "approved.example.test", Host: "127.0.0.1", Port: 15432, Public: true, ConnectorRequired: true, Authentication: "connector"}
			raw, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			var output, diagnostics bytes.Buffer
			id := launchBackgroundPresentation(t, root, background.KindConnect, background.Readiness{Address: "127.0.0.1:15432", Profile: raw},
				func(entry background.Entry) error {
					return writeBackgroundReceipt(&output, &diagnostics, entry, root, true)
				})
			var got connector.Profile
			if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.JobID != id || got.Schema != profile.Schema ||
				got.Protocol != profile.Protocol || got.Host != profile.Host || got.Port != profile.Port ||
				got.Hostname != profile.Hostname || !got.ConnectorRequired || got.Authentication != profile.Authentication || diagnostics.Len() != 0 {
				t.Fatalf("background connection JSON changed: %s (%v)\n%s", &output, err, &diagnostics)
			}
		})
	}
}

func TestBackgroundGuestReceiptUsesPrivateVisitURL(t *testing.T) {
	const id = "job_0123456789abcdefghijkl"
	const guestURL = "https://trial.example/__tnl/share/fixture-only"
	entry := background.Entry{JobID: id, Kind: background.KindPublish, Readiness: background.Readiness{
		Address: "https://trial.example", GuestEntryURL: guestURL,
	}}
	for _, machine := range []bool{false, true} {
		var output, diagnostics bytes.Buffer
		if err := writeBackgroundReceipt(&output, &diagnostics, entry, "", machine); err != nil {
			t.Fatal(err)
		}
		if machine {
			var receipt struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(output.Bytes(), &receipt); err != nil || receipt.URL != guestURL || diagnostics.Len() != 0 {
				t.Fatal("machine receipt did not reserve the guest visit URL for its own stdout")
			}
		} else if output.String() != guestURL+"\n" || diagnostics.String() != "To stop:\ntnl stop "+id+"\n" {
			t.Fatal("human receipt did not reserve the guest visit URL for its own stdout")
		}
	}
}

var backgroundPresentationFixture = flag.Bool("tnl-background-presentation-fixture", false, "run the background presentation test child")

func TestBackgroundPresentationChild(t *testing.T) {
	if !*backgroundPresentationFixture {
		return
	}
	if err := background.RunChild(t.Context(), func(ctx context.Context, spec background.Bootstrap) error {
		var ready background.Readiness
		if err := json.Unmarshal(spec.Payload, &ready); err != nil {
			return err
		}
		if err := background.Ready(ctx, ready); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
