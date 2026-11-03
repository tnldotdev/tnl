package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/detached"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
)

func detachedPresentationOwner(t *testing.T) (context.Context, string, string) {
	t.Helper()
	// unix socket paths must fit even when the checkout and macOS temp path are long.
	root, err := os.MkdirTemp("/tmp", "tnl-detached-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(root, "state")
	const id = "0123456789abcdef01234567"
	ctx, cleanup, err := detached.ServeWithOptions(t.Context(), root, id, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return ctx, root, id
}

func TestDetachedListAndStopPresentation(t *testing.T) {
	_, root, id := detachedPresentationOwner(t)
	var output bytes.Buffer
	if err := runDetachedList(detachedListCommand{StateDir: root}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), id) || !strings.Contains(output.String(), "booting") {
		t.Fatal("list omitted the pre-publication state", output.String())
	}
	output.Reset()
	flags := detachedStopCommand{detachedListCommand: detachedListCommand{StateDir: root}, ID: id}
	if err := runDetachedStop(flags, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), id) || !strings.Contains(output.String(), "stopping") {
		t.Fatal("stop omitted its result", output.String())
	}
	if err := runDetachedStop(flags, &output); err == nil {
		t.Fatal("duplicate stop was reported as a new successful stop")
	}
}

func TestDetachedConnectionPresentationPreservesEveryProtocol(t *testing.T) {
	for _, protocol := range []string{"http", "postgres", "mysql", "tcp", "kubernetes"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, root, id := detachedPresentationOwner(t)
			// the publisher/connector owns the payload; the detached owner only carries it.
			profile := connector.Profile{Schema: 1, Protocol: config.ProtocolName(protocol), Hostname: "approved.example.test", Host: "127.0.0.1", Port: 15432, Public: true, ConnectorRequired: true, Authentication: "connector"}
			detached.SetConnection(ctx, profile)
			var output bytes.Buffer
			if err := writeDetachedConnection(root, id, statusOutputJSON, &output); err == nil {
				t.Fatal("connection was printed before readiness")
			}
			detached.Ready(ctx)
			if err := writeDetachedConnection(root, id, statusOutputJSON, &output); err != nil {
				t.Fatal(err)
			}
			var got connector.Profile
			if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.DetachedID != id || got.Protocol != profile.Protocol || got.Host != profile.Host || got.Port != profile.Port || got.Hostname != profile.Hostname || !got.ConnectorRequired {
				t.Fatal("detached connection JSON changed", output.String(), err)
			}
		})
	}
}
