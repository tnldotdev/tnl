package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
)

func TestConnectionStartOwnerGoogleMetadataFromConfig(t *testing.T) {
	t.Setenv("TNL_SERVER", "")
	t.Setenv("TNL_CONFIG", "")
	for _, audience := range []string{"", "https://control.example/custom&key=value"} {
		name := "control audience"
		if audience != "" {
			name = "explicit audience"
		}
		t.Run(name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://github.com/fixture/shop.git"}} {
				if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
					t.Fatalf("fixture git: %v %s", err, output)
				}
			}
			configuration := map[string]any{"version": 1, "tnl": map[string]any{
				"server": "https://control.example", "team": "acme",
				"deployments": map[string]any{"remote": map[string]any{"targets": map[string]any{"api": map[string]any{"address": "http://unused.invalid:3000"}}}},
				"services":    map[string]any{"api": map[string]any{}},
				"workloads":   map[string]any{"job": map[string]any{"deployment": "remote", "google": map[string]any{"service_account": "112010400000000710080", "audience": audience}, "services": []string{"api"}}},
			}}
			data, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "tnl.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			options := OwnerStartOptions{ContextOptions: ContextOptions{Directory: root, Workload: "job"}, RunnerTemp: root}
			_, scope, err := connectionProject(t.Context(), options.ContextOptions)
			if err != nil {
				t.Fatal(err)
			}
			wantAudience := audience
			if wantAudience == "" {
				wantAudience = scope.Audience
			}
			var requests atomic.Int32
			metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.Host != "metadata.google.internal" || r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/identity" || r.URL.Query().Get("audience") != wantAudience || r.URL.Query().Get("format") != "full" || r.Header.Get("Metadata-Flavor") != "Google" || r.Header.Get("Authorization") != "" {
					t.Error("config startup changed the Google metadata request")
				}
				// reject at acquisition so no owner subprocess is launched.
				w.Header().Set("Metadata-Flavor", "Google")
				w.WriteHeader(http.StatusForbidden)
			}))
			defer metadata.Close()
			previous := http.DefaultTransport
			transport := previous.(*http.Transport).Clone()
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "metadata.google.internal:80" {
					return nil, errors.New("unexpected Google metadata destination")
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", metadata.Listener.Addr().String())
			}
			http.DefaultTransport = transport
			defer func() {
				http.DefaultTransport = previous
				transport.CloseIdleConnections()
			}()
			input, err := json.Marshal(connectorruntime.StartRequest{Schema: 1, Context: scope})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err = StartOwner(ctx, options, bytes.NewReader(input), io.Discard)
			if !errors.Is(err, workload.ErrAssertionUnavailable) || requests.Load() != 1 {
				t.Fatalf("Google config startup did not select metadata acquisition: requests=%d error=%v", requests.Load(), err)
			}
		})
	}
}
