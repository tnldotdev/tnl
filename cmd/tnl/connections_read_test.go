package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestConnectionReadUsesOnlyExistingPreparedOwner(t *testing.T) {
	for _, scenario := range []string{"ready", "expired-handle", "expired-owner", "expired-snapshot", "invalid-schema", "bare-snapshot", "canceled", "denied"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("TNL_STATE_DIR", filepath.Join(root, "must-not-authenticate"))
			t.Setenv("TNL_SERVER", "https://must-not-contact.invalid")
			calls := 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			key, digest := strings.Repeat("a", 64), strings.Repeat("b", 64)
			owner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var request connectionruntime.Request
				if connectionruntime.ReadJSON(r.Body, &request) != nil || r.Method != "POST" || r.URL.Path != "/v1/connections/prepared" || r.Header.Get("Authorization") != "Bearer "+key || request.Schema != 1 || request.Service != "database" || request.Directory != root || request.ConfigDigest != digest {
					t.Error("read changed the prepared owner's exact scope")
				}
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "expired-owner":
					w.WriteHeader(410)
					return
				case "denied":
					w.WriteHeader(503)
					return
				case "canceled":
					cancel()
					<-r.Context().Done()
					return
				}
				expires := time.Now().Add(time.Hour)
				if scenario == "expired-snapshot" {
					expires = time.Now().Add(-time.Second)
				}
				snapshot := connectionruntime.Connection{Schema: 1, Protocol: "postgres", Host: "127.0.0.1", Port: 15432, SSL: &connectionruntime.TLSOptions{ServerName: "approved.example.test", RejectUnauthorized: true}, ExpiresAt: expires}
				if scenario == "bare-snapshot" {
					_ = json.NewEncoder(w).Encode(snapshot)
					return
				}
				prepared := connectionruntime.Prepared{Schema: 1, PublicRuntime: projectmeta.PublicMetadata{Namespace: "example.test", Services: map[string]projectmeta.Service{"database": {Protocol: "postgres", Namespace: "example.test", Hostname: "approved.example.test", Port: 15432, Public: true}}}, Connection: snapshot}
				if scenario == "invalid-schema" {
					prepared.Schema = 2
				}
				_ = json.NewEncoder(w).Encode(prepared)
			}))
			defer owner.Close()
			directory, err := connectionruntime.NewDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "handle.json")
			expires := time.Now().Add(time.Hour)
			if scenario == "expired-handle" {
				expires = time.Now().Add(-time.Second)
			}
			if err := connectionruntime.WriteHandle(path, connectionruntime.Handle{Schema: 1, URL: owner.URL, Key: key, Directory: root, ConfigDigest: digest, ExpiresAt: expires, Executable: "/absolute/tnl"}); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = run(ctx, []string{"runtime", "connections", "read", "--handle", path, "--service", "database"}, &output, &output)
			if scenario == "ready" {
				var prepared connectionruntime.Prepared
				if err != nil || connectionruntime.ReadJSON(&output, &prepared) != nil || prepared.Schema != 1 || prepared.Connection.Host != "127.0.0.1" || prepared.Connection.Port != 15432 || prepared.Connection.SSL == nil || prepared.Connection.SSL.ServerName != "approved.example.test" || prepared.PublicRuntime.Services["database"].Hostname != prepared.Connection.SSL.ServerName {
					t.Fatal("read lost the prepared snapshot", err, output.String())
				}
			} else {
				want := failure.ConnectionExpired
				if scenario == "denied" || scenario == "canceled" {
					want = failure.ConnectionUnavailable
				}
				if scenario == "invalid-schema" || scenario == "bare-snapshot" {
					want = failure.ConnectionRequestInvalid
				}
				if reason, _ := failure.ReasonOf(err); reason != want || output.Len() != 0 {
					t.Fatal("read lost owned error or emitted stale readiness", err, output.String())
				}
				if scenario == "canceled" && !errors.Is(err, context.Canceled) {
					t.Fatal("read lost cancellation cause", err)
				}
			}
			owner.Close()
			if scenario == "expired-handle" && calls != 0 || scenario != "expired-handle" && calls != 1 {
				t.Fatal("read started or retried an owner", calls)
			}
			if _, err := os.Lstat(os.Getenv("TNL_STATE_DIR")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("prepared read attempted authentication")
			}
		})
	}
}
