package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/api/pkg/authconfig"
	"github.com/moby/moby/client"
)

func TestPrepareFixtureImage(t *testing.T) {
	// auth discovery asks the daemon for its default registry; keep that lookup
	// local and isolate Docker configuration from the developer's credentials.
	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/info") {
			t.Errorf("unexpected registry lookup: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, `{"IndexServerAddress":"https://index.docker.io/v1/"}`)
	}))
	defer registryServer.Close()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DOCKER_HOST", registryServer.URL)
	t.Setenv("DOCKER_API_VERSION", "1.56")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", "/var/run/docker.sock")
	t.Setenv("DOCKER_AUTH_CONFIG", "")

	for _, test := range []struct {
		name, stream, wantError string
		config, envConfig       string
		helper                  string
		wantUser, wantPassword  string
		wantIdentityToken       string
		present, installed      bool
		inspectStatus           int
		wantPulls, wantInspects int
	}{
		{name: "cached", present: true, wantInspects: 1},
		{name: "pulled", stream: `{"status":"download complete"}`, installed: true, wantPulls: 1, wantInspects: 2},
		{name: "daemon error in successful HTTP response", stream: `{"status":"pulling"}` + "\n" + `{"errorDetail":{"message":"registry unavailable"},"error":"registry unavailable"}`, wantError: "registry unavailable", wantPulls: 1, wantInspects: 1},
		{name: "truncated progress", stream: `{"status":`, wantError: "unexpected EOF", wantPulls: 1, wantInspects: 1},
		{name: "not installed", stream: `{"status":"download complete"}`, wantError: "after pull", wantPulls: 1, wantInspects: 2},
		{name: "inspect failure", inspectStatus: 500, wantError: "inspect disposable service image", wantInspects: 1},
		{name: "Docker config credentials", config: `{"auths":{"https://index.docker.io/v1/":{"auth":"Zml4dHVyZTpmaXh0dXJlLXNlY3JldA=="}}}`, wantUser: "fixture", wantPassword: "fixture-secret", installed: true, wantPulls: 1, wantInspects: 2},
		{name: "identity token", config: `{"auths":{"https://index.docker.io/v1/":{"identitytoken":"fixture-secret"}}}`, wantIdentityToken: "fixture-secret", installed: true, wantPulls: 1, wantInspects: 2},
		{name: "environment config overrides file", config: `{"auths":{"https://index.docker.io/v1/":{"username":"file-user","password":"file-secret"}}}`, envConfig: `{"auths":{"https://index.docker.io/v1/":{"username":"fixture","password":"fixture-secret"}}}`, wantUser: "fixture", wantPassword: "fixture-secret", installed: true, wantPulls: 1, wantInspects: 2},
		{name: "unrelated registry credentials", config: `{"auths":{"registry.example.test":{"username":"fixture","password":"fixture-secret"}}}`, installed: true, wantPulls: 1, wantInspects: 2},
		{name: "registry credential helper", config: `{"credHelpers":{"https://index.docker.io/v1/":"fixture"}}`, helper: `printf '%s' '{"Username":"fixture","Secret":"fixture-secret"}'`, wantUser: "fixture", wantPassword: "fixture-secret", installed: true, wantPulls: 1, wantInspects: 2},
		{name: "credential store", config: `{"auths":{"https://index.docker.io/v1/":{}},"credsStore":"fixture"}`, helper: `printf '%s' '{"Username":"fixture","Secret":"fixture-secret"}'`, wantUser: "fixture", wantPassword: "fixture-secret", installed: true, wantPulls: 1, wantInspects: 2},
		{name: "empty credential store", config: `{"auths":{"https://index.docker.io/v1/":{}},"credsStore":"empty"}`, helper: `printf '%s' 'credentials not found in native keychain'; exit 1`, installed: true, wantPulls: 1, wantInspects: 2},
		{name: "broken credential helper", config: `{"credHelpers":{"https://index.docker.io/v1/":"broken"}}`, helper: `printf '%s' 'fixture-secret'; exit 1`, wantError: "check Docker configuration and credential helpers", wantInspects: 1},
		{name: "malformed config", config: `{"auths":`, wantError: "check Docker configuration and credential helpers", wantInspects: 1},
		{name: "cached without credential lookup", config: `{"auths":`, present: true, wantInspects: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DOCKER_CONFIG", dir)
			t.Setenv("DOCKER_AUTH_CONFIG", test.envConfig)
			if test.config != "" {
				if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(test.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.helper != "" {
				script := "#!/bin/sh\n[ \"$1\" = get ] || exit 2\nhost=$(cat)\n[ \"$host\" = https://index.docker.io/v1/ ] || exit 3\n" + test.helper + "\n"
				for _, name := range []string{"fixture", "empty", "broken"} {
					if err := os.WriteFile(filepath.Join(dir, "docker-credential-"+name), []byte(script), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			}
			var pulls, inspects int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/json"):
					inspects++
					if test.inspectStatus != 0 {
						w.WriteHeader(test.inspectStatus)
						fmt.Fprintln(w, `{"message":"daemon unavailable"}`)
					} else if test.present || pulls > 0 && test.installed {
						fmt.Fprintln(w, `{"Id":"sha256:fixture"}`)
					} else {
						w.WriteHeader(http.StatusNotFound)
						fmt.Fprintln(w, `{"message":"image not found"}`)
					}
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/images/create"):
					pulls++
					if r.URL.Query().Get("fromImage") != "docker.io/library/postgres" {
						t.Error("pull did not use Docker Hub directly")
					}
					if r.URL.Query().Get("tag") != strings.Split(postgresImage, "@")[1] {
						t.Error("pull lost the pinned digest")
					}
					auth, err := authconfig.Decode(r.Header.Get("X-Registry-Auth"))
					if err != nil || auth.Username != test.wantUser || auth.Password != test.wantPassword || auth.IdentityToken != test.wantIdentityToken {
						t.Error("pull did not forward the selected registry credentials")
					}
					stream := test.stream
					if stream == "" {
						stream = `{"status":"download complete"}`
					}
					fmt.Fprintln(w, stream)
				default:
					t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			cli, err := client.NewClientWithOpts(client.WithHost(server.URL), client.WithAPIVersion("1.56"))
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			err = prepareImage(t.Context(), cli, postgresImage)
			if err != nil && strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("prepare image error exposed registry credentials")
			}
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("prepare image: %v; want %q", err, test.wantError)
			}
			if pulls != test.wantPulls || inspects != test.wantInspects {
				t.Fatalf("pulls=%d inspects=%d; want %d/%d", pulls, inspects, test.wantPulls, test.wantInspects)
			}
		})
	}
}
