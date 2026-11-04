package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

func TestPrepareFixtureImage(t *testing.T) {
	for _, test := range []struct {
		name, stream, wantError string
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
	} {
		t.Run(test.name, func(t *testing.T) {
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
					if r.URL.Query().Get("tag") != strings.Split(postgresImage, "@")[1] {
						t.Error("pull lost the pinned digest")
					}
					fmt.Fprintln(w, test.stream)
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
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("prepare image: %v; want %q", err, test.wantError)
			}
			if pulls != test.wantPulls || inspects != test.wantInspects {
				t.Fatalf("pulls=%d inspects=%d; want %d/%d", pulls, inspects, test.wantPulls, test.wantInspects)
			}
		})
	}
}
