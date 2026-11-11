package invocation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestNamedPublicationRetainsLeaseCleanupFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"server":"https://control.example","services":{"web":{}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	project, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: path}, root, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	const registration = "registration_test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/leases":
			var lease publisherprotocol.Lease
			if err := json.NewDecoder(r.Body).Decode(&lease); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(publisherprotocol.Registration{Version: 1, Owner: lease.Owner, RegistrationID: registration})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(publisherapp.Snapshot{Services: []publisherapp.Service{{Name: "web", RegistrationID: registration, Target: "http://localhost:3000"}}})
		case "/v1/unregister":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"runtime.cleanup_failed"}`))
		default:
			t.Errorf("unexpected operation: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	capabilities, err := publisherprotocol.NewCapabilities(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	outputFailure := errors.New("output failed")
	err = PublishNamed(t.Context(), project, "web", filepath.Join(t.TempDir(), "state"), func(context.Context, clientproject.Project, string) (publisherprotocol.Endpoint, error) {
		return capabilities.Owner(), nil
	}, &Presentation{Starting: func(string, string) error { return outputFailure }})
	var cleanup *publisherprotocol.ResponseError
	if !errors.Is(err, outputFailure) || !errors.As(err, &cleanup) || cleanup.Status != http.StatusServiceUnavailable {
		t.Fatalf("publication lost an operation or cleanup failure: %v", err)
	}
}
