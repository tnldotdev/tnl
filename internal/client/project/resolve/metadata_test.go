package resolve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestEnvironmentConfigurationDoesNotFetchOrExposePrivateMetadata(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests++; w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "visitor-session")
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"http", "postgres", "kubernetes"} {
		address := "https://production.internal:6443"
		if protocol == "postgres" {
			address = "production.internal:5432"
		}
		project := clientproject.Project{Config: config.TNL{Server: &server.URL, Services: config.Services{"remote": {Protocol: &protocol}}, Environments: map[string]config.Environment{"production": {Targets: map[string]config.EnvironmentTarget{"remote": {Address: testTarget(address), TLS: &config.EnvironmentTargetTLS{}}}}}}}
		resolver := NewMetadataResolver(nil, project, nil)
		resolver.Seed(server.URL, &auth.Client{ServerEndpoint: server.URL, Control: control})
		metadata, err := resolver.Generate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(metadata)
		if err != nil || requests != 0 || len(metadata.Services) != 0 || strings.Contains(string(encoded), "production.internal") || strings.Contains(string(encoded), "visitor-session") {
			t.Fatalf("configuration fetched remote state or leaked management facts: %s, calls=%d: %v", encoded, requests, err)
		}
	}
}

func testTarget(value string) *config.Target { target := config.Target(value); return &target }
