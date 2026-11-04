package meta

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestProjectMetadataConformance(t *testing.T) {
	data, err := os.ReadFile("../../../../api/fixtures/project-metadata-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int `json:"version"`
		Cases   []struct {
			Name     string          `json:"name"`
			Valid    bool            `json:"valid"`
			Metadata json.RawMessage `json:"metadata"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 2 || len(fixture.Cases) == 0 {
		t.Fatalf("unsupported or empty project metadata fixture: version %d", fixture.Version)
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			metadata, err := Parse(testCase.Metadata)
			if (err == nil) != testCase.Valid {
				t.Fatalf("metadata valid = %v, want %v (error: %v)", err == nil, testCase.Valid, err)
			}
			for name, service := range metadata.Services {
				endpoint, err := NewEndpoint(service.Namespace, service.Hostname, service.Protocol, service.Port, service.Public)
				if err != nil || endpoint.URL != service.URL {
					t.Fatalf("service %q constructor disagrees with the shared contract: %+v, error: %v", name, endpoint, err)
				}
			}
		})
	}
}

func TestEndpointPreservesPortAndExposureForEveryProtocol(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "mysql", "postgres", "kubernetes"} {
		for _, public := range []bool{false, true} {
			for _, port := range []int{1, 443, 15432, 65535} {
				t.Run(fmt.Sprintf("%s/public=%t/port=%d", protocol, public, port), func(t *testing.T) {
					service, err := NewEndpoint("member.example", "app.member.example", protocol, port, public)
					if err != nil {
						t.Fatal(err)
					}
					wantURL := ""
					if protocol == "http" || protocol == "kubernetes" {
						wantURL = "https://app.member.example"
						if port != 443 {
							wantURL += fmt.Sprintf(":%d", port)
						}
					}
					if service.Namespace != "member.example" || service.Hostname != "app.member.example" || service.Protocol != protocol || service.Port != port || service.Public != public || service.URL != wantURL {
						t.Fatalf("endpoint facts changed: %+v, want URL %q", service, wantURL)
					}
					metadata := Metadata{Version: Version, Namespace: service.Namespace, Services: map[string]Service{"app": service}}
					data, err := Render(metadata)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := Parse(data); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestEndpointRejectsUnassignedPortsAndInvalidProtocols(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "mysql", "postgres", "kubernetes"} {
		for _, port := range []int{-1, 0, 65536} {
			for _, public := range []bool{false, true} {
				if _, err := NewEndpoint("member.example", "app.member.example", protocol, port, public); err == nil {
					t.Fatalf("accepted %s endpoint with port %d and public=%t", protocol, port, public)
				}
			}
		}
	}
	for _, protocol := range []string{"", "ssh", "redis"} {
		if _, err := NewEndpoint("member.example", "app.member.example", protocol, 443, true); err == nil {
			t.Fatalf("accepted protocol %q", protocol)
		}
	}
}

func TestEndpointRequiresCanonicalDNSHostnames(t *testing.T) {
	for _, hostname := range []string{"", "INVALID.example", "app.example.", "127.0.0.1", "::1", "[::1]", "2001:db8::1", "[2001:db8::1]", "app.example:443"} {
		for _, protocol := range []string{"http", "kubernetes"} {
			for _, port := range []int{443, 15432} {
				if _, err := NewEndpoint("member.example", hostname, protocol, port, false); err == nil {
					t.Fatalf("accepted %s endpoint with hostname %q and port %d", protocol, hostname, port)
				}
			}
		}
	}
	if _, err := NewEndpoint("INVALID.example", "app.member.example", "http", 443, true); err == nil {
		t.Fatal("accepted a noncanonical namespace")
	}
}

func TestSavedAddressesRenderWithoutPrivateData(t *testing.T) {
	service, err := NewEndpoint("member.example", "web.member.example", "http", 443, true)
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{"web": service}}
	file, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"address", "target", "trust", "credential", "token", "private", "key"} {
		if strings.Contains(string(file), forbidden) {
			t.Fatalf("unsafe HTTP metadata: %s", file)
		}
	}
	if !strings.Contains(string(file), "https://web.member.example") {
		t.Fatalf("HTTP metadata lost its URL: %s", file)
	}
}

func TestPublicPathMountDoesNotNeedServiceTargetMetadata(t *testing.T) {
	service, err := NewEndpoint("member.example", "web.member.example", "http", 443, true)
	if err != nil {
		t.Fatal(err)
	}
	service.Paths = map[string]Path{"/api": {Service: "private-api", URL: service.URL + "/api", StripPrefix: true}}
	metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{"web": service}}
	file, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(file); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(file), "target") || strings.Contains(string(file), "private.internal") {
		t.Fatalf("private target leaked: %s", file)
	}
}
