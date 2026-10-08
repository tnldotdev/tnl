package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestDevSocketDigestGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "dev-socket-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		ProjectRoot string `json:"projectRoot"`
		Service     string `json:"service"`
		Digest      string `json:"digest"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		if got := devSocketDigest(vector.ProjectRoot, vector.Service); got != vector.Digest {
			t.Fatalf("digest(%q, %q) = %q, want %q", vector.ProjectRoot, vector.Service, got, vector.Digest)
		}
	}
}

func TestDevProtocolUsesExplicitNullForAdHocService(t *testing.T) {
	data, err := json.Marshal(devConfigurationResponse{
		Protocol: 1, TunnelID: "tun_0123456789abcdefghijkl",
		Namespace: "member.example", Hostname: "route.member.example", PublicURL: "https://route.member.example",
		Project: projectmeta.PublicMetadata{Namespace: "member.example", Services: map[string]projectmeta.Service{}, Dev: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"protocol": float64(1), "tunnelID": "tun_0123456789abcdefghijkl", "service": nil,
		"namespace": "member.example", "hostname": "route.member.example", "publicURL": "https://route.member.example",
		"project": map[string]any{"namespace": "member.example", "services": map[string]any{}, "dev": true},
	}
	if !reflect.DeepEqual(wire, want) {
		t.Fatalf("wire response = %s, want %#v", data, want)
	}
}

func TestDevProtocolWireFixture(t *testing.T) {
	data, err := os.ReadFile("../../api/fixtures/dev-protocol-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version              int                     `json:"version"`
		Configuration        json.RawMessage         `json:"configuration"`
		InvalidConfiguration devConfigurationRequest `json:"invalidConfiguration"`
		Target               json.RawMessage         `json:"target"`
		InvalidTarget        devTargetRequest        `json:"invalidTarget"`
		Assignment           json.RawMessage         `json:"assignment"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 {
		t.Fatalf("unsupported dev protocol fixture version %d", fixture.Version)
	}
	if validFrameworkName(fixture.InvalidConfiguration.Framework) {
		t.Fatalf("invalid configuration accepted: %#v", fixture.InvalidConfiguration)
	}
	if _, err := localproxy.NormalizeTarget(fixture.InvalidTarget.Target); err == nil {
		t.Fatalf("invalid target accepted: %#v", fixture.InvalidTarget)
	}
	for _, testCase := range []struct {
		name  string
		value any
		want  json.RawMessage
	}{
		{"configuration", devConfigurationRequest{Protocol: 1, Framework: "vite"}, fixture.Configuration},
		{"target", devTargetRequest{Protocol: 1, Framework: "vite", Target: "http://127.0.0.2:5174"}, fixture.Target},
		{"assignment", devConfigurationResponse{
			Protocol: 1, TunnelID: "tun_bbbbbbbbbbbbbbbbbbbbbb", Service: nullableService("api"),
			Namespace: "member.example", Hostname: "api.member.example", PublicURL: "https://api.member.example",
			Project: projectmeta.PublicMetadata{
				Namespace: "member.example", Dev: true,
				Webhooks: map[string]projectmeta.Webhook{"stripe": {Hostname: "hooks-shop-ab1234.member.example", URL: "https://hooks-shop-ab1234.member.example/api/webhooks/stripe", Service: "api", Path: "/api/webhooks/stripe", Methods: []string{"POST"}}},
				OAuth:    &projectmeta.IntegrationOrigin{Hostname: "oauth-shop-ab1234.member.example", URL: "https://oauth-shop-ab1234.member.example"},
				Services: map[string]projectmeta.Service{
					"api": {Namespace: "member.example", Hostname: "api.member.example", URL: "https://api.member.example"},
				},
			},
		}, fixture.Assignment},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := json.Marshal(testCase.value)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(actual, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(testCase.want, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("wire value = %s, want %s", actual, testCase.want)
			}
		})
	}
}
