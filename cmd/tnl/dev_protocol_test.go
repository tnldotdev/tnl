package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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
		Protocol: 1, TunnelID: "tunnel_0123456789abcdef0123456789abcdef",
		MemberNamespace: "member.example", Hostname: "route.member.example", PublicURL: "https://route.member.example",
		Project: projectmeta.PublicMetadata{MemberNamespace: "member.example", Services: map[string]projectmeta.Service{}, RunningUnderTnlDev: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"protocol": float64(1), "tunnelID": "tunnel_0123456789abcdef0123456789abcdef", "service": nil,
		"memberNamespace": "member.example", "hostname": "route.member.example", "publicURL": "https://route.member.example",
		"project": map[string]any{"memberNamespace": "member.example", "services": map[string]any{}, "runningUnderTnlDev": true},
	}
	if !reflect.DeepEqual(wire, want) {
		t.Fatalf("wire response = %s, want %#v", data, want)
	}
}
