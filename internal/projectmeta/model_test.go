package projectmeta

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestProjectMetadataConformance(t *testing.T) {
	data, err := os.ReadFile("../../api/fixtures/project-metadata-v2.json")
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
			_, err := Parse(testCase.Metadata)
			if (err == nil) != testCase.Valid {
				t.Fatalf("metadata valid = %v, want %v (error: %v)", err == nil, testCase.Valid, err)
			}
		})
	}
}

func TestSavedAddressesRenderWithoutPrivateData(t *testing.T) {
	port := 15432
	for _, protocol := range []string{"postgres", "mysql", "redis", "ssh"} {
		service, err := NewService("member.example", "db.member.example", protocol, &port)
		if err != nil {
			t.Fatal(err)
		}
		metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{"db": service}}
		file, declarations, err := Render(metadata)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(file), `"address": "db.member.example:15432"`) || !strings.Contains(string(declarations), `readonly port: 15432`) || strings.Contains(string(declarations), "readonly url:") {
			t.Fatalf("TCP declarations=%s", declarations)
		}
		public, err := json.Marshal(metadata.Public(true))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(public), "private/source") || strings.Contains(string(public), "serviceDirectories") {
			t.Fatal("browser metadata contains source directories")
		}
		metadata.Aliases = map[string]Alias{"review": {Hostname: "review.member.example", URL: "https://review.member.example", Service: "db"}}
		if err := metadata.Validate(); err == nil {
			t.Fatal("TCP alias was accepted")
		}
		metadata.Aliases = nil
		http, _ := NewService("member.example", "web.member.example", "http", nil)
		http.Paths = map[string]Path{"/db": {Service: "db", URL: "https://web.member.example/db"}}
		metadata.Services["web"] = http
		if err := metadata.Validate(); err == nil {
			t.Fatal("HTTP mount into TCP service was accepted")
		}
	}
	if _, err := NewService("member.example", "db.member.example", "postgres", nil); err == nil {
		t.Fatal("TCP metadata was built before reservation")
	}
	if _, err := NewService("member.example", "web.member.example", "http", &port); err == nil {
		t.Fatal("HTTP metadata accepted a public TCP port")
	}
}
