package meta

import (
	"encoding/json"
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
			_, err := Parse(testCase.Metadata)
			if (err == nil) != testCase.Valid {
				t.Fatalf("metadata valid = %v, want %v (error: %v)", err == nil, testCase.Valid, err)
			}
		})
	}
}

func TestSavedAddressesRenderWithoutPrivateData(t *testing.T) {
	port := 15432
	endpoint, err := NewEndpoint("member.example", "db.member.example", "postgres", port, true)
	if err != nil || !endpoint.Public || endpoint.URL != "" {
		t.Fatal("native exposure must come from runtime state", err)
	}
	for _, protocol := range []string{"tcp", "mysql", "postgres", "kubernetes"} {
		if service, err := NewService("member.example", "db.member.example", protocol, &port); err != nil || service.Port != port || service.Public {
			t.Fatalf("private %s metadata is invalid: %+v %v", protocol, service, err)
		}
	}
	service, err := NewService("member.example", "web.member.example", "http", nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{"web": service}}
	file, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{string(file)} {
		if strings.Contains(data, "address") || strings.Contains(data, "target") || !strings.Contains(data, "https://web.member.example") {
			t.Fatalf("unsafe HTTP metadata: %s", data)
		}
	}
	if _, err := NewService("member.example", "db.member.example", "tcp", nil); err == nil {
		t.Fatal("private TCP service received a public hostname and shared port")
	}
	if service, err := NewService("member.example", "db.member.example", "tcp", &port); err != nil || service.Public {
		t.Fatal("private TCP endpoint metadata failed")
	}
	if _, err := NewService("member.example", "db.member.example", "ssh", nil); err == nil {
		t.Fatal("ssh metadata was built before port assignment")
	}
	if _, err := NewService("member.example", "db.member.example", "postgres", nil); err == nil {
		t.Fatal("old public URL protocol was accepted")
	}
	if service, err := NewService("member.example", "web.member.example", "http", &port); err != nil || service.URL != "https://web.member.example:15432" {
		t.Fatal("service HTTP lost its allocated port", err)
	}
}

func TestPublicPathMountDoesNotNeedServiceTargetMetadata(t *testing.T) {
	service, err := NewService("member.example", "web.member.example", "http", nil)
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
