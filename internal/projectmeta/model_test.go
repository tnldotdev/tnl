package projectmeta

import (
	"encoding/json"
	"os"
	"testing"
)

func TestProjectMetadataConformance(t *testing.T) {
	data, err := os.ReadFile("../../api/fixtures/project-metadata-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int `json:"version"`
		Cases   []struct {
			Name     string   `json:"name"`
			Valid    bool     `json:"valid"`
			Metadata Metadata `json:"metadata"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Cases) == 0 {
		t.Fatalf("unsupported or empty project metadata fixture: version %d", fixture.Version)
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			err := testCase.Metadata.Validate()
			if (err == nil) != testCase.Valid {
				t.Fatalf("metadata valid = %v, want %v (error: %v)", err == nil, testCase.Valid, err)
			}
		})
	}
}
