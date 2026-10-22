package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublisherAWSConfiguration(t *testing.T) {
	for _, format := range []string{"json", "ts"} {
		for _, test := range []struct {
			name, aws string
			count     int
		}{
			{"default", `{}`, 1}, {"two", `{"replicas":2}`, 2}, {"maximum", `{"replicas":8}`, 8},
			{"zero", `{"replicas":0}`, 0}, {"negative", `{"replicas":-1}`, 0}, {"overflow", `{"replicas":9}`, 0},
			{"fraction", `{"replicas":1.5}`, 0}, {"string", `{"replicas":"2"}`, 0},
			{"infrastructure", `{"replicas":2,"vpcId":"vpc-12345678"}`, 0},
		} {
			t.Run(format+"/"+test.name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "tnl."+format)
				contents := fmt.Sprintf(`{"publisher_groups":{"production":{"aws":%s}}}`, test.aws)
				if format == "json" {
					contents = `{"version":1,"tnl":` + contents + `}`
				} else {
					path = filepath.Join(root, "tnl.config.ts")
					contents = "export default " + strings.ReplaceAll(contents, "publisher_groups", "publisherGroups") + ";"
				}
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				project, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
				if test.count == 0 {
					if err == nil {
						t.Fatal("invalid AWS configuration accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got := project.Config.PublisherGroups["production"].AWS; got == nil || got.ReplicaCount() != test.count {
					t.Fatalf("AWS capacity = %+v", got)
				}
			})
		}
	}
}
