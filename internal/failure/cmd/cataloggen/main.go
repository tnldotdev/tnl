package main

import (
	"encoding/json"
	"os"

	"github.com/tnldotdev/tnl/internal/failure"
)

func main() {
	data, err := json.MarshalIndent(struct {
		SchemaVersion int                   `json:"schema_version"`
		Failures      []failure.ClientEntry `json:"failures"`
	}{SchemaVersion: 1, Failures: failure.ClientReasons()}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("catalog.gen.json", append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
}
