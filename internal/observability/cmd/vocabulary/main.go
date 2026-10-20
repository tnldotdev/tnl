package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/observability"
)

func main() {
	data, err := json.MarshalIndent(observability.SharedVocabulary(), "", "  ")
	if err != nil {
		panic(err)
	}
	path := os.Args[1]
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		panic(err)
	}
}
