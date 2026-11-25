package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestAgentGuideDocumentsConfiguredServiceNamesInBothFormats(t *testing.T) {
	for _, args := range [][]string{{"agent-guide"}, {"agent-guide", "--skill"}} {
		var out bytes.Buffer
		if err := run(t.Context(), args, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		for _, recipe := range guideRecipes {
			for _, step := range recipe.steps {
				if !strings.Contains(out.String(), "\ntnl "+step.example.args+"\n") {
					t.Fatalf("missing intact command in %v: %q", args, step.example.args)
				}
			}
		}
	}
}
