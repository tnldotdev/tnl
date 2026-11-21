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
		words := strings.Join(strings.Fields(strings.ReplaceAll(out.String(), "|", " ")), " ")
		if !strings.Contains(words, "tnl wait --service NAME --output json") ||
			!strings.Contains(words, "a configured service name") || strings.Contains(words, "invocation ID") {
			t.Fatalf("bad readiness guidance: %s", out.String())
		}
	}
}
