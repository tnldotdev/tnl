package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

func TestPingDoesNotLoadProjectOrSendCredentials(t *testing.T) {
	if _, err := commandForTest(&cli{}, io.Discard)([]string{"ping", "https://example.com", "--protocol", "http"}); err == nil {
		t.Fatal("ping still accepts a redundant protocol override")
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("visitor probe sent credentials")
		}
		output.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var output, diagnostics bytes.Buffer
	if err := run(t.Context(), []string{"--config", "missing.yml", "ping", server.URL, "--output", "json"}, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var result publisherapp.PingResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.State != "responding" || result.Status != http.StatusNoContent || requests != 1 {
		t.Fatalf("ping result=%s, requests=%d, err=%v", output.String(), requests, err)
	}
}
