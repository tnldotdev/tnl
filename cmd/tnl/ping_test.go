package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

func TestPingDoesNotLoadProjectOrSendCredentials(t *testing.T) {
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
