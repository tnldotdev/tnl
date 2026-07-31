package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSampleResourcesUsesRoleMetadataWithoutSendingFragment(t *testing.T) {
	requestedFragment := "not-called"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestedFragment = request.URL.Fragment
		_, _ = response.Write([]byte("process_resident_memory_bytes 1024\nignored_metric 1\n"))
	}))
	defer server.Close()

	samples := sampleResources(t.Context(), []string{server.URL + "/metrics#relay-a"}, "loaded")
	if len(samples) != 1 || samples[0].Role != "relay" || samples[0].Identity == "" ||
		samples[0].Metrics["process_resident_memory_bytes"] != 1024 || len(samples[0].Metrics) != 1 {
		t.Fatalf("resource samples = %#v", samples)
	}
	if requestedFragment != "" {
		t.Fatalf("HTTP request included fragment %q", requestedFragment)
	}
}
