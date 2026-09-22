package tnldruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Capture each process's own counters before its test cleanup stops the daemon.
// A peer may already be exiting when the coordinator observes the failure.
func captureSeparatedFailure(t *testing.T, component string) {
	t.Helper()
	if !t.Failed() {
		return
	}
	resources, err := readSeparatedResources()
	if err == nil {
		resources.NetworkNamespace = component
		var data []byte
		data, err = json.Marshal(resources)
		if err == nil {
			err = os.WriteFile(filepath.Join("/results", "failure-"+component+"-resources.json"), data, 0o644)
		}
	}
	if err != nil {
		t.Logf("failure resource capture %s: %v", component, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := integrationGET(ctx, &http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:9090/metrics")
	if err == nil {
		const limit = 4 << 20
		var data []byte
		data, err = io.ReadAll(io.LimitReader(response.Body, limit+1))
		err = errors.Join(err, response.Body.Close())
		if response.StatusCode != http.StatusOK || len(data) > limit {
			err = errors.Join(err, fmt.Errorf("metrics HTTP %d, captured bytes=%d (limit %d)", response.StatusCode, len(data), limit))
		}
		if err == nil {
			err = os.WriteFile(filepath.Join("/results", "failure-"+component+".prom"), data, 0o644)
		}
	}
	if err != nil {
		t.Logf("failure metrics capture %s: %v", component, err)
	}
}
