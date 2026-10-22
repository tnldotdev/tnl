package tnldruntime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CPU profiling perturbs capacity measurements. use it only in an explicitly
// selected diagnostic run while the steady visitor workload is active.
func captureSeparatedCPUProfiles(t *testing.T) {
	t.Helper()
	for _, relay := range []string{"relay-a", "relay-b"} {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		response, err := integrationGET(ctx, &http.Client{Timeout: 15 * time.Second},
			"http://"+relay+":9090/debug/pprof/profile?seconds=10")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			cancel()
			t.Fatalf("%s CPU profile: %s", relay, response.Status)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
		_ = response.Body.Close()
		cancel()
		if readErr != nil || len(data) == 0 || len(data) > 16<<20 {
			t.Fatalf("%s CPU profile: bytes=%d read=%v", relay, len(data), readErr)
		}
		name := fmt.Sprintf("steady-%s-cpu.pb.gz", relay)
		if err := os.WriteFile(filepath.Join("/results", name), data, 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("separated_cpu_profile component=%s bytes=%d file=%s", relay, len(data), name)
	}
}
