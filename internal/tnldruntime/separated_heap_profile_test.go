package tnldruntime

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Heap snapshots are deliberately opt-in: the forced GC changes the workload.
// Run a separate diagnostic trial rather than mixing them into capacity points.
func captureSeparatedHeapProfiles(t *testing.T, database *sql.DB, before separatedSnapshot) {
	t.Helper()
	components := append([]string{"ingress-a", "relay-a"}, separatedPublisherComponents()...)
	components = append(components, separatedAppComponents()...)
	components = append(components, "visitor-1")
	for _, component := range components {
		address := component + ":9091"
		if slices.Contains(separatedAppComponents(), component) {
			address = separatedAppPublisher(component) + ":9092"
		}
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		response, err := integrationGET(ctx, &http.Client{Timeout: 20 * time.Second}, "http://"+address+"/heap")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			cancel()
			t.Fatalf("%s heap profile: %s", component, response.Status)
		}
		path := filepath.Join("/results", fmt.Sprintf("steady-%s-heap.pb.gz", component))
		file, err := os.Create(path)
		if err != nil {
			_ = response.Body.Close()
			cancel()
			t.Fatal(err)
		}
		written, copyErr := io.Copy(file, io.LimitReader(response.Body, (16<<20)+1))
		err = file.Close()
		_ = response.Body.Close()
		cancel()
		if copyErr != nil || err != nil || written > 16<<20 {
			t.Fatalf("%s heap profile: bytes=%d copy=%v close=%v", component, written, copyErr, err)
		}
	}
	after := separatedCapture(t, database, "steady-after-heap")
	for _, component := range components {
		t.Logf("separated_heap component=%s memory_before=%d memory_after_gc=%d profile=steady-%s-heap.pb.gz", component,
			before.Resources[component].Memory, after.Resources[component].Memory, component)
	}
}
