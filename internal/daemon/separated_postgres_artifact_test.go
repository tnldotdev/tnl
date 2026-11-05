package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

func TestPostgresRequestArtifactStaysOutsideCoordination(t *testing.T) {
	const successes = 25_001
	directory := t.TempDir()
	result := connectLoadResult{
		Summary:      benchworkload.VisitorResult{Scheduled: successes + 5, Completed: successes + 1, Successes: successes, Failures: 1, QueueExpired: 1, Missed: 3},
		RequestsFile: "phase-visitor-1-requests.jsonl",
	}
	path := filepath.Join(directory, result.RequestsFile)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	row := benchworkload.RequestResult{URL: strings.Repeat("artifact-row-payload-", 40), Scheduled: time.Unix(100, 0).UTC(), Started: time.Unix(100, 0).UTC(), Duration: time.Millisecond}
	// stream more than the coordinator's entire 16 MiB payload allowance without
	// retaining request structs or running a timed workload in this routine test.
	for range successes {
		if err := encoder.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	row.Error = "query failed"
	if err := encoder.Encode(row); err != nil {
		t.Fatal(err)
	}
	row.Error, row.QueueExpired = "request expired in queue", true
	if err := encoder.Encode(row); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(writer.Flush(), file.Close()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 16<<20 {
		t.Fatalf("sample artifact must exceed 16 MiB: info=%v error=%v", info, err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 16<<10 || bytes.Contains(payload, []byte("artifact-row-payload-")) || bytes.Contains(payload, []byte(`"Requests"`)) {
		t.Fatalf("request samples entered coordination: payload bytes=%d", len(payload))
	}
	var received connectLoadResult
	if err := json.Unmarshal(payload, &received); err != nil {
		t.Fatal(err)
	}
	var completed, failed, expired, successful int
	if err := forEachConnectLoadRequest(directory, received, func(row benchworkload.RequestResult) {
		if row.QueueExpired {
			expired++
		} else {
			completed++
			if row.Error != "" {
				failed++
			} else {
				successful++
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if completed != received.Summary.Completed || successful != successes || failed != 1 || expired != 1 {
		t.Fatalf("request accounting: completed=%d success=%d failed=%d expired=%d", completed, successful, failed, expired)
	}
	received.Summary.Completed++
	if err := forEachConnectLoadRequest(directory, received, func(benchworkload.RequestResult) {}); err == nil {
		t.Fatal("accepted an incomplete sample artifact")
	}
	received.Summary.Completed--
	received.Summary.Failures++
	if err := forEachConnectLoadRequest(directory, received, func(benchworkload.RequestResult) {}); err == nil {
		t.Fatal("accepted mismatched artifact outcome counts")
	}
}

func TestConnectRequestArtifactRejectsInlineSamples(t *testing.T) {
	result := connectLoadResult{RequestsFile: "requests.jsonl", Requests: []benchworkload.RequestResult{{}}}
	if err := forEachConnectLoadRequest(t.TempDir(), result, func(benchworkload.RequestResult) {}); err == nil {
		t.Fatal("accepted both inline samples and a request artifact")
	}
}
